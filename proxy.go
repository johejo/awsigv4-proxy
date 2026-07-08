package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// unsignedPayloadHash is the sentinel payload hash used to skip payload signing.
const unsignedPayloadHash = "UNSIGNED-PAYLOAD"

// httpClient is the subset of *http.Client used by proxyClient, extracted as an
// interface to make testing easier.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// proxyHandler forwards each incoming request through proxyClient and copies the
// upstream response back to the caller.
type proxyHandler struct {
	logger *slog.Logger
	proxy  *proxyClient
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := h.proxy.Do(r)
	if err != nil {
		status, msg := http.StatusBadGateway, "unable to proxy request"
		if _, ok := errors.AsType[*clientError](err); ok {
			status, msg = http.StatusBadRequest, "invalid request"
			if errors.Is(err, errBodyTooLarge) {
				status, msg = http.StatusRequestEntityTooLarge, "request body too large"
			}
		}
		// Log the underlying error (which may reveal internal hosts/IPs) but
		// return only a generic message to the caller to avoid leaking details.
		h.logger.Error(msg, "error", err)
		http.Error(w, msg, status)
		return
	}
	defer resp.Body.Close()

	delHopByHopHeaders(resp.Header)
	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Unknown-length responses and event streams (streaming APIs, SSE) must
	// reach the client promptly instead of sitting in the server's write
	// buffer, mirroring httputil.ReverseProxy's immediate-flush conditions.
	// Fixed-length responses keep the plain path (and its io.Copy fast paths).
	var dst io.Writer = w
	if resp.ContentLength == -1 || isEventStream(resp.Header.Get("Content-Type")) {
		dst = &flushWriter{w: w, rc: http.NewResponseController(w)}
	}
	if _, err := io.Copy(dst, resp.Body); err != nil {
		// Status and headers are already sent, so we can only log here.
		h.logger.Error("error while copying response from upstream", "error", err)
	}
}

// clientError marks failures caused by the inbound request itself; the handler
// maps these to 400 rather than 502.
type clientError struct{ err error }

func (e *clientError) Error() string { return e.err.Error() }
func (e *clientError) Unwrap() error { return e.err }

// errBodyTooLarge marks inbound requests rejected by --max-request-body-size;
// always wrapped in a clientError, and mapped by the handler to 413.
var errBodyTooLarge = errors.New("request body exceeds --max-request-body-size")

func isEventStream(contentType string) bool {
	const mediaType = "text/event-stream"
	// Cheap prefix check so the common non-SSE response skips the full
	// (allocating) media-type parse.
	if !hasPrefixFold(contentType, mediaType) {
		return false
	}
	ct, _, _ := mime.ParseMediaType(contentType)
	return ct == mediaType
}

// flushWriter flushes after every write so each chunk of a streaming response
// is forwarded as soon as it arrives.
type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err != nil {
		return n, err
	}
	if ferr := fw.rc.Flush(); ferr != nil && !errors.Is(ferr, http.ErrNotSupported) {
		// The client is gone (broken pipe etc.); stop the copy.
		return n, ferr
	}
	return n, nil
}

// proxyClient signs and forwards a single request.
type proxyClient struct {
	signer      *v4.Signer
	client      httpClient
	credentials aws.CredentialsProvider
	logger      *slog.Logger

	stripHeaders        []string
	customHeaders       http.Header
	duplicateHeaders    []string
	serviceOverride     *awsService
	signingHostOverride string
	hostOverride        string
	logFailedRequest    bool
	schemeOverride      string
	unsignedPayload     bool
	maxBodySize         int64

	// now returns the signing time; nil means time.Now. Injected by tests to
	// make signatures deterministic.
	now func() time.Time
}

func (p *proxyClient) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	proxyURL := *req.URL
	proxyURL.Host = req.Host
	if p.hostOverride != "" {
		proxyURL.Host = p.hostOverride
	}
	proxyURL.Scheme = "https"
	if p.schemeOverride != "" {
		proxyURL.Scheme = p.schemeOverride
	}
	if req.URL.RawQuery != "" {
		// SignHTTP re-encodes the query via URL.Query(), which silently DROPS
		// pairs containing semicolons or invalid percent-escapes — the upstream
		// would then receive (and we would sign) a different query than the
		// client sent. Reject such requests outright.
		query, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			return nil, &clientError{fmt.Errorf("invalid query string: %w", err)}
		}
		// Drop presigned-URL auth artifacts from the query, mirroring the
		// X-Amz-Security-Token header strip below: forwarding them alongside
		// the fresh Authorization header makes AWS reject the request with
		// "only one auth mechanism allowed". Re-encoding is harmless when
		// nothing was stripped, since SignHTTP re-encodes the query anyway.
		stripPresignedQueryParams(query)
		proxyURL.RawQuery = query.Encode()
	}

	// A declared length over the cap is rejected before any body is read; a
	// chunked (unknown-length) body is instead capped during the buffered read
	// below. The streaming path always has a declared length, so this check
	// alone covers it.
	if p.maxBodySize > 0 && req.ContentLength > p.maxBodySize {
		return nil, &clientError{fmt.Errorf("declared request body of %d bytes: %w", req.ContentLength, errBodyTooLarge)}
	}

	// The signer needs the payload hash before the headers are written, so the
	// body must normally be buffered (which also makes it rewindable for
	// transport retries). With --unsigned-payload the hash is a constant and
	// the body can stream through — but only when the inbound length is known:
	// an unknown length would force chunked framing upstream, which S3 rejects
	// and which drops the signed Content-Length from the wire.
	stream := p.unsignedPayload && req.ContentLength > 0

	// Never dump the body on the streaming path or for unknown-length bodies
	// when a cap is configured: DumpRequest would drain the whole body into
	// memory before the size limit below can be enforced.
	dumpInitialBody := !stream && !(p.maxBodySize > 0 && req.ContentLength < 0)
	p.debugDumpRequest(ctx, "initial request dump", req, dumpInitialBody)

	var body []byte // buffered path only; stays nil when streaming
	var bodyReader io.Reader
	if stream {
		// Used as-is; the transport closes it. The server closes it again
		// after the handler returns, which is safe (http.body.Close is
		// idempotent). GetBody stays nil, so the transport cannot retry —
		// an accepted trade-off for constant memory.
		bodyReader = req.Body
	} else {
		var err error
		body, err = readRequestBody(req, p.maxBodySize)
		if err != nil {
			// A body-read failure at this point is the inbound side (client
			// aborted the upload, bad chunked framing); nothing upstream is
			// involved yet.
			return nil, &clientError{fmt.Errorf("reading request body: %w", err)}
		}
		bodyReader = bytes.NewReader(body)
	}

	proxyReq, err := http.NewRequestWithContext(ctx, req.Method, proxyURL.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	if stream {
		// NewRequestWithContext only derives ContentLength from bytes/strings
		// readers; for a plain reader it stays 0 (= unknown with a non-nil
		// body), which would chunk. Set it so identity framing and an
		// accurate, signed Content-Length go out. On the buffered path the
		// bytes.Reader already yielded an exact ContentLength, so net/http
		// never auto-chunks there.
		proxyReq.ContentLength = req.ContentLength
	}

	if p.signingHostOverride != "" {
		proxyReq.Host = p.signingHostOverride
	}

	svc := p.serviceOverride
	if svc == nil {
		svc = p.determineSigningService(req.Host)
	}
	if svc == nil {
		return nil, fmt.Errorf("unable to determine service from host: %q (set --name and --region)", p.signingServiceHost(req.Host))
	}

	// Copy the caller's headers onto the proxy request, then drop hop-by-hop
	// headers. This happens BEFORE signing so the caller's headers (notably
	// x-amz-*, which AWS requires to be part of the signature) are included in
	// the SigV4 signed headers. Strip on the clone, not on req.Header:
	// handlers must not modify the inbound request (http.Handler contract).
	proxyReq.Header = req.Header.Clone()
	for _, header := range p.stripHeaders {
		proxyReq.Header.Del(header)
	}
	delHopByHopHeaders(proxyReq.Header)

	// Drop any caller-supplied security token: the signer only replaces it
	// when OUR credentials carry a session token, so a stale client token
	// would otherwise be signed and forwarded, and AWS rejects the request.
	// Operators can still inject one deliberately via --custom-headers.
	proxyReq.Header.Del("X-Amz-Security-Token")

	// X-Original-* is a proxy-owned namespace: drop every caller-supplied value
	// (spoofed headers would otherwise be signed and forwarded as if we attested
	// them), then repopulate from the configured duplicate headers. Strip wins:
	// a header listed in both --strip and --duplicate-headers is not preserved.
	maps.DeleteFunc(proxyReq.Header, func(k string, _ []string) bool {
		return hasPrefixFold(k, "X-Original-")
	})
	for _, header := range p.duplicateHeaders {
		if slices.ContainsFunc(p.stripHeaders, func(s string) bool { return strings.EqualFold(s, header) }) {
			continue
		}
		key := "X-Original-" + header
		for _, v := range req.Header.Values(header) {
			proxyReq.Header.Add(key, v)
		}
	}

	copyHeaderWithoutOverwrite(proxyReq.Header, p.customHeaders)

	payloadHash := unsignedPayloadHash
	if !p.unsignedPayload {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}
	if err := p.sign(ctx, proxyReq, payloadHash, svc); err != nil {
		return nil, err
	}

	p.debugDumpRequest(ctx, "proxying request", proxyReq, !stream)

	resp, err := p.client.Do(proxyReq)
	if err != nil {
		return nil, err
	}

	if p.logFailedRequest && resp.StatusCode >= 400 {
		// Log a bounded prefix of the error body without buffering the whole
		// response, then splice it back so the caller still sees the full body.
		const maxLogBody = 64 << 10
		prefix, _ := io.ReadAll(io.LimitReader(resp.Body, maxLogBody))
		p.logger.Error("error proxying request",
			"request", fmt.Sprintf("%s %s", proxyReq.Method, proxyReq.URL),
			"status_code", resp.StatusCode,
			"message", string(prefix))
		resp.Body = spliceBody(prefix, resp.Body)
	}

	return resp, nil
}

func (p *proxyClient) signingServiceHost(requestHost string) string {
	if p.signingHostOverride != "" {
		return p.signingHostOverride
	}
	return requestHost
}

func (p *proxyClient) determineSigningService(requestHost string) *awsService {
	if p.signingHostOverride != "" {
		if svc := determineAWSServiceFromHost(p.signingHostOverride); svc != nil {
			return svc
		}
	}
	return determineAWSServiceFromHost(requestHost)
}

func (p *proxyClient) sign(ctx context.Context, req *http.Request, payloadHash string, svc *awsService) error {
	creds, err := p.credentials.Retrieve(ctx)
	if err != nil {
		return err
	}

	// SignHTTP does not set the X-Amz-Content-Sha256 header itself. Set it
	// before signing (so it is part of the signature); S3 requires it and it
	// is harmless for other services.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signTime := time.Now()
	if p.now != nil {
		signTime = p.now()
	}
	err = p.signer.SignHTTP(ctx, creds, req, payloadHash, svc.signingName, svc.signingRegion, signTime, func(so *v4.SignerOptions) {
		so.DisableURIPathEscaping = svc.disableURIPathEscaping()
	})
	if err == nil {
		p.logger.Debug("signed request", "service", svc.signingName, "region", svc.signingRegion)
	}
	return err
}

func (p *proxyClient) debugDumpRequest(ctx context.Context, msg string, req *http.Request, withBody bool) {
	if !p.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	if dump, err := httputil.DumpRequest(req, withBody); err == nil {
		p.logger.Debug(msg, "request", string(dump))
	}
}

// readRequestBody buffers the request body. With a positive limit it fails
// with errBodyTooLarge as soon as more than limit bytes arrive, so a chunked
// body (whose length is unknown upfront) never buffers more than the cap.
func readRequestBody(req *http.Request, limit int64) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	defer req.Body.Close()
	if limit <= 0 {
		return io.ReadAll(req.Body)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errBodyTooLarge
	}
	return body, nil
}

// presignedQueryParams are the SigV4 query-auth parameters carried by
// presigned URLs (X-Amz-Algorithm, X-Amz-Credential, ...), lowercased for
// case-insensitive lookup.
var presignedQueryParams = map[string]bool{
	"x-amz-algorithm":      true,
	"x-amz-credential":     true,
	"x-amz-date":           true,
	"x-amz-expires":        true,
	"x-amz-signedheaders":  true,
	"x-amz-signature":      true,
	"x-amz-security-token": true,
}

func stripPresignedQueryParams(q url.Values) {
	for k := range q {
		if presignedQueryParams[strings.ToLower(k)] {
			delete(q, k)
		}
	}
}

func copyHeaderWithoutOverwrite(dst, src http.Header) {
	for k, vv := range src {
		if _, ok := dst[k]; ok {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// hasPrefixFold is a case-insensitive strings.HasPrefix.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// hopByHopHeaders are consumed by a single transport-level connection and must
// not be forwarded (or signed) by a proxy, per RFC 7230 section 6.1.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// delHopByHopHeaders removes hop-by-hop headers, including any additional ones
// named in the Connection header.
func delHopByHopHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for sf := range strings.SplitSeq(f, ",") {
			if sf = strings.TrimSpace(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

// spliceBody returns a ReadCloser that yields prefix followed by the remainder
// of body, delegating Close to body.
func spliceBody(prefix []byte, body io.ReadCloser) io.ReadCloser {
	return struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(prefix), body), body}
}

// awsService is the minimal signing information needed for SigV4.
type awsService struct {
	signingName   string
	signingRegion string
}

// disableURIPathEscaping reports whether SigV4's additional URI path escaping
// must be disabled for this service; S3 (and S3 Object Lambda) reject
// double-escaped paths.
func (s *awsService) disableURIPathEscaping() bool {
	return s.signingName == "s3" || s.signingName == "s3-object-lambda"
}

// isRegionAny reports whether s matches any partition's region pattern; used
// where no partition context exists (on.aws hosts).
func isRegionAny(s string) bool {
	for _, re := range generatedPartitionSuffixes {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// hostMatcher derives signing info from normalized (lowercased, port- and
// trailing-dot-stripped) host labels, returning nil when its pattern does not
// apply.
type hostMatcher func(labels []string) *awsService

// hostMatchers handle disjoint domain families; the first match wins.
var hostMatchers = []hostMatcher{
	matchOnAws,
	matchPartitionHost,
}

// signingNameRe matches plausible SigV4 signing names; anything else derived
// from a host is a bucket name, typo or garbage, not a real AWS service.
var signingNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// determineAWSServiceFromHost derives the signing service and region from an
// endpoint host. It replaces aws-sdk-go v1's built-in endpoints table (which
// does not exist in v2) with heuristics covering the common AWS host patterns.
// It returns nil when the host is not recognized.
func determineAWSServiceFromHost(host string) *awsService {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	labels := strings.Split(host, ".")
	// Empty labels (leading/doubled dots) are not valid hostnames; rejecting
	// them here keeps the matchers from deriving an empty service name.
	if slices.Contains(labels, "") {
		return nil
	}
	for _, m := range hostMatchers {
		if svc := m(labels); svc != nil {
			if !signingNameRe.MatchString(svc.signingName) {
				return nil
			}
			return svc
		}
	}
	return nil
}

// onAwsServices maps the service label in <...>.<label>.<region>.on.aws hosts
// to its SigV4 signing name.
var onAwsServices = map[string]string{
	"lambda-url":       "lambda",           // Lambda function URLs
	"vpc-lattice-svcs": "vpc-lattice-svcs", // VPC Lattice services
}

// matchOnAws handles the *.on.aws family: <...>.<service-label>.<region>.on.aws.
func matchOnAws(labels []string) *awsService {
	n := len(labels)
	if n < 5 || labels[n-1] != "aws" || labels[n-2] != "on" {
		return nil
	}
	name, ok := onAwsServices[labels[n-4]]
	if !ok || !isRegionAny(labels[n-3]) {
		return nil
	}
	return &awsService{signingName: name, signingRegion: labels[n-3]}
}

// matchPartitionHost handles hosts under a partition DNS suffix
// (amazonaws.com, amazonaws.com.cn, api.aws, ...).
func matchPartitionHost(labels []string) *awsService {
	rest, ps := partitionRest(labels)
	if ps == nil || len(rest) == 0 {
		return nil
	}

	// VPC interface endpoints insert a "vpce" label before the suffix
	// (vpce-<id>.<service>.<region>.vpce.amazonaws.com); drop it and match
	// the remainder like the plain endpoint host.
	if rest[len(rest)-1] == "vpce" {
		rest = rest[:len(rest)-1]
		if len(rest) == 0 {
			return nil
		}
	}

	// S3 determines its region positionally (a dotted bucket name may contain
	// region-shaped labels), so it must run before the findRegion-based rules.
	if svc := matchS3(rest, ps.regionRe); svc != nil {
		return svc
	}

	region := findRegion(rest, ps.regionRe)
	if region == "" {
		// Region-less global endpoints (e.g. iam.amazonaws.com,
		// sts.amazonaws.com) sign against a fixed region. Exact host match
		// only: a prefixed host under a global endpoint is not a known shape.
		key := strings.Join(rest, ".")
		if svc, ok := generatedGlobalEndpoints[ps.suffix][key]; ok {
			return &svc
		}
		if ps.suffix == "amazonaws.com" {
			if svc, ok := legacyGlobalEndpoints[key]; ok {
				return &svc
			}
		}
		return nil
	}

	// Services that put their label last rather than immediately before the
	// region: <domain>.<region>.<service-label>.amazonaws.com.
	if name, ok := lastLabelServices[rest[len(rest)-1]]; ok {
		return &awsService{signingName: name, signingRegion: region}
	}

	// Generic: [...].<service>.<region>.<suffix> — region is the last label
	// and the service is the label (or dotted labels) immediately before it.
	if len(rest) < 2 || rest[len(rest)-1] != region {
		return nil
	}
	name := serviceName(rest[:len(rest)-1])
	// IoT hosts with labels before "iot" are data planes with their own
	// signing names; only match the documented shapes and refuse to guess for
	// the rest (e.g. <prefix>.credentials.iot.<region>, which does not use
	// SigV4 at all). The bare control-plane endpoint iot.<region> signs "iot".
	if name == "iot" && len(rest) > 2 {
		switch prev := rest[len(rest)-3]; {
		case len(rest) == 3 && (prev == "data" || strings.HasSuffix(prev, "-ats")):
			// data.iot.<region>, <prefix>-ats.iot.<region>
			name = "iotdata"
		case len(rest) == 4 && rest[0] == "data" && rest[1] == "jobs":
			// data.jobs.iot.<region>
			name = "iot-jobs-data"
		default:
			return nil
		}
	}
	return &awsService{signingName: name, signingRegion: region}
}

// serviceName resolves the signing name from the labels before the region:
// dotted service prefixes first (participant.connect.<region> signs
// execute-api), then the single-label path via normalizeService. The probe
// depth matches the generator's maxDottedLabels; iot data planes are absent
// from the dotted table by construction and fall through to the single-label
// path, keeping the iot special case in matchPartitionHost authoritative.
func serviceName(prefix []string) string {
	for n := min(3, len(prefix)); n >= 2; n-- {
		key := strings.TrimSuffix(strings.Join(prefix[len(prefix)-n:], "."), "-fips")
		if alias, ok := generatedDottedAliases[key]; ok {
			return alias
		}
	}
	return normalizeService(prefix[len(prefix)-1])
}

// matchS3 handles the S3 endpoint family (s3Labels plus the legacy dashed form
// s3-<region>). Labels before the right-most s3-family label belong to the
// bucket or access-point name, which may itself be dotted or region-shaped, so
// the region is searched only in the suffix after it. No suffix at all is the
// legacy global endpoint (us-east-1); a suffix without a region is not a known
// S3 form and must not sign as global S3.
func matchS3(rest []string, regionRe *regexp.Regexp) *awsService {
	for i := len(rest) - 1; i >= 0; i-- {
		name, ok := s3Labels[rest[i]]
		if !ok {
			// Legacy dashed form, where the label carries its own region:
			// s3-<region>. The s3- prefix keeps it from matching the region
			// pattern or s3Labels.
			if r := strings.TrimPrefix(rest[i], "s3-"); r != rest[i] && regionRe.MatchString(r) {
				return &awsService{signingName: "s3", signingRegion: r}
			}
			continue
		}
		suffix := rest[i+1:]
		if len(suffix) == 0 {
			return &awsService{signingName: name, signingRegion: "us-east-1"}
		}
		if r := findRegion(suffix, regionRe); r != "" {
			return &awsService{signingName: name, signingRegion: r}
		}
		return nil
	}
	return nil
}

// partitionSuffix pairs a partition DNS suffix (as labels, for label-wise
// matching) with the pattern for its region labels.
type partitionSuffix struct {
	suffix   string
	labels   []string
	regionRe *regexp.Regexp
}

// partitionSuffixes is generatedPartitionSuffixes prepared for matching,
// longest suffix first so amazonaws.com.cn wins over any shorter overlap.
var partitionSuffixes = func() []partitionSuffix {
	ps := make([]partitionSuffix, 0, len(generatedPartitionSuffixes))
	for s, re := range generatedPartitionSuffixes {
		ps = append(ps, partitionSuffix{suffix: s, labels: strings.Split(s, "."), regionRe: re})
	}
	slices.SortFunc(ps, func(a, b partitionSuffix) int {
		if d := len(b.labels) - len(a.labels); d != 0 {
			return d
		}
		return strings.Compare(a.suffix, b.suffix)
	})
	return ps
}()

// partitionRest strips a known partition DNS suffix, returning the remaining
// labels and the matched suffix (nil when the host is under no partition).
func partitionRest(labels []string) ([]string, *partitionSuffix) {
	for i := range partitionSuffixes {
		p := &partitionSuffixes[i]
		n := len(labels) - len(p.labels)
		if n < 1 || !slices.Equal(labels[n:], p.labels) {
			continue
		}
		return labels[:n], p
	}
	return nil, nil
}

// s3Labels maps S3-family endpoint host labels to their SigV4 signing names.
// Access-point and FIPS variants sign as plain "s3".
var s3Labels = map[string]string{
	"s3":                  "s3",
	"s3-fips":             "s3",
	"s3-accesspoint":      "s3",
	"s3-accesspoint-fips": "s3",
	"s3-object-lambda":    "s3-object-lambda",
	"s3-outposts":         "s3-outposts",
}

// legacyGlobalEndpoints are region-less amazonaws.com endpoints that predate
// endpoints.json (the source of generatedGlobalEndpoints) and so cannot be
// generated.
var legacyGlobalEndpoints = map[string]awsService{
	"queue":             {signingName: "sqs", signingRegion: "us-east-1"}, // legacy global SQS
	"globalaccelerator": {signingName: "globalaccelerator", signingRegion: "us-west-2"},
}

// lastLabelServices maps services whose endpoint hosts end in the service
// label, with the region before it (e.g. <domain>.<region>.es), to their
// SigV4 signing names.
var lastLabelServices = map[string]string{
	"es":          "es",
	"aoss":        "aoss",
	"cloudsearch": "cloudsearch",
	"queue":       "sqs", // legacy regional SQS: <region>.queue
}

// serviceAliases maps endpoint host labels whose SigV4 signing name differs
// from the label itself and which are absent from botocore's service metadata
// (generatedServiceAliases covers everything present there): these labels are
// resource-specific host shapes with no service model of their own.
var serviceAliases = map[string]string{
	"aps-workspaces":      "aps",        // <workspace>.aps-workspaces.<region>
	"appsync-api":         "appsync",    // <api-id>.appsync-api.<region>
	"transcribestreaming": "transcribe", // streaming data plane of transcribe
}

// normalizeService maps an endpoint's service label to its SigV4 signing name,
// stripping the -fips suffix and translating known aliases.
func normalizeService(s string) string {
	s = strings.TrimSuffix(s, "-fips")
	if alias, ok := serviceAliases[s]; ok {
		return alias
	}
	if alias, ok := generatedServiceAliases[s]; ok {
		return alias
	}
	return s
}

// findRegion returns the last label matching the partition's region pattern,
// or "" if none. Scanning from the right avoids treating a leading
// region-shaped label (such as an S3 bucket named like a region) as the
// endpoint's region.
func findRegion(labels []string, regionRe *regexp.Regexp) string {
	for i := len(labels) - 1; i >= 0; i-- {
		if regionRe.MatchString(labels[i]) {
			return labels[i]
		}
	}
	return ""
}
