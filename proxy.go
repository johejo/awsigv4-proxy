package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
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
		const msg = "unable to proxy request"
		// Log the underlying error (which may reveal internal hosts/IPs) but
		// return only a generic message to the caller to avoid leaking details.
		h.logger.Error(msg, "error", err)
		http.Error(w, msg, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Drop hop-by-hop headers and stream the body straight through instead of
	// buffering it, so large (e.g. multi-GB S3) responses do not sit in memory.
	delHopByHopHeaders(resp.Header)
	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		// Status and headers are already sent, so we can only log here.
		h.logger.Error("error while copying response from upstream", "error", err)
	}
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

	p.debugDumpRequest(ctx, "initial request dump", req)

	// Buffer the body so it is rewindable (the SDK signer reads it) and so the
	// request can be retried by the transport.
	body, err := readRequestBody(req)
	if err != nil {
		return nil, err
	}

	proxyReq, err := http.NewRequestWithContext(ctx, req.Method, proxyURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	reqChunked := chunked(req.TransferEncoding)
	// Ignore ContentLength if "chunked" transfer-coding is used.
	if !reqChunked && req.ContentLength >= 0 {
		proxyReq.ContentLength = req.ContentLength
	}

	if p.signingHostOverride != "" {
		proxyReq.Host = p.signingHostOverride
	}

	svc := p.serviceOverride
	if svc == nil {
		svc = determineAWSServiceFromHost(req.Host)
	}
	if svc == nil {
		return nil, fmt.Errorf("unable to determine service from host: %q (set --name and --region)", req.Host)
	}

	// Strip requested headers from the incoming request before copying.
	for _, header := range p.stripHeaders {
		req.Header.Del(header)
	}

	// Copy the caller's headers onto the proxy request, then drop hop-by-hop
	// headers. This happens BEFORE signing so the caller's headers (notably
	// x-amz-*, which AWS requires to be part of the signature) are included in
	// the SigV4 signed headers.
	proxyReq.Header = req.Header.Clone()
	delHopByHopHeaders(proxyReq.Header)

	// Duplicate requested headers into an X-Original-* prefixed header.
	for _, header := range p.duplicateHeaders {
		v := req.Header.Get(header)
		if v == "" {
			continue
		}
		proxyReq.Header.Set("X-Original-"+header, v)
	}

	// Add custom headers, without overwriting existing ones.
	copyHeaderWithoutOverwrite(proxyReq.Header, p.customHeaders)

	// net/http emits "Transfer-Encoding: chunked" when a body is set without a
	// known length. Force identity so services like S3 (which reject chunked)
	// receive a Content-Length instead.
	if !reqChunked {
		proxyReq.TransferEncoding = []string{"identity"}
	} else {
		proxyReq.TransferEncoding = req.TransferEncoding
	}

	if err := p.sign(ctx, proxyReq, body, svc); err != nil {
		return nil, err
	}

	p.debugDumpRequest(ctx, "proxying request", proxyReq)

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

func (p *proxyClient) sign(ctx context.Context, req *http.Request, body []byte, svc *awsService) error {
	payloadHash := unsignedPayloadHash
	if !p.unsignedPayload {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}

	creds, err := p.credentials.Retrieve(ctx)
	if err != nil {
		return err
	}

	// Unlike aws-sdk-go v1's signer, v2's SignHTTP does not set the
	// X-Amz-Content-Sha256 header itself. Set it before signing (so it is part
	// of the signature); S3 requires it and it is harmless for other services.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	err = p.signer.SignHTTP(ctx, creds, req, payloadHash, svc.signingName, svc.signingRegion, time.Now(), func(so *v4.SignerOptions) {
		so.DisableURIPathEscaping = svc.disableURIPathEscaping()
	})
	if err == nil {
		p.logger.Debug("signed request", "service", svc.signingName, "region", svc.signingRegion)
	}
	return err
}

// debugDumpRequest logs a full request dump when debug logging is enabled.
func (p *proxyClient) debugDumpRequest(ctx context.Context, msg string, req *http.Request) {
	if !p.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	if dump, err := httputil.DumpRequest(req, true); err == nil {
		p.logger.Debug(msg, "request", string(dump))
	}
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	defer req.Body.Close()
	return io.ReadAll(req.Body)
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

// chunked reports whether the transfer-encoding implies chunked framing (any
// value other than "identity"), per RFC 2616 sections 3.6 and 4.4.
func chunked(transferEncoding []string) bool {
	for _, v := range transferEncoding {
		if v != "identity" {
			return true
		}
	}
	return false
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

// regionRe loosely matches AWS region tokens such as us-east-1, ap-southeast-2
// and us-gov-west-1.
var regionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

func isRegion(s string) bool { return regionRe.MatchString(s) }

// hostMatcher derives signing info from normalized (lowercased, port- and
// trailing-dot-stripped) host labels, returning nil when its pattern does not
// apply.
type hostMatcher func(labels []string) *awsService

// hostMatchers is ordered most-specific first; the first match wins.
var hostMatchers = []hostMatcher{
	matchOnAws,
	matchAmazonAws,
}

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
	if !ok || !isRegion(labels[n-3]) {
		return nil
	}
	return &awsService{signingName: name, signingRegion: labels[n-3]}
}

// matchAmazonAws handles hosts under amazonaws.com or amazonaws.com.cn.
func matchAmazonAws(labels []string) *awsService {
	rest, ok := amazonAWSRest(labels)
	if !ok || len(rest) == 0 {
		return nil
	}

	region := findRegion(rest)
	if region == "" {
		// Legacy single-label path-style S3: s3-<region>.amazonaws.com. The
		// s3- prefix keeps the label from matching regionRe, so these hosts
		// always land here rather than in the regional rules below.
		if len(rest) == 1 {
			if r := strings.TrimPrefix(rest[0], "s3-"); r != rest[0] && isRegion(r) {
				return &awsService{signingName: "s3", signingRegion: r}
			}
		}
		// Region-less global endpoints (e.g. iam.amazonaws.com,
		// sts.amazonaws.com, s3.amazonaws.com) sign against us-east-1.
		if svc := normalizeService(rest[len(rest)-1]); globalServices[svc] {
			return &awsService{signingName: svc, signingRegion: "us-east-1"}
		}
		return nil
	}

	// OpenSearch/Elasticsearch: <domain>.<region>.es.amazonaws.com — the
	// service label is last rather than immediately before the region.
	if rest[len(rest)-1] == "es" {
		return &awsService{signingName: "es", signingRegion: region}
	}

	// S3 in any of its forms: s3.<region>, <bucket>.s3.<region>,
	// <bucket>.s3.dualstack.<region>, plus FIPS/access-point/object-lambda/
	// outposts variants.
	for _, l := range rest {
		if name, ok := s3Labels[l]; ok {
			return &awsService{signingName: name, signingRegion: region}
		}
	}

	// Generic: [...].<service>.<region>.amazonaws.com — region is the last
	// label and the service is the label immediately before it.
	if len(rest) < 2 || rest[len(rest)-1] != region {
		return nil
	}
	return &awsService{signingName: normalizeService(rest[len(rest)-2]), signingRegion: region}
}

// amazonAWSRest strips the amazonaws.com / amazonaws.com.cn suffix, returning
// the remaining labels and whether the host is under either domain.
func amazonAWSRest(labels []string) ([]string, bool) {
	n := len(labels)
	switch {
	case n >= 4 && labels[n-3] == "amazonaws" && labels[n-2] == "com" && labels[n-1] == "cn":
		return labels[:n-3], true
	case n >= 3 && labels[n-2] == "amazonaws" && labels[n-1] == "com":
		return labels[:n-2], true
	}
	return nil, false
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

// globalServices are region-less AWS endpoints that sign against us-east-1.
var globalServices = map[string]bool{
	"iam":           true,
	"sts":           true,
	"s3":            true,
	"cloudfront":    true,
	"route53":       true,
	"waf":           true,
	"organizations": true,
}

// normalizeService maps an endpoint's service label to its SigV4 signing name,
// stripping the -fips suffix and translating known aliases.
func normalizeService(s string) string {
	s = strings.TrimSuffix(s, "-fips")
	if s == "aps-workspaces" {
		return "aps"
	}
	return s
}

// findRegion returns the last region-looking label, or "" if none. Scanning
// from the right avoids treating a leading region-shaped label (such as an S3
// bucket named like a region) as the endpoint's region.
func findRegion(labels []string) string {
	for i := len(labels) - 1; i >= 0; i-- {
		if isRegion(labels[i]) {
			return labels[i]
		}
	}
	return ""
}
