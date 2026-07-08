package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf8"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestDetermineAWSServiceFromHost(t *testing.T) {
	tests := []struct {
		host       string
		wantName   string
		wantRegion string
		wantNil    bool
	}{
		{host: "sts.us-east-1.amazonaws.com", wantName: "sts", wantRegion: "us-east-1"},
		{host: "sqs.ap-southeast-2.amazonaws.com", wantName: "sqs", wantRegion: "ap-southeast-2"},
		{host: "dynamodb.us-gov-west-1.amazonaws.com", wantName: "dynamodb", wantRegion: "us-gov-west-1"},
		{host: "execute-api.us-east-1.amazonaws.com", wantName: "execute-api", wantRegion: "us-east-1"},
		{host: "abc123.execute-api.eu-west-1.amazonaws.com", wantName: "execute-api", wantRegion: "eu-west-1"},
		{host: "myid.lambda-url.us-east-2.on.aws", wantName: "lambda", wantRegion: "us-east-2"},
		{host: "mysvc-0123456789abcdef0.7d67968.vpc-lattice-svcs.us-west-2.on.aws", wantName: "vpc-lattice-svcs", wantRegion: "us-west-2"},
		{host: "foo.unknown-svc.us-east-1.on.aws", wantNil: true},
		{host: "search-mydomain-abcdef.us-west-2.es.amazonaws.com", wantName: "es", wantRegion: "us-west-2"},
		{host: "aps-workspaces.us-east-1.amazonaws.com", wantName: "aps", wantRegion: "us-east-1"},
		{host: "aps.eu-central-1.amazonaws.com", wantName: "aps", wantRegion: "eu-central-1"},
		{host: "s3.us-east-1.amazonaws.com", wantName: "s3", wantRegion: "us-east-1"},
		{host: "mybucket.s3.us-west-2.amazonaws.com", wantName: "s3", wantRegion: "us-west-2"},
		{host: "mybucket.s3.dualstack.eu-west-1.amazonaws.com", wantName: "s3", wantRegion: "eu-west-1"},
		{host: "s3-ap-northeast-1.amazonaws.com", wantName: "s3", wantRegion: "ap-northeast-1"},
		{host: "mybucket.s3-us-west-2.amazonaws.com", wantName: "s3", wantRegion: "us-west-2"},
		{host: "s3.amazonaws.com", wantName: "s3", wantRegion: "us-east-1"},
		// A dotted, region-shaped bucket name on the legacy global endpoint
		// must not steal the signing region.
		{host: "us-west-2.backups.s3.amazonaws.com", wantName: "s3", wantRegion: "us-east-1"},
		{host: "s3.s3.us-west-2.amazonaws.com", wantName: "s3", wantRegion: "us-west-2"},
		// S3 interface VPC endpoint: the region sits after the s3 label but
		// is not the final label.
		{host: "bucket.vpce-0a1b2c3d4e5f.s3.us-west-2.vpce.amazonaws.com", wantName: "s3", wantRegion: "us-west-2"},
		// An s3 label with a region-less suffix is not a known S3 form and
		// must fail loudly rather than sign as global S3.
		{host: "bucket.s3.notregion.amazonaws.com", wantNil: true},
		{host: "123456789012.s3-control.us-west-2.amazonaws.com", wantName: "s3", wantRegion: "us-west-2"},
		// Services whose signing name differs from the endpoint label.
		{host: "email.us-east-1.amazonaws.com", wantName: "ses", wantRegion: "us-east-1"},
		{host: "appstream2.us-west-2.amazonaws.com", wantName: "appstream", wantRegion: "us-west-2"},
		{host: "transcribestreaming.us-east-2.amazonaws.com", wantName: "transcribe", wantRegion: "us-east-2"},
		{host: "abc123def.appsync-api.us-east-1.amazonaws.com", wantName: "appsync", wantRegion: "us-east-1"},
		// IoT: bare control plane signs "iot", data-plane hosts sign "iotdata".
		{host: "iot.us-east-1.amazonaws.com", wantName: "iot", wantRegion: "us-east-1"},
		{host: "a1b2c3d4e5-ats.iot.us-east-1.amazonaws.com", wantName: "iotdata", wantRegion: "us-east-1"},
		{host: "data.iot.us-east-1.amazonaws.com", wantName: "iotdata", wantRegion: "us-east-1"},
		{host: "data.jobs.iot.us-east-1.amazonaws.com", wantName: "iot-jobs-data", wantRegion: "us-east-1"},
		// The credentials provider does not use SigV4; unknown iot data
		// planes must not be guessed.
		{host: "abc123.credentials.iot.us-east-1.amazonaws.com", wantNil: true},
		// OpenSearch Serverless data plane, parallel to the es rule.
		{host: "abc123.us-east-1.aoss.amazonaws.com", wantName: "aoss", wantRegion: "us-east-1"},
		{host: "search-mydomain-abc123.us-west-2.cloudsearch.amazonaws.com", wantName: "cloudsearch", wantRegion: "us-west-2"},
		{host: "doc-mydomain-abc123.us-west-2.cloudsearch.amazonaws.com", wantName: "cloudsearch", wantRegion: "us-west-2"},
		// Region-less endpoints with a non-default signing region or name.
		{host: "globalaccelerator.amazonaws.com", wantName: "globalaccelerator", wantRegion: "us-west-2"},
		{host: "queue.amazonaws.com", wantName: "sqs", wantRegion: "us-east-1"},
		{host: "us-east-2.queue.amazonaws.com", wantName: "sqs", wantRegion: "us-east-2"},
		{host: "sts.cn-north-1.amazonaws.com.cn", wantName: "sts", wantRegion: "cn-north-1"},
		{host: "sts.us-east-1.amazonaws.com:443", wantName: "sts", wantRegion: "us-east-1"},
		// Garbage labels must not become signing names.
		{host: "my_svc!.us-east-1.amazonaws.com", wantNil: true},
		{host: ".us-east-1.amazonaws.com", wantNil: true},
		{host: "a..s3.us-west-2.amazonaws.com", wantNil: true},
		{host: "example.com", wantNil: true},
		{host: "localhost", wantNil: true},
		{host: "", wantNil: true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := determineAWSServiceFromHost(tt.host)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("determineAWSServiceFromHost(%q) = %+v, want nil", tt.host, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("determineAWSServiceFromHost(%q) = nil, want %s/%s", tt.host, tt.wantName, tt.wantRegion)
			}
			if got.signingName != tt.wantName || got.signingRegion != tt.wantRegion {
				t.Fatalf("determineAWSServiceFromHost(%q) = %s/%s, want %s/%s",
					tt.host, got.signingName, got.signingRegion, tt.wantName, tt.wantRegion)
			}
		})
	}
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// FuzzDetermineAWSServiceFromHost checks that arbitrary (attacker-controlled)
// Host values never panic the parser, and that any non-nil result satisfies
// the signing invariants.
func FuzzDetermineAWSServiceFromHost(f *testing.F) {
	f.Add("mybucket.s3.us-west-2.amazonaws.com")
	f.Add("mybucket.s3.dualstack.eu-west-1.amazonaws.com")
	f.Add("myid.lambda-url.us-east-2.on.aws")
	f.Add("mysvc-0123456789abcdef0.7d67968.vpc-lattice-svcs.us-west-2.on.aws")
	f.Add("sts.us-east-1.amazonaws.com:443")
	f.Add("s3-ap-northeast-1.amazonaws.com.")
	f.Add("sts.cn-north-1.amazonaws.com.cn")
	f.Add("search-mydomain-abcdef.us-west-2.es.amazonaws.com")
	f.Add("s3.amazonaws.com")
	f.Add("us-west-2.backups.s3.amazonaws.com")
	f.Add("bucket.vpce-0a1b2c3d4e5f.s3.us-west-2.vpce.amazonaws.com")
	f.Add("data.jobs.iot.us-east-1.amazonaws.com")
	f.Add("email.us-east-1.amazonaws.com")
	f.Add("a1b2c3d4e5-ats.iot.us-east-1.amazonaws.com")
	f.Add("abc123.us-east-1.aoss.amazonaws.com")
	f.Add("queue.amazonaws.com")
	f.Add("my_svc!.us-east-1.amazonaws.com")
	f.Add("")
	f.Fuzz(func(t *testing.T, host string) {
		svc := determineAWSServiceFromHost(host)
		// isRegion is reused because no matcher validates the region centrally;
		// a future matcher deriving an unvalidated region is still caught.
		if svc != nil && (svc.signingName == "" || !isRegion(svc.signingRegion)) {
			t.Fatalf("invalid service for %q: %+v", host, svc)
		}
		// Normalization invariance: a default port, trailing dot or different
		// case must not change the result. Skip variants that do not normalize
		// back to the same host (colons/brackets, an existing trailing dot,
		// non-ASCII case mappings that do not round-trip).
		var variants []string
		if isASCII(host) {
			variants = append(variants, strings.ToUpper(host))
		}
		if !strings.ContainsAny(host, ":[]") {
			variants = append(variants, host+":443")
		}
		if !strings.HasSuffix(host, ".") {
			variants = append(variants, host+".")
		}
		for _, v := range variants {
			got := determineAWSServiceFromHost(v)
			switch {
			case (svc == nil) != (got == nil):
				t.Fatalf("determineAWSServiceFromHost(%q) = %+v, but (%q) = %+v", host, svc, v, got)
			case svc != nil && *svc != *got:
				t.Fatalf("determineAWSServiceFromHost(%q) = %+v, but (%q) = %+v", host, *svc, v, *got)
			}
		}
	})
}

func TestParseCustomHeaders(t *testing.T) {
	// Trailing comma and blank segments are ignored, not errors.
	h, err := parseCustomHeaders("X-Foo=bar, X-Baz=qux , ,X-Empty=,X-Eq=a=b,")
	if err != nil {
		t.Fatalf("parseCustomHeaders: %v", err)
	}
	if len(h) != 4 {
		t.Errorf("got %d headers, want 4: %v", len(h), h)
	}
	if got := h.Get("X-Foo"); got != "bar" {
		t.Errorf("X-Foo = %q, want bar", got)
	}
	if got := h.Get("X-Baz"); got != "qux" {
		t.Errorf("X-Baz = %q, want qux (whitespace should be trimmed)", got)
	}
	if got := h.Get("X-Empty"); got != "" {
		t.Errorf("X-Empty = %q, want empty", got)
	}
	if got := h.Get("X-Eq"); got != "a=b" {
		t.Errorf("X-Eq = %q, want a=b (split on first = only)", got)
	}

	if h, err := parseCustomHeaders(""); err != nil || len(h) != 0 {
		t.Errorf("parseCustomHeaders(\"\") = %v, %v; want no headers, nil error", h, err)
	}

	for _, in := range []string{
		"malformed",         // no =
		"=bar",              // empty name
		"X Foo=bar",         // space in name
		"X-Foo:extra=bar",   // invalid token char
		"X-Foo=b\x00ar",     // control char in value
		"X-Foo=bar,between", // valid pair followed by malformed one
	} {
		if _, err := parseCustomHeaders(in); err == nil {
			t.Errorf("parseCustomHeaders(%q) = nil error, want error", in)
		}
	}
}

func TestValidateHeaderNames(t *testing.T) {
	if err := validateHeaderNames("strip", []string{"Authorization", "X-Trace"}); err != nil {
		t.Errorf("valid names: %v", err)
	}
	if err := validateHeaderNames("strip", []string{"X Trace"}); err == nil {
		t.Errorf("name with space: want error")
	}
	if err := validateHeaderNames("duplicate-headers", []string{""}); err == nil {
		t.Errorf("empty name: want error")
	}
}

func TestCopyHeaderWithoutOverwrite(t *testing.T) {
	dst := http.Header{"X-Keep": []string{"original"}}
	src := http.Header{"X-Keep": []string{"new"}, "X-Add": []string{"added"}}
	copyHeaderWithoutOverwrite(dst, src)
	if got := dst.Get("X-Keep"); got != "original" {
		t.Errorf("X-Keep = %q, want original (must not overwrite)", got)
	}
	if got := dst.Get("X-Add"); got != "added" {
		t.Errorf("X-Add = %q, want added", got)
	}
}

func TestServiceOverrideFromFlags(t *testing.T) {
	warned := func(o *options) (svc *awsService, warning bool) {
		var buf bytes.Buffer
		svc = serviceOverrideFromFlags(o, slog.New(slog.NewTextHandler(&buf, nil)))
		return svc, strings.Contains(buf.String(), "level=WARN")
	}

	svc, warning := warned(&options{name: "execute-api", region: "eu-west-1"})
	if svc == nil || svc.signingName != "execute-api" || svc.signingRegion != "eu-west-1" {
		t.Errorf("override = %+v, want execute-api/eu-west-1", svc)
	}
	if warning {
		t.Error("unexpected warning for --name with --region")
	}

	// --name alone is ignored (original behavior), but must warn.
	if svc, warning := warned(&options{name: "execute-api"}); svc != nil || !warning {
		t.Errorf("override = %+v, warning = %v; want nil with a warning", svc, warning)
	}

	// --region alone is a valid credential-resolution setting: no warning.
	if svc, warning := warned(&options{region: "eu-west-1"}); svc != nil || warning {
		t.Errorf("override = %+v, warning = %v; want nil without warning", svc, warning)
	}

	if svc, warning := warned(&options{}); svc != nil || warning {
		t.Errorf("override = %+v, warning = %v; want nil without warning", svc, warning)
	}
}

func TestRoleSessionName(t *testing.T) {
	hostFn := func(name string) func() (string, error) {
		return func() (string, error) { return name, nil }
	}

	t.Setenv("AWS_ROLE_SESSION_NAME", "custom-session")
	if got, err := roleSessionName(hostFn("host")); err != nil || got != "custom-session" {
		t.Errorf("roleSessionName = %q, %v; want custom-session", got, err)
	}

	// Values violating the STS constraint are rejected, not silently rewritten.
	for _, invalid := range []string{"has space", "x", strings.Repeat("a", 65), "日本語"} {
		t.Setenv("AWS_ROLE_SESSION_NAME", invalid)
		if got, err := roleSessionName(hostFn("host")); err == nil {
			t.Errorf("roleSessionName(env=%q) = %q, want error", invalid, got)
		}
	}

	t.Setenv("AWS_ROLE_SESSION_NAME", "")
	if got, err := roleSessionName(hostFn("myhost")); err != nil || got != "awsigv4-proxy-myhost" {
		t.Errorf("roleSessionName = %q, %v; want awsigv4-proxy-myhost", got, err)
	}

	// Hostname characters outside [\w+=,.@-] are sanitized to '-'.
	if got, err := roleSessionName(hostFn("my host!")); err != nil || got != "awsigv4-proxy-my-host-" {
		t.Errorf("roleSessionName = %q, %v; want awsigv4-proxy-my-host-", got, err)
	}

	// Long hostnames are truncated to the 64-character STS limit.
	got, err := roleSessionName(hostFn(strings.Repeat("h", 100)))
	if err != nil || len(got) != 64 || !strings.HasPrefix(got, "awsigv4-proxy-hhh") {
		t.Errorf("roleSessionName = %q (len %d), %v; want 64-char truncation", got, len(got), err)
	}

	// A multi-byte hostname must not leave invalid bytes or split a rune.
	if got, err := roleSessionName(hostFn("ホスト")); err != nil || got != "awsigv4-proxy----" {
		t.Errorf("roleSessionName = %q, %v; want awsigv4-proxy----", got, err)
	}
}

// stubClient captures the outgoing signed request and returns a canned response.
type stubClient struct {
	got  *http.Request
	body []byte
	resp *http.Response
}

func (c *stubClient) Do(req *http.Request) (*http.Response, error) {
	c.got = req
	c.body, _ = io.ReadAll(req.Body)
	if c.resp != nil {
		return c.resp, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
	}, nil
}

func staticProxy(client httpClient) *proxyClient {
	return &proxyClient{
		signer:      v4.NewSigner(),
		client:      client,
		credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		logger:      discardLogger(),
	}
}

func TestProxyClientOverrides(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)
	p.hostOverride = "upstream.internal"
	p.serviceOverride = &awsService{signingName: "execute-api", signingRegion: "eu-west-1"}
	p.schemeOverride = "http"
	p.stripHeaders = []string{"Authorization-Downstream"}
	p.customHeaders = http.Header{"X-Custom": []string{"yes"}}

	req := httptest.NewRequest(http.MethodPost, "http://ignored.example.com/path", strings.NewReader("payload"))
	req.Header.Set("Authorization-Downstream", "secret")

	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if stub.got.URL.Host != "upstream.internal" {
		t.Errorf("host = %q, want upstream.internal", stub.got.URL.Host)
	}
	if stub.got.URL.Scheme != "http" {
		t.Errorf("scheme = %q, want http", stub.got.URL.Scheme)
	}
	if !strings.Contains(stub.got.Header.Get("Authorization"), "eu-west-1/execute-api/aws4_request") {
		t.Errorf("Authorization does not reference execute-api/eu-west-1: %q", stub.got.Header.Get("Authorization"))
	}
	if stub.got.Header.Get("Authorization-Downstream") != "" {
		t.Errorf("stripped header leaked through: %q", stub.got.Header.Get("Authorization-Downstream"))
	}
	// Stripping must happen on the outbound clone; the inbound request is not
	// ours to modify (http.Handler contract).
	if req.Header.Get("Authorization-Downstream") != "secret" {
		t.Errorf("inbound request header mutated: %q", req.Header.Get("Authorization-Downstream"))
	}
	if stub.got.Header.Get("X-Custom") != "yes" {
		t.Errorf("custom header = %q, want yes", stub.got.Header.Get("X-Custom"))
	}
	if string(stub.body) != "payload" {
		t.Errorf("body = %q, want payload", string(stub.body))
	}
}

func TestProxyClientDuplicateHeadersMultiValue(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)
	p.serviceOverride = &awsService{signingName: "execute-api", signingRegion: "eu-west-1"}
	p.duplicateHeaders = []string{"X-Trace", "X-Absent", "X-Empty"}

	req := httptest.NewRequest(http.MethodGet, "http://upstream.example.com/", nil)
	req.Header.Add("X-Trace", "abc")
	req.Header.Add("X-Trace", "def")
	req.Header.Set("X-Empty", "")
	// Caller-supplied X-Original-* headers must never survive: replaced when
	// the source header is present, dropped when it is absent or unconfigured.
	req.Header.Set("X-Original-X-Trace", "spoofed")
	req.Header.Set("X-Original-X-Absent", "spoofed")
	req.Header.Set("X-Original-Other", "spoofed")

	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if got, want := stub.got.Header.Values("X-Original-X-Trace"), []string{"abc", "def"}; !slices.Equal(got, want) {
		t.Errorf("duplicated header = %q, want %q", got, want)
	}
	// A present-but-empty source header is still duplicated (presence is
	// preserved, and an empty spoof cannot slip through in its place).
	if got, want := stub.got.Header.Values("X-Original-X-Empty"), []string{""}; !slices.Equal(got, want) {
		t.Errorf("empty header duplicated as %q, want %q", got, want)
	}
	// Check map presence, not Values length: a nil-valued entry would pass a
	// len(Values) == 0 check.
	if got, ok := stub.got.Header["X-Original-X-Absent"]; ok {
		t.Errorf("spoofed X-Original-X-Absent survived: %q", got)
	}
	if got, ok := stub.got.Header["X-Original-Other"]; ok {
		t.Errorf("spoofed X-Original-Other survived: %q", got)
	}
}

func TestProxyClientDuplicateHeadersAfterStrip(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)
	p.serviceOverride = &awsService{signingName: "execute-api", signingRegion: "eu-west-1"}
	p.stripHeaders = []string{"X-Trace"}
	p.duplicateHeaders = []string{"X-Trace"}

	req := httptest.NewRequest(http.MethodGet, "http://upstream.example.com/", nil)
	req.Header.Set("X-Trace", "abc")
	req.Header.Set("X-Original-X-Trace", "spoofed")

	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if got := stub.got.Header.Get("X-Trace"); got != "" {
		t.Errorf("stripped source header leaked through: %q", got)
	}
	if got, ok := stub.got.Header["X-Original-X-Trace"]; ok {
		t.Errorf("stripped header was duplicated or spoof survived: %q", got)
	}
}

func TestPayloadHash(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)
	req := httptest.NewRequest(http.MethodPost, "http://sts.us-east-1.amazonaws.com/", strings.NewReader("hello"))
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	// Known-answer SHA-256 of "hello" rather than a recomputation, so the test
	// shares no hashing code with the implementation.
	const wantHash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got := stub.got.Header.Get("X-Amz-Content-Sha256"); got != wantHash {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %q", got, wantHash)
	}
}

// signedHeadersFromAuth extracts the SignedHeaders list from an Authorization
// header value.
func signedHeadersFromAuth(t *testing.T, auth string) []string {
	t.Helper()
	for part := range strings.SplitSeq(auth, ", ") {
		if v, ok := strings.CutPrefix(part, "SignedHeaders="); ok {
			return strings.Split(v, ";")
		}
	}
	t.Fatalf("no SignedHeaders in %q", auth)
	return nil
}

func TestDeterministicSignature(t *testing.T) {
	fixed := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	stub := &stubClient{}
	p := staticProxy(stub)
	p.now = func() time.Time { return fixed }

	const bodyStr = "Action=GetCallerIdentity&Version=2011-06-15"
	req := httptest.NewRequest(http.MethodPost, "http://sts.us-east-1.amazonaws.com/", strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}

	// Golden value computed once from this fixed time, static credentials and
	// request; asserting the exact header keeps the test independent of the
	// proxy's own signing code, so a canonicalization bug cannot cancel out.
	const wantAuth = "AWS4-HMAC-SHA256 Credential=AKID/20260702/us-east-1/sts/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date, Signature=8df0e857750592d97116a4c1fa988470bb980d346c2e4c4b84e69af5cdb2fb22"
	if auth := stub.got.Header.Get("Authorization"); auth != wantAuth {
		t.Errorf("Authorization = %q, want %q", auth, wantAuth)
	}
	if stub.got.URL.Scheme != "https" {
		t.Errorf("scheme = %q, want https (default upstream scheme)", stub.got.URL.Scheme)
	}
}

func TestHopByHopStripping(t *testing.T) {
	// Request side, including a Connection-named extension header.
	stub := &stubClient{}
	p := staticProxy(stub)
	req := httptest.NewRequest(http.MethodGet, "http://sts.us-east-1.amazonaws.com/", nil)
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "v")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Proxy-Authorization", "secret")
	req.Header.Set("Te", "trailers")
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	for _, h := range []string{"Connection", "X-Hop", "Keep-Alive", "Proxy-Authorization", "Te"} {
		if got := stub.got.Header.Get(h); got != "" {
			t.Errorf("hop-by-hop header %s leaked upstream: %q", h, got)
		}
	}

	// Response side: upstream hop-by-hop headers must not reach the caller.
	respHeader := http.Header{}
	respHeader.Set("Connection", "X-Resp-Hop")
	respHeader.Set("X-Resp-Hop", "v")
	respHeader.Set("Keep-Alive", "timeout=5")
	respHeader.Set("X-Keep", "yes")
	stub = &stubClient{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     respHeader,
		Body:       io.NopCloser(strings.NewReader("ok")),
	}}
	h := &proxyHandler{logger: discardLogger(), proxy: staticProxy(stub)}
	rec := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://sts.us-east-1.amazonaws.com/", nil)
	h.ServeHTTP(rec, req)
	for _, hn := range []string{"Connection", "X-Resp-Hop", "Keep-Alive"} {
		if got := rec.Header().Get(hn); got != "" {
			t.Errorf("response hop-by-hop header %s leaked to caller: %q", hn, got)
		}
	}
	if rec.Header().Get("X-Keep") != "yes" {
		t.Errorf("end-to-end response header dropped, got %v", rec.Header())
	}
}

func TestSigningHostOverride(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)
	p.hostOverride = "upstream.internal"
	p.schemeOverride = "http"
	p.signingHostOverride = "signed.example.com"
	p.serviceOverride = &awsService{signingName: "execute-api", signingRegion: "eu-west-1"}

	req := httptest.NewRequest(http.MethodGet, "http://ignored.example.com/", nil)
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if stub.got.Host != "signed.example.com" {
		t.Errorf("Host = %q, want signed.example.com", stub.got.Host)
	}
	if stub.got.URL.Host != "upstream.internal" {
		t.Errorf("URL.Host = %q, want upstream.internal", stub.got.URL.Host)
	}
	if !slices.Contains(signedHeadersFromAuth(t, stub.got.Header.Get("Authorization")), "host") {
		t.Error("host missing from SignedHeaders")
	}
}

// A chunked (unknown-length) inbound request must go upstream buffered, with
// an exact Content-Length and no chunked transfer-encoding: the signer signs
// content-length whenever ContentLength > 0, and chunked framing would omit
// the header from the wire (breaking the signature; S3 also rejects chunked).
func TestChunkedInboundBuffered(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)
	req := httptest.NewRequest(http.MethodPut, "http://mybucket.s3.us-west-2.amazonaws.com/key", strings.NewReader("hello world"))
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if want := int64(len("hello world")); stub.got.ContentLength != want {
		t.Errorf("ContentLength = %d, want %d", stub.got.ContentLength, want)
	}
	if len(stub.got.TransferEncoding) != 0 {
		t.Errorf("TransferEncoding = %v, want none", stub.got.TransferEncoding)
	}
	if stub.got.GetBody == nil {
		t.Error("expected a buffered, rewindable body (GetBody != nil)")
	}
	if string(stub.body) != "hello world" {
		t.Errorf("body = %q, want hello world", stub.body)
	}
}

// End-to-end variant through real HTTP servers and the real transport: a
// client upload of unknown length (chunked on the wire) must reach the
// upstream with a Content-Length and identity framing.
func TestChunkedInboundIdentityUpstreamE2E(t *testing.T) {
	var gotCL int64
	var gotTE []string
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCL = r.ContentLength
		gotTE = r.TransferEncoding
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer upstream.Close()

	p := staticProxy(upstream.Client())
	p.hostOverride = strings.TrimPrefix(upstream.URL, "http://")
	p.schemeOverride = "http"
	p.serviceOverride = &awsService{signingName: "s3", signingRegion: "us-east-1"}
	front := httptest.NewServer(&proxyHandler{logger: discardLogger(), proxy: p})
	defer front.Close()

	// io.MultiReader hides the length, so the request to the proxy is sent
	// with Transfer-Encoding: chunked.
	req, err := http.NewRequest(http.MethodPut, front.URL+"/key", io.MultiReader(strings.NewReader("hello world")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if want := int64(len("hello world")); gotCL != want {
		t.Errorf("upstream ContentLength = %d, want %d", gotCL, want)
	}
	if len(gotTE) != 0 {
		t.Errorf("upstream TransferEncoding = %v, want none", gotTE)
	}
	if string(gotBody) != "hello world" {
		t.Errorf("upstream body = %q, want hello world", gotBody)
	}
}

func TestUnsignedPayloadStreams(t *testing.T) {
	// Known length: the body streams through without a rewind buffer.
	stub := &stubClient{}
	p := staticProxy(stub)
	p.unsignedPayload = true
	req := httptest.NewRequest(http.MethodPut, "http://mybucket.s3.us-west-2.amazonaws.com/key", strings.NewReader("hello"))
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := stub.got.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
		t.Errorf("X-Amz-Content-Sha256 = %q, want UNSIGNED-PAYLOAD", got)
	}
	if stub.got.GetBody != nil {
		t.Error("expected streaming body (GetBody == nil)")
	}
	if stub.got.ContentLength != 5 {
		t.Errorf("ContentLength = %d, want 5", stub.got.ContentLength)
	}
	if string(stub.body) != "hello" {
		t.Errorf("body = %q, want hello", stub.body)
	}

	// Unknown length falls back to buffering so the upstream still receives
	// an exact Content-Length.
	stub = &stubClient{}
	p = staticProxy(stub)
	p.unsignedPayload = true
	req = httptest.NewRequest(http.MethodPut, "http://mybucket.s3.us-west-2.amazonaws.com/key", strings.NewReader("hello"))
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if stub.got.GetBody == nil {
		t.Error("expected buffered fallback (GetBody != nil)")
	}
	if stub.got.ContentLength != 5 {
		t.Errorf("ContentLength = %d, want 5", stub.got.ContentLength)
	}
}

func TestSecurityTokenStripped(t *testing.T) {
	// A stale client-supplied token must not be signed and forwarded.
	stub := &stubClient{}
	p := staticProxy(stub)
	req := httptest.NewRequest(http.MethodGet, "http://sts.us-east-1.amazonaws.com/", nil)
	req.Header.Set("X-Amz-Security-Token", "stale-client-token")
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := stub.got.Header.Get("X-Amz-Security-Token"); got != "" {
		t.Errorf("stale client token forwarded: %q", got)
	}

	// With session credentials the proxy's own token must be used.
	stub = &stubClient{}
	p = staticProxy(stub)
	p.credentials = credentials.NewStaticCredentialsProvider("AKID", "SECRET", "proxy-token")
	req = httptest.NewRequest(http.MethodGet, "http://sts.us-east-1.amazonaws.com/", nil)
	req.Header.Set("X-Amz-Security-Token", "stale-client-token")
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := stub.got.Header.Get("X-Amz-Security-Token"); got != "proxy-token" {
		t.Errorf("X-Amz-Security-Token = %q, want proxy-token", got)
	}
}

func TestProxyHandlerErrorResponses(t *testing.T) {
	// Unknown host: 502 with a generic message revealing no internal detail.
	stub := &stubClient{}
	h := &proxyHandler{logger: discardLogger(), proxy: staticProxy(stub)}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://secret-internal-host.example.com/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if rec.Body.String() != "unable to proxy request\n" {
		t.Errorf("body = %q, must be the generic message", rec.Body.String())
	}
	if stub.got != nil {
		t.Error("request must not be forwarded")
	}

	// Malformed query strings (which the signer would silently rewrite): 400,
	// never forwarded.
	for _, q := range []string{"a=%zz", "a=1;b=2"} {
		stub.got = nil
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://sts.us-east-1.amazonaws.com/?"+q, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: status = %d, want %d", q, rec.Code, http.StatusBadRequest)
		}
		if stub.got != nil {
			t.Errorf("query %q was forwarded upstream", q)
		}
	}
}

func TestPresignedQueryParamsStripped(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)
	req := httptest.NewRequest(http.MethodGet,
		"http://mybucket.s3.us-west-2.amazonaws.com/key"+
			"?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID%2F20260702%2Fus-west-2%2Fs3%2Faws4_request"+
			"&X-Amz-Date=20260702T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host"+
			"&X-Amz-Signature=deadbeef&X-Amz-Security-Token=stale&prefix=data", nil)
	if _, err := p.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := stub.got.URL.Query()
	for _, param := range []string{
		"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
		"X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Security-Token",
	} {
		if got.Has(param) {
			t.Errorf("presigned auth param %s forwarded upstream: %q", param, got.Get(param))
		}
	}
	if got.Get("prefix") != "data" {
		t.Errorf("application query param lost, query = %q", stub.got.URL.RawQuery)
	}
	if stub.got.Header.Get("Authorization") == "" {
		t.Error("missing Authorization header on re-signed request")
	}
}

func TestMaxRequestBodySize(t *testing.T) {
	overLimit := func(t *testing.T, p *proxyClient, req *http.Request) {
		t.Helper()
		stub := p.client.(*stubClient)
		_, err := p.Do(req)
		if !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("Do error = %v, want errBodyTooLarge", err)
		}
		if _, ok := errors.AsType[*clientError](err); !ok {
			t.Errorf("Do error = %v, want *clientError", err)
		}
		if stub.got != nil {
			t.Error("over-limit request was forwarded upstream")
		}
	}

	// Declared Content-Length over the limit: rejected before reading the body.
	p := staticProxy(&stubClient{})
	p.maxBodySize = 4
	overLimit(t, p, httptest.NewRequest(http.MethodPost, "http://sts.us-east-1.amazonaws.com/", strings.NewReader("hello")))

	// Chunked (unknown-length) body over the limit: caught during the buffered
	// read, which must not buffer more than the cap.
	p = staticProxy(&stubClient{})
	p.maxBodySize = 4
	req := httptest.NewRequest(http.MethodPost, "http://sts.us-east-1.amazonaws.com/", strings.NewReader("hello"))
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1
	overLimit(t, p, req)

	// The streaming (unsigned payload) path has no buffered read, so the
	// declared-length check must cover it.
	p = staticProxy(&stubClient{})
	p.maxBodySize = 4
	p.unsignedPayload = true
	overLimit(t, p, httptest.NewRequest(http.MethodPost, "http://sts.us-east-1.amazonaws.com/", strings.NewReader("hello")))

	// A body exactly at the limit passes through intact.
	stub := &stubClient{}
	p = staticProxy(stub)
	p.maxBodySize = 5
	if _, err := p.Do(httptest.NewRequest(http.MethodPost, "http://sts.us-east-1.amazonaws.com/", strings.NewReader("hello"))); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(stub.body) != "hello" {
		t.Errorf("body = %q, want hello", stub.body)
	}

	// The handler maps the rejection to 413 with a generic message.
	p = staticProxy(&stubClient{})
	p.maxBodySize = 4
	h := &proxyHandler{logger: discardLogger(), proxy: p}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://sts.us-east-1.amazonaws.com/", strings.NewReader("hello")))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if rec.Body.String() != "request body too large\n" {
		t.Errorf("body = %q, must be the generic message", rec.Body.String())
	}
}

// The log-failed-requests path must log only a bounded prefix of the error
// body while the caller still receives the complete body.
func TestLogFailedRequestPreservesBody(t *testing.T) {
	const maxLogBody = 64 << 10 // mirrors the cap in Do
	bodyStr := strings.Repeat("a", maxLogBody) + "TAIL"
	stub := &stubClient{resp: &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(bodyStr)),
	}}
	var logBuf bytes.Buffer
	p := staticProxy(stub)
	p.logger = slog.New(slog.NewTextHandler(&logBuf, nil))
	p.logFailedRequest = true

	resp, err := p.Do(httptest.NewRequest(http.MethodGet, "http://sts.us-east-1.amazonaws.com/", nil))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading spliced body: %v", err)
	}
	if string(got) != bodyStr {
		t.Errorf("caller body corrupted: len %d, want %d", len(got), len(bodyStr))
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "status_code=500") {
		t.Errorf("failed request not logged: %q", logged)
	}
	if strings.Contains(logged, "TAIL") {
		t.Error("log contains bytes beyond the 64KiB cap")
	}
}

func TestBodyReadErrorIsClientError(t *testing.T) {
	// The failing reader simulates a client that aborts its upload mid-body.
	req := httptest.NewRequest(http.MethodPost, "http://sts.us-east-1.amazonaws.com/", iotest.ErrReader(errors.New("client went away")))
	if _, err := staticProxy(&stubClient{}).Do(req); err == nil {
		t.Error("Do: expected error for failing body read")
	} else if _, ok := errors.AsType[*clientError](err); !ok {
		t.Errorf("Do error = %v, want *clientError", err)
	}
}

func TestStreamingResponseFlushes(t *testing.T) {
	tests := []struct {
		name          string
		contentLength int64
		contentType   string
		wantFlushed   bool
	}{
		// Unknown-length upstream responses must be flushed per write.
		{name: "unknown length", contentLength: -1, wantFlushed: true},
		// SSE must flush even when a Content-Length is declared.
		{name: "length-declared event stream", contentLength: 9, contentType: "text/event-stream; charset=utf-8", wantFlushed: true},
		// Fixed-length responses keep the unflushed fast path.
		{name: "fixed length", contentLength: 9, wantFlushed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			if tt.contentType != "" {
				header.Set("Content-Type", tt.contentType)
			}
			stub := &stubClient{resp: &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: tt.contentLength,
				Header:        header,
				Body:          io.NopCloser(strings.NewReader("data: x\n\n")),
			}}
			h := &proxyHandler{logger: discardLogger(), proxy: staticProxy(stub)}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://sts.us-east-1.amazonaws.com/", nil))
			if rec.Flushed != tt.wantFlushed {
				t.Errorf("Flushed = %v, want %v", rec.Flushed, tt.wantFlushed)
			}
		})
	}
}

// parseFlagsForTest runs parseFlags with a quiet throwaway FlagSet.
func parseFlagsForTest(args ...string) (*options, error) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return parseFlags(fs, args)
}

func TestParseFlagsRejectsLeftoverArgs(t *testing.T) {
	if _, err := parseFlagsForTest("--verbose", "false", "--strip", "X"); err == nil {
		t.Fatal("expected error for leftover non-flag arguments")
	}

	o, err := parseFlagsForTest("--verbose", "--strip", "X")
	if err != nil {
		t.Fatalf("valid args rejected: %v", err)
	}
	if !o.verbose || len(o.strip) != 1 || o.strip[0] != "X" {
		t.Errorf("options = %+v, want verbose + strip [X]", o)
	}
}

func TestProxyHandlerCopiesResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "hit")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "brewed")
	}))
	defer upstream.Close()

	p := staticProxy(upstream.Client())
	p.hostOverride = strings.TrimPrefix(upstream.URL, "http://")
	p.schemeOverride = "http"
	p.serviceOverride = &awsService{signingName: "s3", signingRegion: "us-east-1"}

	h := &proxyHandler{logger: discardLogger(), proxy: p}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://whatever/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if rec.Header().Get("X-Upstream") != "hit" {
		t.Errorf("missing upstream header, got %v", rec.Header())
	}
	if rec.Body.String() != "brewed" {
		t.Errorf("body = %q, want brewed", rec.Body.String())
	}
}
