package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		{host: "sts.cn-north-1.amazonaws.com.cn", wantName: "sts", wantRegion: "cn-north-1"},
		{host: "sts.us-east-1.amazonaws.com:443", wantName: "sts", wantRegion: "us-east-1"},
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
	f.Add("")
	f.Fuzz(func(t *testing.T, host string) {
		svc := determineAWSServiceFromHost(host)
		if svc != nil && (svc.signingName == "" || !isRegion(svc.signingRegion)) {
			t.Fatalf("invalid service for %q: %+v", host, svc)
		}
	})
}

func TestParseCustomHeaders(t *testing.T) {
	h := parseCustomHeaders("X-Foo=bar,X-Baz=qux,malformed,X-Empty=", discardLogger())
	if got := h.Get("X-Foo"); got != "bar" {
		t.Errorf("X-Foo = %q, want bar", got)
	}
	if got := h.Get("X-Baz"); got != "qux" {
		t.Errorf("X-Baz = %q, want qux", got)
	}
	if _, ok := h["Malformed"]; ok {
		t.Errorf("malformed entry should be skipped, got %v", h)
	}
	if got := h.Get("X-Empty"); got != "" {
		t.Errorf("X-Empty = %q, want empty", got)
	}
	if len(parseCustomHeaders("", discardLogger())) != 0 {
		t.Errorf("empty input should yield no headers")
	}
}

func TestChunked(t *testing.T) {
	if chunked(nil) {
		t.Error("nil transfer-encoding should not be chunked")
	}
	if chunked([]string{"identity"}) {
		t.Error("identity should not be chunked")
	}
	if !chunked([]string{"chunked"}) {
		t.Error("chunked should be chunked")
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

func TestRoleSessionName(t *testing.T) {
	t.Setenv("AWS_ROLE_SESSION_NAME", "custom-session")
	if got := roleSessionName(func() (string, error) { return "host", nil }); got != "custom-session" {
		t.Errorf("roleSessionName = %q, want custom-session", got)
	}
	t.Setenv("AWS_ROLE_SESSION_NAME", "")
	if got := roleSessionName(func() (string, error) { return "myhost", nil }); got != "aws-sigv4-proxy-myhost" {
		t.Errorf("roleSessionName = %q, want aws-sigv4-proxy-myhost", got)
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

func TestProxyClientSignsRequest(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)

	req := httptest.NewRequest(http.MethodGet, "http://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity", nil)
	req.Host = "sts.us-east-1.amazonaws.com"

	resp, err := p.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if stub.got.Header.Get("Authorization") == "" {
		t.Error("missing Authorization header on signed request")
	}
	if stub.got.Header.Get("X-Amz-Date") == "" {
		t.Error("missing X-Amz-Date header on signed request")
	}
	if !strings.Contains(stub.got.Header.Get("Authorization"), "us-east-1/sts/aws4_request") {
		t.Errorf("Authorization does not reference sts/us-east-1: %q", stub.got.Header.Get("Authorization"))
	}
	if stub.got.URL.Scheme != "https" {
		t.Errorf("scheme = %q, want https", stub.got.URL.Scheme)
	}
}

func TestProxyClientOverrides(t *testing.T) {
	stub := &stubClient{}
	p := staticProxy(stub)
	p.hostOverride = "upstream.internal"
	p.serviceOverride = &awsService{signingName: "execute-api", signingRegion: "eu-west-1"}
	p.schemeOverride = "http"
	p.stripHeaders = []string{"Authorization-Downstream"}
	p.duplicateHeaders = []string{"X-Trace"}
	p.customHeaders = http.Header{"X-Custom": []string{"yes"}}

	req := httptest.NewRequest(http.MethodPost, "http://ignored.example.com/path", strings.NewReader("payload"))
	req.Host = "ignored.example.com"
	req.Header.Set("Authorization-Downstream", "secret")
	req.Header.Set("X-Trace", "abc")

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
	if stub.got.Header.Get("X-Original-X-Trace") != "abc" {
		t.Errorf("duplicated header = %q, want abc", stub.got.Header.Get("X-Original-X-Trace"))
	}
	if stub.got.Header.Get("X-Custom") != "yes" {
		t.Errorf("custom header = %q, want yes", stub.got.Header.Get("X-Custom"))
	}
	if string(stub.body) != "payload" {
		t.Errorf("body = %q, want payload", string(stub.body))
	}
}

func TestProxyClientUnknownHost(t *testing.T) {
	p := staticProxy(&stubClient{})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	if _, err := p.Do(req); err == nil {
		t.Fatal("expected error for unknown host without overrides")
	}
}

// Ensure the handler copies the upstream status/body/headers back to the caller.
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
	req.Host = "whatever"
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
