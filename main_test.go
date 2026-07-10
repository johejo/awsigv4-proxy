package main

import (
	"bytes"
	"flag"
	"io"
	"log/slog"
	"strings"
	"testing"
)

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

func TestVersionString(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "v9.9.9"
	if got := versionString(); got != "v9.9.9" {
		t.Errorf("versionString() = %q, want v9.9.9", got)
	}

	// The fallback value varies by build, so only assert it is non-empty.
	version = ""
	if got := versionString(); got == "" {
		t.Error("versionString() = \"\", want non-empty fallback")
	}
}

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
	if o.maxRequestBodySize != defaultMaxRequestBodySize {
		t.Errorf("maxRequestBodySize = %d, want default %d", o.maxRequestBodySize, defaultMaxRequestBodySize)
	}

	if o.version {
		t.Error("version = true, want false by default")
	}
	o, err = parseFlagsForTest("--version")
	if err != nil || !o.version {
		t.Errorf("parseFlags(--version) = %+v, %v; want version=true", o, err)
	}
}
