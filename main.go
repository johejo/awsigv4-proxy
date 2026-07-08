// Command awsigv4-proxy is an alternative implementation of
// aws-sigv4-proxy (https://github.com/awslabs/aws-sigv4-proxy).
//
// It is a reverse proxy that signs outgoing requests with AWS SigV4. Compared
// to the original it uses aws-sdk-go-v2 (which loads shared config by default
// and uses regional STS endpoints by default) and relies on the standard
// library as much as possible. It aims to accept the same command line options.
package main

// services_gen.go (signing-name aliases, partition suffixes and global
// endpoints) is generated from botocore's service definitions:
//go:generate go run ./tools/gen-services

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
)

// stringSlice is a flag.Value that accumulates repeated flag occurrences.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }

func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type options struct {
	verbose             bool
	logFailedRequest    bool
	logSigning          bool
	port                string
	strip               stringSlice
	customHeaders       string
	duplicateHeaders    stringSlice
	roleArn             string
	name                string
	signHost            string
	host                string
	region              string
	noVerifySSL         bool
	idleConnTimeout     time.Duration
	maxIdleConns        int
	maxIdleConnsPerHost int
	maxConnsPerHost     int
	upstreamScheme      string
	unsignedPayload     bool
	maxRequestBodySize  int64
}

const defaultMaxRequestBodySize = 256 << 20 // 256 MiB

func parseFlags(fs *flag.FlagSet, args []string) (*options, error) {
	o := &options{}
	fs.BoolVar(&o.verbose, "verbose", false, "Enable additional logging, implies all the log-* options")
	fs.BoolVar(&o.verbose, "v", false, "Enable additional logging, implies all the log-* options (shorthand)")
	fs.BoolVar(&o.logFailedRequest, "log-failed-requests", false, "Log 4xx and 5xx response body")
	fs.BoolVar(&o.logSigning, "log-signing-process", false, "Log sigv4 signing process")
	fs.StringVar(&o.port, "port", ":8080", "TCP network address (port and optional ip/hostname) for HTTP server to listen on. E.g., :8080, 127.0.0.1:8080, or example.com:80")
	fs.Var(&o.strip, "strip", "Headers to strip from incoming request")
	fs.Var(&o.strip, "s", "Headers to strip from incoming request (shorthand)")
	fs.StringVar(&o.customHeaders, "custom-headers", "", "Comma-separated list of custom headers in key=value format (values cannot contain commas)")
	fs.Var(&o.duplicateHeaders, "duplicate-headers", "Duplicate headers to an X-Original- prefix name")
	fs.StringVar(&o.roleArn, "role-arn", "", "Amazon Resource Name (ARN) of the role to assume")
	fs.StringVar(&o.name, "name", "", "AWS Service to sign for")
	fs.StringVar(&o.signHost, "sign-host", "", "Host to sign for")
	fs.StringVar(&o.host, "host", "", "Host to proxy to")
	fs.StringVar(&o.region, "region", "", "AWS region to sign for")
	fs.BoolVar(&o.noVerifySSL, "no-verify-ssl", false, "Disable peer SSL certificate validation")
	fs.DurationVar(&o.idleConnTimeout, "transport.idle-conn-timeout", 40*time.Second, "Idle timeout to the upstream service")
	fs.IntVar(&o.maxIdleConns, "transport.max-idle-conns", 100, "Maximum number of idle connections to the upstream service across all hosts (0 means no limit)")
	fs.IntVar(&o.maxIdleConnsPerHost, "transport.max-idle-conns-per-host", 100, "Maximum number of idle connections to the upstream service per host (0 means Go's default of 2)")
	fs.IntVar(&o.maxConnsPerHost, "transport.max-conns-per-host", 0, "Maximum number of connections to the upstream service per host, including active, dialing and idle ones (0 means no limit)")
	fs.StringVar(&o.upstreamScheme, "upstream-url-scheme", "", "Protocol to proxy with")
	fs.BoolVar(&o.unsignedPayload, "unsigned-payload", false, "Prevent signing of the payload")
	fs.Int64Var(&o.maxRequestBodySize, "max-request-body-size", defaultMaxRequestBodySize, "Maximum inbound request body size in bytes; larger requests are rejected with 413 (default 256MiB; 0 means no limit)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		// A bool flag given as "--verbose false" makes "false" a positional
		// argument, silently terminating flag parsing; without this check
		// everything after it (e.g. a --strip) would be dropped.
		err := fmt.Errorf("unexpected non-flag arguments: %q (bool flags do not take a separate value; use --flag=value)", fs.Args())
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return nil, err
	}
	return o, nil
}

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	o, err := parseFlags(fs, os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}

	level := slog.LevelInfo
	if o.verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, o, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, o *options, logger *slog.Logger) error {
	customHeaders, err := parseCustomHeaders(o.customHeaders)
	if err != nil {
		return err
	}
	// Header.Del/Values with a non-token name silently matches nothing, so a
	// typo in these flags would otherwise leave a header unstripped (or never
	// duplicated) with no indication. Fail at startup like --custom-headers.
	if err := validateHeaderNames("strip", o.strip); err != nil {
		return err
	}
	if err := validateHeaderNames("duplicate-headers", o.duplicateHeaders); err != nil {
		return err
	}

	cfg, err := loadAWSConfig(ctx, o)
	if err != nil {
		return err
	}

	creds := cfg.Credentials
	if o.roleArn != "" {
		sessionName, err := roleSessionName(os.Hostname)
		if err != nil {
			return err
		}
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, o.roleArn, func(p *stscreds.AssumeRoleOptions) {
			p.RoleSessionName = sessionName
		})
		creds = aws.NewCredentialsCache(provider)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.IdleConnTimeout = o.idleConnTimeout
	transport.MaxIdleConns = o.maxIdleConns
	transport.MaxIdleConnsPerHost = o.maxIdleConnsPerHost
	transport.MaxConnsPerHost = o.maxConnsPerHost
	if o.noVerifySSL {
		logger.Warn("Peer SSL Certificate validation is DISABLED")
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	signer := v4.NewSigner(func(so *v4.SignerOptions) {
		if o.logSigning || o.verbose {
			so.LogSigning = true
			so.Logger = logging.LoggerFunc(func(c logging.Classification, format string, v ...any) {
				logger.Info(fmt.Sprintf(format, v...), "classification", string(c))
			})
		}
	})

	serviceOverride := serviceOverrideFromFlags(o, logger)

	handler := &proxyHandler{
		logger: logger,
		proxy: &proxyClient{
			signer:              signer,
			client:              httpClient,
			credentials:         creds,
			logger:              logger,
			stripHeaders:        o.strip,
			customHeaders:       customHeaders,
			duplicateHeaders:    o.duplicateHeaders,
			serviceOverride:     serviceOverride,
			signingHostOverride: o.signHost,
			hostOverride:        o.host,
			logFailedRequest:    o.logFailedRequest || o.verbose,
			schemeOverride:      o.upstreamScheme,
			unsignedPayload:     o.unsignedPayload,
			maxBodySize:         o.maxRequestBodySize,
		},
	}

	logger.Info("stripping headers", "headers", []string(o.strip))
	logger.Info("duplicating headers", "headers", []string(o.duplicateHeaders))
	logger.Info("listening", "addr", o.port)

	srv := &http.Server{
		Addr:    o.port,
		Handler: handler,
		// Bound the header-read phase to blunt slowloris-style attacks. Read and
		// write timeouts are intentionally left unset: this is a streaming proxy
		// that must support arbitrarily large and slow uploads/downloads.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// serviceOverrideFromFlags builds the signing override from --name/--region.
// Both are required, mirroring the original aws-sigv4-proxy; --name alone is a
// no-op there too, but silently, so warn about the likely misconfiguration.
// --region alone is legitimate (it selects the region for credential
// resolution, e.g. the regional STS endpoint with --role-arn) and gets no
// warning.
func serviceOverrideFromFlags(o *options, logger *slog.Logger) *awsService {
	if o.name != "" && o.region != "" {
		return &awsService{signingName: o.name, signingRegion: o.region}
	}
	if o.name != "" {
		logger.Warn("--name is ignored without --region; signing service and region will be derived from each request's Host header")
	}
	return nil
}

func loadAWSConfig(ctx context.Context, o *options) (aws.Config, error) {
	var optFns []func(*config.LoadOptions) error
	if o.region != "" {
		optFns = append(optFns, config.WithRegion(o.region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, err
	}
	// For the STS regional endpoint to be effective the region must be set.
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return cfg, nil
}

// parseCustomHeaders parses a comma-separated list of key=value pairs.
// Malformed pairs and invalid header names/values are rejected here so a bad
// flag fails at startup; http.Transport would otherwise reject them on every
// proxied request. Values cannot contain commas (there is no escaping).
func parseCustomHeaders(s string) (http.Header, error) {
	h := make(http.Header)
	for pair := range strings.SplitSeq(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("invalid custom header %q: want key=value", pair)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("invalid custom header name %q", k)
		}
		if !ValidHeaderFieldValue(v) {
			return nil, fmt.Errorf("invalid custom header value %q for %q", v, k)
		}
		h.Add(k, v)
	}
	return h, nil
}

// validateHeaderNames checks every name in a header-name flag against the
// RFC 7230 token rule.
func validateHeaderNames(flagName string, names []string) error {
	for _, name := range names {
		if !ValidHeaderFieldName(name) {
			return fmt.Errorf("invalid header name %q in --%s", name, flagName)
		}
	}
	return nil
}

// roleSessionNamePattern is the STS AssumeRole RoleSessionName constraint.
var roleSessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

// roleSessionName derives the AssumeRole session name. An explicit
// AWS_ROLE_SESSION_NAME is rejected if invalid (rewriting it would hide the
// misconfiguration); the hostname-derived default is sanitized instead.
func roleSessionName(hostnameFn func() (string, error)) (string, error) {
	if env := os.Getenv("AWS_ROLE_SESSION_NAME"); env != "" {
		if !roleSessionNamePattern.MatchString(env) {
			return "", fmt.Errorf("AWS_ROLE_SESSION_NAME %q must match %s", env, roleSessionNamePattern)
		}
		return env, nil
	}
	name := "awsigv4-proxy-"
	if hostname, err := hostnameFn(); err == nil {
		name += hostname
	} else {
		name += strconv.FormatInt(time.Now().Unix(), 10)
	}
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z',
			r == '_', r == '+', r == '=', r == ',', r == '.', r == '@', r == '-':
			return r
		}
		return '-'
	}, name)
	if len(name) > 64 {
		name = name[:64]
	}
	return name, nil
}
