awsigv4-proxy

Alternative implementation of aws-sigv4-proxy (https://github.com/awslabs/aws-sigv4-proxy/)

Motivation
  - Use aws-sdk-go-v2, default AWS_SDK_LOAD_CONFIG=1, regional sts endpoint support
  - Less third-party dependencies, use stdlib as much as possible.

Compatibility
  - Support same command line options as aws-sigv4-proxy.
  - Known difference: kingpin-specific flag syntax is not supported —
    attached short values (-sAuthorization), clustered shorts (-vs) and
    negation (--no-verbose). Use --strip Authorization / -s Authorization
    and --flag=value instead.
