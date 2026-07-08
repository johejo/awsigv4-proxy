package main

import (
	"encoding/json"
	"maps"
	"testing"
)

func testEndpoints() *endpointsFile {
	ep := &endpointsFile{}
	if err := json.Unmarshal([]byte(`{
		"partitions": [
			{
				"partition": "aws",
				"dnsSuffix": "amazonaws.com",
				"regionRegex": "^(us|eu)\\-\\w+\\-\\d+$",
				"defaults": {"variants": [
					{"dnsSuffix": "amazonaws.com"},
					{"dnsSuffix": "api.aws"},
					{"dnsSuffix": "api.aws"}
				]},
				"services": {
					"iam": {
						"partitionEndpoint": "aws-global",
						"isRegionalized": false,
						"endpoints": {"aws-global": {"hostname": "iam.amazonaws.com", "credentialScope": {"region": "us-east-1"}}}
					},
					"account": {
						"partitionEndpoint": "aws-global",
						"endpoints": {"aws-global": {"hostname": "account.us-east-1.amazonaws.com", "credentialScope": {"region": "us-east-1"}}}
					},
					"s3": {
						"partitionEndpoint": "aws-global",
						"endpoints": {"aws-global": {"hostname": "s3.amazonaws.com", "credentialScope": {"region": "us-east-1"}}}
					},
					"importexport": {
						"partitionEndpoint": "aws-global",
						"endpoints": {"aws-global": {"hostname": "importexport.amazonaws.com", "credentialScope": {"region": "us-east-1", "service": "IngestionService"}}}
					}
				}
			},
			{
				"partition": "aws-us-gov",
				"dnsSuffix": "amazonaws.com",
				"regionRegex": "^us\\-gov\\-\\w+\\-\\d+$",
				"services": {
					"iam": {
						"partitionEndpoint": "aws-us-gov-global",
						"endpoints": {"aws-us-gov-global": {"hostname": "iam.us-gov.amazonaws.com", "credentialScope": {"region": "us-gov-west-1"}}}
					}
				}
			}
		]
	}`), ep); err != nil {
		panic(err)
	}
	return ep
}

func testInput() *input {
	return &input{
		metas: map[string]serviceMeta{
			"iam":                 {EndpointPrefix: "iam", SigningName: "iam", SignatureVersion: "v4"},
			"account":             {EndpointPrefix: "account", SigningName: "account", SignatureVersion: "v4"},
			"s3":                  {EndpointPrefix: "s3", SigningName: "s3", SignatureVersion: "s3v4"},
			"importexport":        {EndpointPrefix: "importexport", SigningName: "IngestionService", SignatureVersion: "v2"},
			"bedrock-runtime":     {EndpointPrefix: "bedrock-runtime", SigningName: "bedrock", SignatureVersion: "v4"},
			"participant.connect": {EndpointPrefix: "participant.connect", SigningName: "execute-api", SignatureVersion: "v4"},
			"api.ecr":             {EndpointPrefix: "api.ecr", SigningName: "ecr", SignatureVersion: "v4"},
			"data.iot":            {EndpointPrefix: "data.iot", SigningName: "iotdata", SignatureVersion: "v4"},
			"codecatalyst":        {EndpointPrefix: "codecatalyst", SigningName: "codecatalyst-alias", SignatureVersion: "bearer"},
		},
		endpoints: testEndpoints(),
	}
}

func TestBuild(t *testing.T) {
	tables, err := build(testInput())
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Only the sigv4 service whose signing name differs from its label lands
	// in the alias table: identical names, bearer auth and dotted prefixes
	// must not.
	if want := map[string]string{"bedrock-runtime": "bedrock"}; !maps.Equal(tables.aliases, want) {
		t.Errorf("aliases = %v, want %v", tables.aliases, want)
	}

	// Dotted prefixes go to the dotted table unless the signing name already
	// equals the last label (api.ecr) or the prefix is under iot (hand rules).
	if want := map[string]string{"participant.connect": "execute-api"}; !maps.Equal(tables.dotted, want) {
		t.Errorf("dotted = %v, want %v", tables.dotted, want)
	}

	// aws and aws-us-gov share amazonaws.com: their region regexps must both
	// be present (deduplicated), and the variant-only api.aws suffix must
	// carry the aws regex.
	if got := tables.suffixRegex["amazonaws.com"]; len(got) != 2 {
		t.Errorf("amazonaws.com regexps = %v, want the aws and aws-us-gov patterns", got)
	}
	if got := tables.suffixRegex["api.aws"]; len(got) != 1 {
		t.Errorf("api.aws regexps = %v, want the aws pattern only", got)
	}

	// Global endpoints: exact keys per suffix; hosts carrying a region label
	// (account), the s3 legacy endpoint and non-sigv4 services (importexport
	// is v2) are excluded.
	want := map[string]awsSvc{
		"iam":        {Name: "iam", Region: "us-east-1"},
		"iam.us-gov": {Name: "iam", Region: "us-gov-west-1"},
	}
	if got := tables.globals["amazonaws.com"]; !maps.Equal(got, want) {
		t.Errorf("globals[amazonaws.com] = %v, want %v", got, want)
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	// A sigv4 global endpoint without a credentialScope region cannot be
	// signed; it must fail generation, not be silently dropped.
	in := testInput()
	svc := in.endpoints.Partitions[0].Services["iam"]
	ep := svc.Endpoints["aws-global"]
	ep.CredentialScope.Region = ""
	svc.Endpoints["aws-global"] = ep
	in.endpoints.Partitions[0].Services["iam"] = svc
	if _, err := build(in); err == nil {
		t.Error("missing credentialScope region: want error")
	}

	// A dotted prefix deeper than the matcher's probe depth would silently
	// never match.
	in = testInput()
	in.metas["a.b.c.d"] = serviceMeta{EndpointPrefix: "a.b.c.d", SigningName: "x", SignatureVersion: "v4"}
	if _, err := build(in); err == nil {
		t.Error("4-label dotted prefix: want error")
	}

	// An unanchored region regex cannot be recombined into the per-suffix
	// alternation.
	in = testInput()
	in.endpoints.Partitions[0].RegionRegex = `us\-\w+\-\d+`
	if _, err := build(in); err == nil {
		t.Error("unanchored region regex: want error")
	}

	// A global endpoint under no known partition suffix is unmatchable.
	in = testInput()
	svc = in.endpoints.Partitions[0].Services["iam"]
	ep = svc.Endpoints["aws-global"]
	ep.Hostname = "iam.example.org"
	svc.Endpoints["aws-global"] = ep
	in.endpoints.Partitions[0].Services["iam"] = svc
	if _, err := build(in); err == nil {
		t.Error("hostname outside partition suffixes: want error")
	}
}

func TestAddMeta(t *testing.T) {
	in := &input{metas: make(map[string]serviceMeta)}
	v2 := serviceMeta{EndpointPrefix: "sdb", SigningName: "sdb", SignatureVersion: "v2"}
	v4 := serviceMeta{EndpointPrefix: "sdb", SigningName: "sdb", SignatureVersion: "v4"}

	// A SigV4 model wins over a non-SigV4 one regardless of order.
	for _, order := range [][]serviceMeta{{v2, v4}, {v4, v2}} {
		clear(in.metas)
		for _, m := range order {
			if err := in.addMeta("test", m); err != nil {
				t.Fatalf("addMeta: %v", err)
			}
		}
		if got := in.metas["sdb"]; got != v4 {
			t.Errorf("metas[sdb] = %+v, want the v4 model", got)
		}
	}

	// Two SigV4 models sharing a prefix must agree on the signing name.
	clear(in.metas)
	if err := in.addMeta("test", v4); err != nil {
		t.Fatalf("addMeta: %v", err)
	}
	other := v4
	other.SigningName = "other"
	if err := in.addMeta("test", other); err == nil {
		t.Error("conflicting signing names: want error")
	}
}
