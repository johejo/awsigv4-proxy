// Command gen-services generates services_gen.go from botocore's service
// definitions: SigV4 signing-name aliases from each service model's metadata
// (endpointPrefix vs signingName), and partition DNS suffixes, region
// regexps and region-less global endpoints from endpoints.json.
//
// Only name/region *data* is generated; the host-shape matching logic stays
// hand-written in proxy.go. Endpoint shapes that predate endpoints.json or
// are owned by hand-written rules (the s3 family, iot data planes) are
// excluded here and covered in proxy.go instead.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
)

// defaultRef is the pinned botocore release the generated file is built from.
const defaultRef = "1.43.42"

func main() {
	log.SetFlags(0)
	log.SetPrefix("gen-services: ")
	ref := flag.String("ref", defaultRef, "botocore git ref (tag or commit) to download")
	src := flag.String("src", "", "local botocore data directory (skips the download; output is still stamped with -ref)")
	out := flag.String("o", "services_gen.go", "output file")
	flag.Parse()

	var in *input
	var err error
	if *src != "" {
		in, err = readLocal(*src)
	} else {
		in, err = download(*ref)
	}
	if err != nil {
		log.Fatal(err)
	}
	t, err := build(in)
	if err != nil {
		log.Fatal(err)
	}
	code, err := render(t, *ref)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, code, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s: %d aliases, %d dotted aliases, %d suffixes, %d global endpoints",
		*out, len(t.aliases), len(t.dotted), len(t.suffixRegex), t.globalCount())
}

// serviceMeta is the metadata object of a service-2.json model.
type serviceMeta struct {
	EndpointPrefix   string `json:"endpointPrefix"`
	SigningName      string `json:"signingName"`
	SignatureVersion string `json:"signatureVersion"`
}

// endpointsFile is the subset of endpoints.json this generator consumes.
type endpointsFile struct {
	Partitions []struct {
		Partition   string `json:"partition"`
		DNSSuffix   string `json:"dnsSuffix"`
		RegionRegex string `json:"regionRegex"`
		Defaults    struct {
			Variants []struct {
				DNSSuffix string `json:"dnsSuffix"`
			} `json:"variants"`
		} `json:"defaults"`
		Services map[string]struct {
			PartitionEndpoint string `json:"partitionEndpoint"`
			Endpoints         map[string]struct {
				Hostname        string `json:"hostname"`
				CredentialScope struct {
					Region  string `json:"region"`
					Service string `json:"service"`
				} `json:"credentialScope"`
			} `json:"endpoints"`
		} `json:"services"`
	} `json:"partitions"`
}

type input struct {
	// metas is keyed by endpointPrefix (which is also the service key used
	// in endpoints.json).
	metas     map[string]serviceMeta
	endpoints *endpointsFile
}

func (in *input) addMeta(source string, m serviceMeta) error {
	if m.EndpointPrefix == "" {
		return fmt.Errorf("%s: no endpointPrefix", source)
	}
	if m.SigningName == "" {
		m.SigningName = m.EndpointPrefix
	}
	// Several service models share an endpointPrefix (e.g. sms-voice and
	// pinpoint-sms-voice, or sdb's v2 and v4 models). SigV4 models must agree
	// on the signing name; a SigV4 model wins over a non-SigV4 one.
	if prev, ok := in.metas[m.EndpointPrefix]; ok {
		if isSigV4(prev) && isSigV4(m) && prev.SigningName != m.SigningName {
			return fmt.Errorf("%s: endpointPrefix %q has conflicting signing names: %q vs %q", source, m.EndpointPrefix, prev.SigningName, m.SigningName)
		}
		if isSigV4(prev) && !isSigV4(m) {
			return nil
		}
	}
	in.metas[m.EndpointPrefix] = m
	return nil
}

func parseServiceModel(source string, r io.Reader, in *input) error {
	var model struct {
		Metadata serviceMeta `json:"metadata"`
	}
	if err := json.NewDecoder(r).Decode(&model); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	return in.addMeta(source, model.Metadata)
}

// download fetches the botocore source tarball at ref and extracts the
// service metadata and endpoints.json from it.
func download(ref string) (*input, error) {
	url := "https://codeload.github.com/boto/botocore/tar.gz/" + ref
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}

	in := &input{metas: make(map[string]serviceMeta)}
	// Per service directory only the latest API version's model is used;
	// versions are dates (YYYY-MM-DD), so they order lexically.
	latest := make(map[string]string)             // service dir -> latest version seen
	models := make(map[string]serviceMeta)        // service dir -> metadata of that version
	modelRe := regexp.MustCompile(`^[^/]+/botocore/data/([^/]+)/([^/]+)/service-2\.json$`)
	endpointsRe := regexp.MustCompile(`^[^/]+/botocore/data/endpoints\.json$`)

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if endpointsRe.MatchString(hdr.Name) {
			in.endpoints = &endpointsFile{}
			if err := json.NewDecoder(tr).Decode(in.endpoints); err != nil {
				return nil, fmt.Errorf("%s: %w", hdr.Name, err)
			}
			continue
		}
		m := modelRe.FindStringSubmatch(hdr.Name)
		if m == nil {
			continue
		}
		svc, version := m[1], m[2]
		if version <= latest[svc] {
			continue
		}
		var model struct {
			Metadata serviceMeta `json:"metadata"`
		}
		if err := json.NewDecoder(tr).Decode(&model); err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		latest[svc], models[svc] = version, model.Metadata
	}
	if in.endpoints == nil {
		return nil, fmt.Errorf("no endpoints.json in tarball")
	}
	for _, svc := range slices.Sorted(maps.Keys(models)) {
		if err := in.addMeta("data/"+svc, models[svc]); err != nil {
			return nil, err
		}
	}
	return in, nil
}

// readLocal reads an extracted botocore data directory (the directory that
// contains endpoints.json and one subdirectory per service).
func readLocal(dir string) (*input, error) {
	in := &input{metas: make(map[string]serviceMeta)}

	f, err := os.Open(filepath.Join(dir, "endpoints.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	in.endpoints = &endpointsFile{}
	if err := json.NewDecoder(f).Decode(in.endpoints); err != nil {
		return nil, err
	}

	svcDirs, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, sd := range svcDirs {
		if !sd.IsDir() {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(dir, sd.Name()))
		if err != nil {
			return nil, err
		}
		var latest string
		for _, v := range versions {
			if v.IsDir() && v.Name() > latest {
				latest = v.Name()
			}
		}
		if latest == "" {
			continue
		}
		path := filepath.Join(dir, sd.Name(), latest, "service-2.json")
		mf, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		err = parseServiceModel(path, mf, in)
		mf.Close()
		if err != nil {
			return nil, err
		}
	}
	return in, nil
}

// signingNameRe mirrors proxy.go: generated signing names must be plausible
// SigV4 signing names.
var signingNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// maxDottedLabels is the deepest dotted alias key proxy.go probes for; a
// longer endpointPrefix would silently never match, so build fails on it.
const maxDottedLabels = 3

type tables struct {
	aliases map[string]string // single host label -> signing name
	dotted  map[string]string // dotted endpoint prefix -> signing name
	// suffixRegex maps a partition DNS suffix to the anchor-stripped region
	// regexps of every partition using that suffix (aws and aws-us-gov share
	// amazonaws.com and api.aws).
	suffixRegex map[string][]string
	globals     map[string]map[string]awsSvc // suffix -> host minus suffix -> service
}

// awsSvc fields are exported for the render template.
type awsSvc struct {
	Name   string
	Region string
}

func (t *tables) globalCount() int {
	n := 0
	for _, m := range t.globals {
		n += len(m)
	}
	return n
}

func isSigV4(m serviceMeta) bool {
	return m.SignatureVersion == "v4" || m.SignatureVersion == "s3v4"
}

func build(in *input) (*tables, error) {
	t := &tables{
		aliases:     make(map[string]string),
		dotted:      make(map[string]string),
		suffixRegex: make(map[string][]string),
		globals:     make(map[string]map[string]awsSvc),
	}

	for prefix, m := range in.metas {
		if !isSigV4(m) {
			continue
		}
		labels := strings.Split(prefix, ".")
		if slices.Contains(labels, "") {
			return nil, fmt.Errorf("endpointPrefix %q: empty label", prefix)
		}
		last := labels[len(labels)-1]
		if m.SigningName == last {
			continue // the hand-written matchers already derive this name
		}
		// Prefixes under iot are matched by the hand-written iot data-plane
		// rules in proxy.go, whatever their signing name.
		if last == "iot" {
			continue
		}
		if !signingNameRe.MatchString(m.SigningName) {
			return nil, fmt.Errorf("endpointPrefix %q: implausible signing name %q", prefix, m.SigningName)
		}
		if len(labels) == 1 {
			t.aliases[prefix] = m.SigningName
			continue
		}
		if len(labels) > maxDottedLabels {
			return nil, fmt.Errorf("endpointPrefix %q: more than %d labels; raise the probe depth in proxy.go", prefix, maxDottedLabels)
		}
		t.dotted[prefix] = m.SigningName
	}

	if in.endpoints == nil {
		return nil, fmt.Errorf("no endpoints data")
	}
	for _, p := range in.endpoints.Partitions {
		regionRe, err := regexp.Compile(p.RegionRegex)
		if err != nil {
			return nil, fmt.Errorf("partition %s: %w", p.Partition, err)
		}
		stripped, err := stripAnchors(p.RegionRegex)
		if err != nil {
			return nil, fmt.Errorf("partition %s: %w", p.Partition, err)
		}

		suffixes := []string{p.DNSSuffix}
		for _, v := range p.Defaults.Variants {
			if v.DNSSuffix != "" && !slices.Contains(suffixes, v.DNSSuffix) {
				suffixes = append(suffixes, v.DNSSuffix)
			}
		}
		for _, s := range suffixes {
			if !slices.Contains(t.suffixRegex[s], stripped) {
				t.suffixRegex[s] = append(t.suffixRegex[s], stripped)
			}
		}

		for svcKey, sd := range p.Services {
			if sd.PartitionEndpoint == "" {
				continue
			}
			ep, ok := sd.Endpoints[sd.PartitionEndpoint]
			if !ok || ep.Hostname == "" {
				return nil, fmt.Errorf("partition %s service %s: partition endpoint %q has no hostname", p.Partition, svcKey, sd.PartitionEndpoint)
			}
			meta, ok := in.metas[svcKey]
			if !ok {
				return nil, fmt.Errorf("partition %s: no service model for endpoints.json service %q", p.Partition, svcKey)
			}
			if !isSigV4(meta) {
				continue
			}
			if svcKey == "s3" {
				continue // the legacy global S3 endpoint is a hand-written rule
			}
			suffix := ""
			for _, s := range suffixes {
				if strings.HasSuffix(ep.Hostname, "."+s) && (suffix == "" || len(s) > len(suffix)) {
					suffix = s
				}
			}
			if suffix == "" {
				return nil, fmt.Errorf("partition %s service %s: hostname %q not under any partition suffix", p.Partition, svcKey, ep.Hostname)
			}
			key := strings.TrimSuffix(ep.Hostname, "."+suffix)
			// Hosts that carry a region label (account.us-east-1.amazonaws.com)
			// are already resolved by the generic region rule.
			if slices.ContainsFunc(strings.Split(key, "."), regionRe.MatchString) {
				continue
			}
			if ep.CredentialScope.Region == "" {
				return nil, fmt.Errorf("partition %s service %s: global endpoint %q has no credentialScope region", p.Partition, svcKey, ep.Hostname)
			}
			name := meta.SigningName
			if ep.CredentialScope.Service != "" {
				name = ep.CredentialScope.Service
			}
			if !signingNameRe.MatchString(name) {
				return nil, fmt.Errorf("partition %s service %s: implausible signing name %q", p.Partition, svcKey, name)
			}
			svc := awsSvc{Name: name, Region: ep.CredentialScope.Region}
			if t.globals[suffix] == nil {
				t.globals[suffix] = make(map[string]awsSvc)
			}
			if prev, ok := t.globals[suffix][key]; ok && prev != svc {
				return nil, fmt.Errorf("global endpoint %s.%s: conflicting entries %+v vs %+v", key, suffix, prev, svc)
			}
			t.globals[suffix][key] = svc
		}
	}
	return t, nil
}

// stripAnchors removes the mandatory ^...$ anchors so per-partition regexps
// can be recombined into one anchored alternation per DNS suffix.
func stripAnchors(re string) (string, error) {
	if !strings.HasPrefix(re, "^") || !strings.HasSuffix(re, "$") {
		return "", fmt.Errorf("region regex %q is not anchored", re)
	}
	return strings.TrimSuffix(strings.TrimPrefix(re, "^"), "$"), nil
}

// fileTemplate renders services_gen.go. text/template ranges maps in sorted
// key order, so the output is deterministic. q quotes a value as a Go string
// literal; backquote as a raw string literal (for regexp patterns).
var fileTemplate = template.Must(template.New("services_gen").Funcs(template.FuncMap{
	"q":         strconv.Quote,
	"backquote": backquote,
}).Parse(`// Code generated by tools/gen-services from botocore {{.Ref}}; DO NOT EDIT.
//
// Source: https://github.com/boto/botocore/tree/{{.Ref}}/botocore/data
// Regenerate with: go generate ./...

package main

import "regexp"

// generatedServiceAliases maps single-label endpoint host labels whose SigV4
// signing name differs from the label itself (service model endpointPrefix vs
// signingName).
var generatedServiceAliases = map[string]string{
{{- range $label, $name := .Aliases}}
	{{q $label}}: {{q $name}},
{{- end}}
}

// generatedDottedAliases maps multi-label endpoint prefixes (the labels
// immediately before the region) whose signing name differs from their last
// label, e.g. participant.connect.<region>.amazonaws.com signs "execute-api".
// Prefixes under iot are excluded: proxy.go's iot rules own those hosts.
var generatedDottedAliases = map[string]string{
{{- range $prefix, $name := .Dotted}}
	{{q $prefix}}: {{q $name}},
{{- end}}
}

// generatedPartitionSuffixes maps each partition DNS suffix to the pattern
// matching its region labels. A suffix shared by several partitions (aws and
// aws-us-gov both use amazonaws.com) gets the union of their region regexps.
var generatedPartitionSuffixes = map[string]*regexp.Regexp{
{{- range $suffix, $pattern := .Suffixes}}
	{{q $suffix}}: regexp.MustCompile({{backquote $pattern}}),
{{- end}}
}

// generatedGlobalEndpoints lists region-less global endpoints (host labels
// before the partition suffix, exact match) with the fixed credential scope
// they sign against.
var generatedGlobalEndpoints = map[string]map[string]awsService{
{{- range $suffix, $endpoints := .Globals}}
	{{q $suffix}}: {
	{{- range $host, $svc := $endpoints}}
		{{q $host}}: {signingName: {{q $svc.Name}}, signingRegion: {{q $svc.Region}}},
	{{- end}}
	},
{{- end}}
}
`))

// backquote renders s as a Go raw string literal, in which regexp patterns
// read better than in an escaped quoted string. A backtick in s cannot be
// represented and fails the render.
func backquote(s string) (string, error) {
	if strings.Contains(s, "`") {
		return "", fmt.Errorf("pattern %q cannot be a raw string literal", s)
	}
	return "`" + s + "`", nil
}

func render(t *tables, ref string) ([]byte, error) {
	suffixes := make(map[string]string, len(t.suffixRegex))
	for s, res := range t.suffixRegex {
		res = slices.Clone(res)
		slices.Sort(res)
		suffixes[s] = "^(?:" + strings.Join(res, "|") + ")$"
	}
	var b bytes.Buffer
	err := fileTemplate.Execute(&b, struct {
		Ref      string
		Aliases  map[string]string
		Dotted   map[string]string
		Suffixes map[string]string
		Globals  map[string]map[string]awsSvc
	}{ref, t.aliases, t.dotted, suffixes, t.globals})
	if err != nil {
		return nil, err
	}
	return format.Source(b.Bytes())
}
