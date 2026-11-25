// Package registry reads public package-registry metadata for declared
// dependencies. It is used only when a scan explicitly opts in to network
// lookups; the default scan path never constructs a Client.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Ecosystem names a public registry that Client can query.
type Ecosystem string

const (
	NPM  Ecosystem = "npm"
	PyPI Ecosystem = "pypi"
)

// Package identifies one registry package by its normalized name.
type Package struct {
	Ecosystem Ecosystem
	Name      string
}

// Status is what the registry reports about a package's existence.
type Status int

const (
	// Unknown is the zero value: the lookup did not establish a status.
	Unknown Status = iota
	// Published means the registry serves metadata with at least one release.
	Published
	// Missing means the registry has no package by this name.
	Missing
	// Unpublished means the package existed but every version was removed.
	Unpublished
	// SecurityHold means npm replaced the package with its security placeholder,
	// which it does after removing malware.
	SecurityHold
)

// Record is the registry metadata the reputation policy reads.
type Record struct {
	Package
	Status          Status
	FirstPublished  time.Time
	LatestPublished time.Time
	Versions        int
	// WeeklyDownloads is -1 when the registry has no download data or it was not requested.
	WeeklyDownloads int64
}

const (
	defaultTimeout   = 15 * time.Second
	maxMetadataBytes = 64 << 20
	maxDownloadBytes = 64 << 10
	userAgent        = "repyy-registry-check"
)

// Client queries npm and PyPI. Base URLs are fields so tests can point them at
// local servers.
type Client struct {
	HTTP         *http.Client
	NPMRegistry  string
	NPMDownloads string
	PyPI         string
}

// New returns a Client for the public registries with conservative timeouts
// and redirects confined to the original host.
func New() *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: defaultTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 || req.URL.Host != via[0].URL.Host || req.URL.Scheme != "https" {
					return errors.New("registry redirect refused")
				}
				return nil
			},
		},
		NPMRegistry:  "https://registry.npmjs.org",
		NPMDownloads: "https://api.npmjs.org/downloads/point/last-week",
		PyPI:         "https://pypi.org/pypi",
	}
}

var (
	npmName  = regexp.MustCompile(`^(?i)(@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$`)
	pypiName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	pypiSep  = regexp.MustCompile(`[-_.]+`)
	// npm publishes 0.0.1-security, 0.0.2-security, ... over removed malware.
	securityPlaceholder = regexp.MustCompile(`^0\.0\.\d+-security$`)
)

// Normalize maps a manifest dependency to a registry package. It returns false
// for ecosystems this package does not query and for names or version
// specifiers that do not resolve through the public registry, such as local
// paths, Git URLs, and workspace links.
func Normalize(ecosystem, name, spec string) (Package, bool) {
	switch ecosystem {
	case "npm":
		// npm names are case-sensitive; legacy packages such as JSONStream keep capitals.
		name = strings.TrimSpace(name)
		if len(name) > 214 || !npmName.MatchString(name) || !npmRegistrySpec(spec) {
			return Package{}, false
		}
		return Package{NPM, name}, true
	case "pip":
		if len(name) > 200 || !pypiName.MatchString(name) || strings.EqualFold(name, "python") {
			return Package{}, false
		}
		spec = strings.TrimSpace(spec)
		if strings.HasPrefix(spec, "@") || strings.Contains(spec, "://") {
			return Package{}, false
		}
		return Package{PyPI, pypiSep.ReplaceAllString(strings.ToLower(name), "-")}, true
	default:
		return Package{}, false
	}
}

func npmRegistrySpec(spec string) bool {
	spec = strings.ToLower(strings.TrimSpace(spec))
	for _, prefix := range []string{"npm:", "file:", "link:", "workspace:", "portal:", "patch:", "git", "github:", "gitlab:", "bitbucket:", "gist:", "http:", "https:", "./", "../", "/", "~/"} {
		if strings.HasPrefix(spec, prefix) {
			return false
		}
	}
	// "owner/repo" shorthand resolves to GitHub, not the registry.
	return !strings.Contains(spec, "/")
}

// Lookup fetches existence, publish times, and version count.
// Download counts are fetched separately because they cost a second request.
func (c *Client) Lookup(ctx context.Context, pkg Package) (Record, error) {
	switch pkg.Ecosystem {
	case NPM:
		return c.lookupNPM(ctx, pkg)
	case PyPI:
		return c.lookupPyPI(ctx, pkg)
	default:
		return Record{}, fmt.Errorf("unsupported ecosystem %q", pkg.Ecosystem)
	}
}

// WeeklyDownloads returns npm's last-week download count for a package.
func (c *Client) WeeklyDownloads(ctx context.Context, pkg Package) (int64, error) {
	if pkg.Ecosystem != NPM {
		return -1, nil
	}
	body, status, err := c.get(ctx, c.NPMDownloads+"/"+npmPath(pkg.Name))
	if err != nil {
		return -1, err
	}
	defer body.Close()
	if status == http.StatusNotFound {
		return 0, nil
	}
	var doc struct {
		Downloads *int64 `json:"downloads"`
	}
	if err := json.NewDecoder(bounded(body, maxDownloadBytes)).Decode(&doc); err != nil || doc.Downloads == nil {
		return -1, errors.New("malformed download count")
	}
	return *doc.Downloads, nil
}

func npmPath(name string) string {
	return strings.Replace(url.PathEscape(name), "%40", "@", 1)
}

func (c *Client) get(ctx context.Context, target string) (io.ReadCloser, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		resp.Body.Close()
		return nil, resp.StatusCode, fmt.Errorf("registry returned HTTP %d", resp.StatusCode)
	}
	return resp.Body, resp.StatusCode, nil
}

var errTooLarge = errors.New("registry metadata exceeds size limit")

// countingReader never hands the decoder bytes past the limit, so an oversized
// document fails as truncated instead of decoding from a partial buffer.
type countingReader struct {
	r    io.Reader
	left int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

func bounded(body io.Reader, limit int64) io.Reader {
	return &countingReader{r: body, left: limit}
}

func (c *Client) lookupNPM(ctx context.Context, pkg Package) (Record, error) {
	record := Record{Package: pkg, WeeklyDownloads: -1}
	body, status, err := c.get(ctx, c.NPMRegistry+"/"+npmPath(pkg.Name))
	if err != nil {
		return record, err
	}
	defer body.Close()
	if status == http.StatusNotFound {
		record.Status = Missing
		return record, nil
	}
	doc, err := decodeNPM(bounded(body, maxMetadataBytes))
	if err != nil {
		return record, err
	}
	if securityPlaceholder.MatchString(doc.latest) {
		record.Status = SecurityHold
		return record, nil
	}
	for key, raw := range doc.time {
		switch key {
		case "created":
			record.FirstPublished = parseTime(raw)
		case "modified":
		case "unpublished":
			record.Status = Unpublished
		default:
			record.Versions++
			published := parseTime(raw)
			if record.FirstPublished.IsZero() || (!published.IsZero() && published.Before(record.FirstPublished)) {
				record.FirstPublished = published
			}
			if key == doc.latest {
				record.LatestPublished = published
			}
		}
	}
	if record.Status == Unknown {
		if record.Versions == 0 || record.FirstPublished.IsZero() {
			return record, errors.New("registry metadata has no publish times")
		}
		record.Status = Published
	}
	return record, nil
}

type npmDocument struct {
	time   map[string]json.RawMessage
	latest string
}

// decodeNPM streams the packument and keeps only the fields the policy reads.
// Version manifests, which dominate the size of popular packages, are skipped
// token by token instead of being held in memory.
func decodeNPM(r io.Reader) (npmDocument, error) {
	var doc npmDocument
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return doc, err
	}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return doc, err
		}
		key, _ := token.(string)
		switch key {
		case "time":
			if err := dec.Decode(&doc.time); err != nil {
				return doc, err
			}
		case "dist-tags":
			var tags map[string]json.RawMessage
			if err := dec.Decode(&tags); err != nil {
				return doc, err
			}
			_ = json.Unmarshal(tags["latest"], &doc.latest)
		default:
			if err := skipValue(dec); err != nil {
				return doc, err
			}
		}
	}
	return doc, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != want {
		return errors.New("malformed registry metadata")
	}
	return nil
}

func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			if delim == '{' || delim == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

func parseTime(raw json.RawMessage) time.Time {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func (c *Client) lookupPyPI(ctx context.Context, pkg Package) (Record, error) {
	record := Record{Package: pkg, WeeklyDownloads: -1}
	body, status, err := c.get(ctx, c.PyPI+"/"+url.PathEscape(pkg.Name)+"/json")
	if err != nil {
		return record, err
	}
	defer body.Close()
	if status == http.StatusNotFound {
		record.Status = Missing
		return record, nil
	}
	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := json.NewDecoder(bounded(body, maxMetadataBytes)).Decode(&doc); err != nil {
		return record, err
	}
	for version, files := range doc.Releases {
		if len(files) == 0 {
			continue
		}
		record.Versions++
		for _, file := range files {
			uploaded, err := time.Parse(time.RFC3339, file.UploadTime)
			if err != nil {
				continue
			}
			uploaded = uploaded.UTC()
			if record.FirstPublished.IsZero() || uploaded.Before(record.FirstPublished) {
				record.FirstPublished = uploaded
			}
			if version == doc.Info.Version && uploaded.After(record.LatestPublished) {
				record.LatestPublished = uploaded
			}
		}
	}
	record.Status = Published
	if record.Versions == 0 {
		// PyPI serves projects whose files were all deleted with empty releases.
		record.Status = Unpublished
	}
	return record, nil
}
