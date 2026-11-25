package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/registry"
)

type fakePackage struct {
	created   time.Time
	versions  int
	downloads int64
	latest    string
}

// fakeRegistry serves npm packuments, npm download counts, and PyPI project
// JSON for the named packages. Unknown names return 404; names in failing
// return 500. It records every path it was asked for.
type fakeRegistry struct {
	npm     map[string]fakePackage
	pypi    map[string]fakePackage
	failing map[string]bool
	mu      sync.Mutex
	paths   []string
}

func (f *fakeRegistry) client(t *testing.T) *registry.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return &registry.Client{HTTP: server.Client(), NPMRegistry: server.URL + "/npm", NPMDownloads: server.URL + "/downloads", PyPI: server.URL + "/pypi"}
}

func (f *fakeRegistry) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	kind, name, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	name = strings.TrimSuffix(name, "/json")
	if f.failing[name] {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	table := f.npm
	if kind == "pypi" {
		table = f.pypi
	}
	pkg, ok := table[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	var doc any
	switch kind {
	case "downloads":
		doc = map[string]any{"downloads": pkg.downloads, "package": name}
	case "npm":
		times := map[string]string{"created": pkg.created.Format(time.RFC3339), "modified": pkg.created.Format(time.RFC3339)}
		versions := map[string]any{}
		for i := range pkg.versions {
			version := fmt.Sprintf("1.0.%d", i)
			times[version] = pkg.created.Add(time.Duration(i) * time.Hour).Format(time.RFC3339)
			versions[version] = map[string]any{"name": name, "version": version, "scripts": map[string]string{"test": "node test.js"}}
		}
		latest := pkg.latest
		if latest == "" {
			latest = fmt.Sprintf("1.0.%d", pkg.versions-1)
		}
		doc = map[string]any{"name": name, "dist-tags": map[string]string{"latest": latest}, "versions": versions, "time": times, "maintainers": []any{map[string]string{"name": "someone"}}}
	case "pypi":
		releases := map[string]any{}
		for i := range pkg.versions {
			releases[fmt.Sprintf("0.%d", i)] = []any{map[string]string{"upload_time_iso_8601": pkg.created.Add(time.Duration(i) * time.Hour).Format(time.RFC3339)}}
		}
		doc = map[string]any{"info": map[string]string{"version": fmt.Sprintf("0.%d", pkg.versions-1)}, "releases": releases}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func findingFor(findings []model.Finding, id, name string) (model.Finding, bool) {
	for _, f := range findings {
		if f.RuleID == id && strings.HasPrefix(f.Evidence, name+" ") {
			return f, true
		}
	}
	return model.Finding{}, false
}

func TestRegistryCheckFlagsNewAndMissingPackages(t *testing.T) {
	now := time.Now().UTC()
	fake := &fakeRegistry{
		npm: map[string]fakePackage{
			"interview-helper-utils": {created: now.Add(-5 * 24 * time.Hour), versions: 1, downloads: 12},
			"busy-new-lib":           {created: now.Add(-10 * 24 * time.Hour), versions: 2, downloads: 50_000},
			"quarantined-lib":        {created: now.Add(-400 * 24 * time.Hour), versions: 1, latest: "0.0.2-security"},
			"express":                {created: now.Add(-15 * 365 * 24 * time.Hour), versions: 280, downloads: 50_000_000},
		},
		pypi: map[string]fakePackage{
			"fresh-crypto-tools": {created: now.Add(-3 * 24 * time.Hour), versions: 1},
			"requests":           {created: now.Add(-14 * 365 * 24 * time.Hour), versions: 150},
		},
	}
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{
  "dependencies": {
    "express": "^4.19.2",
    "interview-helper-utils": "^1.0.0",
    "busy-new-lib": "1.0.1",
    "quarantined-lib": "*",
    "ghost-package-xyz": "^2.0.0",
    "@acme/internal-ui": "^3.0.0",
    "local-lib": "file:../local-lib",
    "forked": "github:someone/forked"
  }
}
`)
	writeFixture(t, root, "requirements.txt", "requests==2.32.3\nFresh_Crypto.Tools>=0.1\n-e ./vendored\n")

	coverage, findings := New(Options{Registry: fake.client(t)}).Scan(context.Background(), root)

	if !coverage.Complete {
		t.Fatalf("expected complete coverage: %+v", coverage)
	}
	expect := []struct {
		id, name   string
		severity   model.Severity
		confidence model.Confidence
		path       string
		line       int
	}{
		{"PKG-010", "interview-helper-utils", model.SeverityHigh, model.ConfidenceMedium, "package.json", 4},
		{"PKG-010", "busy-new-lib", model.SeverityMedium, model.ConfidenceMedium, "package.json", 5},
		{"PKG-011", "quarantined-lib", model.SeverityCritical, model.ConfidenceHigh, "package.json", 6},
		{"PKG-011", "ghost-package-xyz", model.SeverityHigh, model.ConfidenceMedium, "package.json", 7},
		{"PKG-011", "@acme/internal-ui", model.SeverityMedium, model.ConfidenceLow, "package.json", 8},
		{"PKG-010", "Fresh_Crypto.Tools", model.SeverityMedium, model.ConfidenceMedium, "requirements.txt", 2},
	}
	for _, want := range expect {
		got, ok := findingFor(findings, want.id, want.name)
		if !ok {
			t.Errorf("missing %s for %s in %+v", want.id, want.name, findings)
			continue
		}
		if got.Severity != want.severity || got.Confidence != want.confidence || got.Path != want.path || got.Line != want.line {
			t.Errorf("%s %s: got %s/%s at %s:%d, want %s/%s at %s:%d", want.id, want.name, got.Severity, got.Confidence, got.Path, got.Line, want.severity, want.confidence, want.path, want.line)
		}
	}
	if got, _ := findingFor(findings, "PKG-010", "interview-helper-utils"); !strings.Contains(got.Message, "1 version; 12 downloads last week") {
		t.Errorf("message should state the registry facts: %q", got.Message)
	}
	for _, benign := range []string{"express", "requests", "local-lib", "forked"} {
		for _, id := range []string{"PKG-010", "PKG-011"} {
			if f, ok := findingFor(findings, id, benign); ok {
				t.Errorf("benign dependency %s produced %+v", benign, f)
			}
		}
	}
	for _, path := range fake.requested() {
		if strings.Contains(path, "local-lib") || strings.Contains(path, "forked") || strings.Contains(path, "vendored") {
			t.Errorf("non-registry dependency was looked up: %s", path)
		}
	}
}

func TestRegistryCheckLooksUpEachPackageOnceAndSkipsWorkspaces(t *testing.T) {
	now := time.Now().UTC()
	fake := &fakeRegistry{npm: map[string]fakePackage{"shared-new-lib": {created: now.Add(-2 * 24 * time.Hour), versions: 1, downloads: 3}}}
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{"dependencies":{"shared-new-lib":"1.0.0"}}`)
	writeFixture(t, root, "packages/web/package.json", `{"name":"web-app","devDependencies":{"shared-new-lib":"1.0.0","ui-kit":"*"}}`)
	writeFixture(t, root, "packages/ui-kit/package.json", `{"name":"ui-kit","dependencies":{"web-app":"^1.0.0"}}`)

	_, findings := New(Options{Registry: fake.client(t)}).Scan(context.Background(), root)

	metadataRequests := 0
	for _, path := range fake.requested() {
		if path == "/npm/shared-new-lib" {
			metadataRequests++
		}
	}
	if metadataRequests != 1 {
		t.Errorf("expected one metadata request, got %d: %v", metadataRequests, fake.requested())
	}
	if hasRule(findings, "PKG-011") {
		t.Errorf("workspace packages defined in the repository are not registry dependencies: %+v", findings)
	}
	paths := map[string]bool{}
	for _, f := range findings {
		if f.RuleID == "PKG-010" {
			paths[f.Path] = true
		}
	}
	if !paths["package.json"] || !paths["packages/web/package.json"] {
		t.Errorf("each declaring manifest should carry the finding: %+v", findings)
	}
}

func TestRegistryFailureMarksCoverageIncomplete(t *testing.T) {
	now := time.Now().UTC()
	fake := &fakeRegistry{
		npm:     map[string]fakePackage{"brand-new-dep": {created: now.Add(-1 * 24 * time.Hour), versions: 1, downloads: 0}},
		failing: map[string]bool{"flaky-dep": true},
	}
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{"dependencies":{"flaky-dep":"^1.0.0","brand-new-dep":"^1.0.0"}}`)

	coverage, findings := New(Options{Registry: fake.client(t)}).Scan(context.Background(), root)

	if coverage.Complete {
		t.Fatal("a failed registry lookup must not leave coverage complete")
	}
	if !strings.Contains(strings.Join(coverage.Warnings, "\n"), "registry check failed for 1 of 2 packages: npm flaky-dep") {
		t.Errorf("warning should name the failed package: %v", coverage.Warnings)
	}
	if _, ok := findingFor(findings, "PKG-010", "brand-new-dep"); !ok {
		t.Errorf("successful lookups should still report: %+v", findings)
	}
}

func TestRegistryUnreachableMarksCoverageIncomplete(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	unreachable := server.URL
	server.Close()
	client := &registry.Client{HTTP: &http.Client{Timeout: time.Second}, NPMRegistry: unreachable, NPMDownloads: unreachable, PyPI: unreachable}
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{"dependencies":{"express":"^4.19.2"}}`)

	coverage, findings := New(Options{Registry: client}).Scan(context.Background(), root)

	if coverage.Complete || len(coverage.Warnings) == 0 {
		t.Fatalf("unreachable registry must be reported: %+v", coverage)
	}
	if hasRule(findings, "PKG-010") || hasRule(findings, "PKG-011") {
		t.Errorf("no reputation finding without registry data: %+v", findings)
	}
}

func TestAssessReputationThresholds(t *testing.T) {
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	cases := []struct {
		name       string
		record     registry.Record
		id         string
		severity   model.Severity
		confidence model.Confidence
	}{
		{"recent npm package", registry.Record{Package: registry.Package{Ecosystem: registry.NPM, Name: "a"}, FirstPublished: now.Add(-60 * day), Versions: 8, WeeklyDownloads: 5000}, "PKG-010", model.SeverityMedium, model.ConfidenceLow},
		{"old but unused npm package", registry.Record{Package: registry.Package{Ecosystem: registry.NPM, Name: "b"}, FirstPublished: now.Add(-900 * day), Versions: 1, WeeklyDownloads: 4}, "PKG-010", model.SeverityMedium, model.ConfidenceLow},
		{"old single-release PyPI package", registry.Record{Package: registry.Package{Ecosystem: registry.PyPI, Name: "c"}, FirstPublished: now.Add(-900 * day), Versions: 1, WeeklyDownloads: -1}, "", "", ""},
		{"new PyPI package cannot reach high without download data", registry.Record{Package: registry.Package{Ecosystem: registry.PyPI, Name: "d"}, FirstPublished: now.Add(-2 * day), Versions: 1, WeeklyDownloads: -1}, "PKG-010", model.SeverityMedium, model.ConfidenceMedium},
		{"unpublished package", registry.Record{Package: registry.Package{Ecosystem: registry.NPM, Name: "e"}, Status: registry.Unpublished}, "PKG-011", model.SeverityHigh, model.ConfidenceMedium},
	}
	for _, tc := range cases {
		signal, ok := assessReputation(tc.record, now)
		if tc.id == "" {
			if ok {
				t.Errorf("%s: unexpected %+v", tc.name, signal)
			}
			continue
		}
		if !ok || signal.ruleID != tc.id || signal.severity != tc.severity || signal.confidence != tc.confidence {
			t.Errorf("%s: got %+v (ok=%v), want %s %s/%s", tc.name, signal, ok, tc.id, tc.severity, tc.confidence)
		}
	}
}
