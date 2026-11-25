package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
)

func TestReportConvertsLegacyJSONToSelfContainedHTML(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestReportRejectsInvalidInput(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
