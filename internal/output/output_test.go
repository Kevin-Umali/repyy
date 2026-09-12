package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func sampleReport() model.Report {
	return model.Report{SchemaVersion: "1", ToolVersion: "test", GeneratedAt: time.Unix(0, 0).UTC(), Results: []model.RepoResult{{Target: "fixture", Verdict: model.VerdictReview, Coverage: model.Coverage{Complete: true, FilesScanned: 1}, Findings: []model.Finding{{RuleID: "TEST-001", Category: "test", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Path: "file.txt", Line: 2, Message: "test finding", Evidence: "safe evidence", Fingerprint: "sha256:test"}}}}}
}

func TestTerminalIncludesVerdictAndDisclaimer(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "terminal", sampleReport()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), model.VerdictReview) || !strings.Contains(out.String(), "does not guarantee") {
		t.Fatalf("unexpected terminal output: %s", out.String())
	}
}

func TestJSONOutput(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "json", sampleReport()); err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Results) != 1 {
		t.Fatalf("unexpected report: %+v", decoded)
	}
}

func TestSARIFOutput(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "sarif", sampleReport()); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF: %+v", decoded)
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", sampleReport()); err == nil {
		t.Fatal("expected an error")
	}
}
