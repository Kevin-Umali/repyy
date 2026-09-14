package app

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestLocalScanRecordsHostMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_, err := Run([]string{"scan", t.TempDir(), "--format", "json", "--progress", "quiet"}, &stdout, &stderr, "test")
	if err != nil {
		t.Fatal(err)
	}
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].ScanMode != "host" {
		t.Fatalf("scan mode not recorded: %+v", report.Results)
	}
}

func TestReportValidationDistinguishesLegacyAndInvalidScanMode(t *testing.T) {
	for _, mode := range []model.ScanMode{"", model.ScanModeHost, model.ScanModeDocker, "invented"} {
		report := model.Report{SchemaVersion: "1", Results: []model.RepoResult{{
			ScanMode: mode, Verdict: model.VerdictNoFindings, Coverage: model.Coverage{Complete: true},
		}}}
		err := normalizeAndValidateReport(&report)
		if (err != nil) != (mode == "invented") {
			t.Fatalf("mode %q: unexpected validation error %v", mode, err)
		}
	}
}
