package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
)

func TestCleanupFailurePreservesFindingsAndFailsVisibly(t *testing.T) {
	result := model.RepoResult{
		Target:   "assignment",
		Verdict:  model.VerdictReview,
		Coverage: model.Coverage{Complete: true},
		Findings: []model.Finding{{RuleID: "TEST-001", Severity: model.SeverityHigh, Message: "Review the observed behavior"}},
	}
	finishCheckout(&result, func() error { return errors.New("private filesystem detail") })
	if result.Coverage.Complete || result.Verdict != model.VerdictIncomplete || len(result.Findings) != 1 {
		t.Fatalf("cleanup failure lost findings or completion state: %+v", result)
	}
	var rendered bytes.Buffer
	if err := output.Write(&rendered, "terminal", model.Report{Results: []model.RepoResult{result}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), "temporary checkout cleanup failed") || strings.Contains(rendered.String(), "private filesystem detail") {
		t.Fatalf("cleanup failure not safely reported: %s", rendered.String())
	}
}
