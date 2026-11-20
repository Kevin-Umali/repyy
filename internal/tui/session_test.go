package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
)

func TestCancelWaitsForScanCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup := make(chan struct{})
	cancelled := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-cleanup:
		default:
			close(cleanup)
		}
	})
	s := newSession(ctx, Options{Targets: 1}, func(ctx context.Context, _ string, _ func()) (model.Report, string, error) {
		<-ctx.Done()
		close(cancelled)
		<-cleanup
		return model.Report{}, "", ctx.Err()
	})
	s.Init()
	_, quit := s.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	if quit != nil {
		t.Fatal("UI quit before the scan worker cleaned up")
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("scan worker never received cancellation")
	}
	if got := ansi.Strip(s.View().Content); !strings.Contains(got, "Cancelling and cleaning up") {
		t.Fatalf("the cancellation screen is missing: %q", got)
	}
	select {
	case <-s.task.done:
		t.Fatal("scan task finished before cleanup")
	default:
	}
	close(cleanup)
	select {
	case <-s.task.done:
	case <-time.After(2 * time.Second):
		t.Fatal("scan task did not return after cleanup")
	}
	_, quit = s.Update(s.task.result)
	if quit == nil {
		t.Fatal("the UI must quit after cancelled work is cleaned up")
	}
	if _, ok := quit().(tea.QuitMsg); !ok {
		t.Fatal("cancelled work did not return a quit message")
	}
}

func TestReviewDoesNotChangeReportUsedForExitPolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := output.DefaultOptions()
	opts.MinSeverity = model.SeverityCritical
	s := newSession(ctx, Options{Presentation: opts}, nil)
	finding := model.Finding{
		RuleID: "CHECK-1", Category: "test", Context: "executable",
		Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh,
		Message: "Review the configuration", Path: "config.toml",
		Remediation: "Inspect the configuration.",
	}
	report := model.Report{Results: []model.RepoResult{
		{Target: "demo", Verdict: model.VerdictReview, Coverage: model.Coverage{Complete: true}, Findings: []model.Finding{finding}},
	}}
	s.Update(loadResult{report: report})
	view := ansi.Strip(s.View().Content)
	if !strings.Contains(view, "1 finding hidden by display options") {
		t.Fatalf("display filter was ignored: %q", view)
	}
	if len(s.report.Results[0].Findings) != 1 || s.report.Results[0].Findings[0].Severity != model.SeverityHigh {
		t.Fatal("filter changed the findings used for exit policy")
	}
}

func TestTailWithinPreservesShortPathsAndLongPathLocations(t *testing.T) {
	short := "package-lock.json:18"
	if got := tailWithin(short, 30); got != short {
		t.Fatalf("short path changed: %q", got)
	}
	long := "packages/作品/very-long-name/package-lock.json:18"
	got := tailWithin(long, 24)
	if !strings.HasPrefix(got, "…") || !strings.HasSuffix(got, short) || ansi.StringWidth(got) > 24 {
		t.Fatalf("truncation lost the file location or exceeded its width: %q", got)
	}
}
