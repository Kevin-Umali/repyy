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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func reviewSession(t *testing.T, findings ...model.Finding) *session {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := newSession(ctx, Options{Presentation: output.DefaultOptions()}, nil)
	s.resize(100, 30)
	report := model.Report{ToolVersion: "v0.7.3", RulesVersion: "r1", Results: []model.RepoResult{
		{Target: "demo", Verdict: model.VerdictReview, Coverage: model.Coverage{Complete: true, FilesScanned: 3}, Findings: findings},
	}}
	s.Update(loadResult{report: report})
	return s
}

func press(s *session, keys ...string) tea.Cmd {
	var cmd tea.Cmd
	for _, k := range keys {
		msg := tea.KeyPressMsg{Text: k}
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		default:
			msg.Code = []rune(k)[0]
		}
		_, cmd = s.Update(msg)
	}
	return cmd
}

func finding(rule string, severity model.Severity, path string, line int) model.Finding {
	return model.Finding{RuleID: rule, Category: "test", Severity: severity, Confidence: model.ConfidenceHigh,
		Message: "Message for " + rule, Path: path, Line: line}
}

func TestFindingsHeaderCountsSeverities(t *testing.T) {
	t.Parallel()
	s := reviewSession(t, finding("A", model.SeverityHigh, "a.js", 1), finding("B", model.SeverityHigh, "b.js", 2), finding("C", model.SeverityMedium, "c.js", 3))
	if got := ansi.Strip(s.View().Content); !strings.Contains(got, "high 2 · medium 1") {
		t.Fatalf("severity counts missing: %q", got)
	}
}

func TestDetailStepsThroughFindingsInPlace(t *testing.T) {
	t.Parallel()
	s := reviewSession(t, finding("A", model.SeverityHigh, "a.js", 1), finding("B", model.SeverityMedium, "b.js", 2))
	press(s, "enter")
	if got := ansi.Strip(s.View().Content); !strings.Contains(got, "Finding 1 of 2") || !strings.Contains(got, "Message for A") {
		t.Fatalf("detail did not open on the first finding: %q", got)
	}
	press(s, "]")
	if got := ansi.Strip(s.View().Content); !strings.Contains(got, "Finding 2 of 2") || !strings.Contains(got, "Message for B") {
		t.Fatalf("] did not move to the next finding: %q", got)
	}
	press(s, "]")
	if got := ansi.Strip(s.View().Content); !strings.Contains(got, "Finding 2 of 2") {
		t.Fatalf("] moved past the last finding: %q", got)
	}
	press(s, "[")
	if got := ansi.Strip(s.View().Content); !strings.Contains(got, "Finding 1 of 2") {
		t.Fatalf("[ did not move back: %q", got)
	}
}

func TestCopyLocationConfirmsUntilNextKey(t *testing.T) {
	t.Parallel()
	s := reviewSession(t, finding("A", model.SeverityHigh, "src/a.js", 12))
	if cmd := press(s, "y"); cmd == nil {
		t.Fatal("y did not return a clipboard command")
	}
	if got := ansi.Strip(s.View().Content); !strings.Contains(got, "Copied src/a.js:12") {
		t.Fatalf("copy confirmation missing: %q", got)
	}
	press(s, "j")
	if got := ansi.Strip(s.View().Content); strings.Contains(got, "Copied") {
		t.Fatalf("copy confirmation outlived the next key: %q", got)
	}
}

func TestHandoffListsFindingsHiddenByDisplayFilters(t *testing.T) {
	t.Parallel()
	s := reviewSession(t, finding("A", model.SeverityHigh, "a.js", 1), finding("LOW-1", model.SeverityLow, "low.js", 9))
	s.review.minSeverity = model.SeverityHigh
	s.review.selectRepo(0)
	press(s, "h")
	brief := s.review.readerText
	for _, want := range []string{"# Repyy handoff: demo", "`LOW-1`", "`low.js:9`", "Findings (2)", "untrusted data", "v0.7.3"} {
		if !strings.Contains(brief, want) {
			t.Fatalf("handoff brief is missing %q:\n%s", want, brief)
		}
	}
	if got := ansi.Strip(s.View().Content); !strings.Contains(got, "Handoff brief") {
		t.Fatalf("handoff pane did not open: %q", got)
	}
	press(s, "esc")
	if s.review.pane != findingsPane {
		t.Fatal("esc from a handoff opened in the queue should return to the queue")
	}
}

func TestKeyHelpCoversEveryReviewKey(t *testing.T) {
	t.Parallel()
	s := reviewSession(t, finding("A", model.SeverityHigh, "a.js", 1))
	press(s, "?")
	view := ansi.Strip(s.View().Content)
	guide := ansi.Strip(renderGuide(100))
	for _, column := range reviewKeys.FullHelp() {
		for _, binding := range column {
			if !strings.Contains(view, binding.Help().Desc) || !strings.Contains(guide, binding.Help().Desc) {
				t.Fatalf("key help is missing %q:\n%s", binding.Help().Desc, view)
			}
		}
	}
	press(s, "?")
	if s.review.pane != findingsPane {
		t.Fatal("? did not close the key dialog")
	}
}

func TestClickSelectsThenOpensFindingRow(t *testing.T) {
	t.Parallel()
	s := reviewSession(t, finding("A", model.SeverityHigh, "a.js", 1), finding("B", model.SeverityMedium, "b.js", 2))
	s.resize(120, 32)
	s.View()
	rows := s.review.rowDelegate()
	row := func(i int) tea.MouseClickMsg {
		return tea.MouseClickMsg{X: s.left() + 10, Y: chromeRows - 2 + s.review.findingsHeaderHeight() + i*(rows.Height()+rows.Spacing()), Button: tea.MouseLeft}
	}
	s.Update(row(1))
	if s.review.findings.Index() != 1 || s.review.pane != findingsPane {
		t.Fatalf("click did not select the second row: index %d", s.review.findings.Index())
	}
	s.Update(row(1))
	if s.review.pane != detailPane {
		t.Fatal("clicking the selected row did not open it")
	}
}

func TestClickTabSwitchesPane(t *testing.T) {
	t.Parallel()
	s := reviewSession(t, finding("A", model.SeverityHigh, "a.js", 1))
	s.resize(120, 32)
	view := ansi.Strip(s.View().Content)
	line := strings.Split(view, "\n")[1]
	x := ansi.StringWidth(line[:strings.Index(line, "3 Coverage")])
	s.Update(tea.MouseClickMsg{X: x + 1, Y: 1, Button: tea.MouseLeft})
	if s.review.pane != coveragePane {
		t.Fatal("clicking the Coverage tab did not open coverage")
	}
}

func TestHomeCardsOpenWorkspaces(t *testing.T) {
	t.Parallel()
	s := newSession(context.Background(), Options{Home: true}, nil)
	s.resize(120, 32)
	press(s, "l")
	if s.homeChoice != 1 {
		t.Fatalf("→ did not move to the developer card: %d", s.homeChoice)
	}
	press(s, "enter")
	if s.phase != workspace || s.audience != developerExperience {
		t.Fatalf("enter did not open the developer workspace: %v %q", s.phase, s.audience)
	}
}
