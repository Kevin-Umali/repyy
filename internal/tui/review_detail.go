package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/tree"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func (r *review) openReader(view pane, body string) {
	r.pane = view
	r.readerText = body
	r.detail.SetContent(ansi.Wrap(body, r.detail.Width(), ""))
	r.detail.GotoTop()
}

func (r *review) showDetail(f model.Finding) {
	section := func(title string) string { return "\n" + label(title) + "\n" }
	body := severityBadge(f.Severity) + muted.Render(string(f.Confidence)+" confidence · "+f.RuleID) + "\n\n" +
		strong.Render(f.Message) + "\n" +
		accent.Render(pathAt(f.Path, f.Line)) + "\n"
	if f.Remediation != "" {
		body += section("recommended action") + f.Remediation + "\n"
	}
	if f.Evidence != "" {
		gutter := lipgloss.NewStyle().Border(lipgloss.ThickBorder(), false, false, false, true).
			BorderForeground(severityColor(f.Severity)).PaddingLeft(1).Foreground(theme.text)
		body += section("evidence") + gutter.Render(plainEvidence(f.Evidence)) + "\n"
	}
	detection := f.RuleID + " · " + strings.ReplaceAll(f.Category, "-", " ")
	if f.Disposition != "" {
		detection += " · " + string(f.Disposition)
	}
	body += section("detection") + detection
	if f.Occurrences > 1 {
		body += muted.Render(fmt.Sprintf("\n%d occurrences · l to browse them", f.Occurrences))
	}
	if f.LocationsOmitted > 0 {
		body += muted.Render(fmt.Sprintf("\n%d additional locations omitted", f.LocationsOmitted))
	}
	if len(f.ContributingRuleIDs) > 0 {
		body += muted.Render("\nRelated rules  " + strings.Join(f.ContributingRuleIDs, ", "))
	}
	r.openReader(detailPane, body)
}

func (r *review) showLocations(f model.Finding) {
	root := tree.Root(f.RuleID)
	files := make(map[string]*tree.Node)
	locations := f.Locations
	if len(locations) == 0 {
		locations = []model.Location{{Path: f.Path, StartLine: f.Line, Evidence: f.Evidence}}
	}
	for _, location := range locations {
		file := files[location.Path]
		if file == nil {
			file = tree.Root(location.Path)
			files[location.Path] = file
			root.Child(file)
		}
		label := "File match"
		if location.StartLine > 0 {
			label = fmt.Sprintf("Line %d", location.StartLine)
			if location.EndLine > location.StartLine {
				label += fmt.Sprintf("–%d", location.EndLine)
			}
		}
		if location.Evidence != "" {
			label += "  " + strings.Join(strings.Fields(plainEvidence(location.Evidence)), " ")
		}
		file.Child(label)
	}
	r.locations = tree.New(root, r.width, max(1, r.height-2))
	r.locations.SetShowHelp(false)
	r.pane = locationsPane
}

func (r *review) showCoverage() {
	result := r.report.Results[r.repository]
	section := func(title string) string { return "\n\n" + label(title) + "\n" }
	body := strong.Render(result.Target) + "\n" + statusBadge(result.DecisionStatus()) + "\n"
	state := lipgloss.NewStyle().Foreground(theme.ok).Render("● complete coverage")
	if !result.Coverage.Complete {
		state = lipgloss.NewStyle().Foreground(theme.medium).Render("◐ partial coverage")
	}
	body += "\n" + state + muted.Render(fmt.Sprintf(" · %d files · %s · %s", result.Coverage.FilesScanned, humanBytes(result.Coverage.BytesScanned), result.Duration.Round(time.Millisecond)))
	if result.ScanMode != "" {
		body += muted.Render(" · " + string(result.ScanMode) + " scan")
	}
	if result.Error != "" {
		body += section("scan error") + lipgloss.NewStyle().Foreground(theme.critical).Render(result.Error)
	}
	for _, items := range []struct {
		title  string
		values []string
	}{{"skipped areas", result.Coverage.Skipped}, {"warnings", result.Coverage.Warnings}} {
		if len(items.values) != 0 {
			body += section(items.title) + "• " + strings.Join(items.values, "\n• ")
		}
	}
	if result.Resolved != "" {
		body += section("retained checkout") + result.Resolved
	}
	if r.notice != "" {
		body += section("intelligence notice") + r.notice
	}
	body += "\n\n" + muted.Render(r.report.Limitation)
	r.openReader(coveragePane, body)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value, suffix := float64(n)/unit, "KB"
	for _, next := range []string{"MB", "GB"} {
		if value < unit {
			break
		}
		value, suffix = value/unit, next
	}
	return fmt.Sprintf("%.1f %s", value, suffix)
}
