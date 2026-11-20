package tui

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	"charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Kevin-Umali/repyy/internal/model"
)

type findingItem struct {
	finding model.Finding
}

func (i findingItem) Title() string {
	return i.finding.Message
}

func (i findingItem) Description() string {
	return string(i.finding.Severity) + " " + i.finding.RuleID + " " + pathAt(i.finding.Path, i.finding.Line)
}

func (i findingItem) FilterValue() string {
	return i.Title() + " " + i.Description() + " " + i.finding.Category
}

type findingRows struct {
	titleLines int
	spacing    int
}

func (d findingRows) Height() int                         { return d.titleLines + 1 }
func (d findingRows) Spacing() int                        { return d.spacing }
func (d findingRows) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (d findingRows) Render(w io.Writer, m list.Model, index int, item list.Item) {
	f := item.(findingItem).finding
	width := max(1, m.Width()-3)
	marker := "  "
	titleStyle := lipgloss.NewStyle()
	if index == m.Index() {
		marker = accent.Render("› ")
		titleStyle = strong
	}
	title := strings.Split(ansi.Wrap(f.Message, width, ""), "\n")
	lines := make([]string, 0, d.Height())
	for i, line := range title[:min(len(title), d.titleLines)] {
		prefix := "  "
		if i == 0 {
			prefix = marker
		}
		if i == d.titleLines-1 && len(title) > d.titleLines {
			line = ansi.Truncate(line, max(1, width-1), "") + "…"
		}
		lines = append(lines, prefix+titleStyle.Render(ansi.Truncate(line, width, "…")))
	}
	severity := severityText(f.Severity)
	path := tailWithin(pathAt(f.Path, f.Line), max(1, width-lipgloss.Width(severity)-3))
	lines = append(lines, "  "+severity+muted.Render(" · "+path))
	for len(lines) < d.Height() {
		lines = append(lines, "")
	}
	fmt.Fprint(w, strings.Join(lines, "\n"))
}

func severityText(severity model.Severity) string {
	label := string(severity)
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return accent.Render(label)
	default:
		return strong.Render(label)
	}
}

func (r *review) findingsHeaderHeight() int {
	if r.notice == "" {
		return 5
	}
	return 6
}

func (r *review) selectedFinding() (model.Finding, bool) {
	item, ok := r.findings.SelectedItem().(findingItem)
	return item.finding, ok
}

func (r *review) findingsScreen() (string, string, []key.Binding) {
	keys := []key.Binding{hint("enter", "detail"), hint("/", "search"), hint("↑↓", "move"), hint("f", "filter"), hint("?", "guide"), quitKey}
	if len(r.report.Results) == 0 {
		return "Terminal review", "This report contains no repositories.", []key.Binding{quitKey}
	}
	result := r.report.Results[r.repository]
	header := "\n" + muted.Render("Target  ") + strong.Render(result.Target) + "\n"
	state, coverage := strong, "Complete coverage"
	switch result.DecisionStatus() {
	case "SCAN INCOMPLETE":
		state, coverage = accent, "Partial coverage"
	case "REVIEW REQUIRED", "FINDINGS DETECTED":
		state = accent
	}
	header += state.Render(result.DecisionStatus()) + "\n"
	summary := fmt.Sprintf("%d findings · %d files · %s", len(result.Findings), result.Coverage.FilesScanned, coverage)
	if r.width < 48 {
		summary = fmt.Sprintf("%d findings · %d files", len(result.Findings), result.Coverage.FilesScanned)
	}
	header += muted.Render(summary) + "\n"
	var banner string
	if r.fixes > 0 {
		label := "findings with a suggested fix"
		if r.fixes == 1 {
			label = "finding with a suggested fix"
		}
		banner = fmt.Sprintf("%d %s", r.fixes, label)
	}
	if r.reminder != nil {
		if r.reminder.Timedout() {
			banner = "Review reminder  ·  Time to revisit your next action  ·  t dismiss"
		} else {
			banner = "Review reminder  ·  " + r.reminder.View() + " remaining  ·  t cancel"
		}
	}
	if r.notice != "" {
		header += warning.Render(ansi.Truncate(r.notice, r.width, "…")) + "\n"
	}
	header += muted.Render(banner) + "\n"
	if r.findings.SettingFilter() {
		keys = []key.Binding{hint("enter", "apply"), hint("esc", "clear"), hint("ctrl+c", "quit")}
	}
	if len(r.findings.Items()) == 0 {
		switch {
		case len(result.Findings) != 0:
			label := fmt.Sprintf("%d findings hidden by display options.", len(result.Findings))
			if len(result.Findings) == 1 {
				label = "1 finding hidden by display options."
			}
			body := ansi.Wrap(label+" Use --detail all or lower the display thresholds.", r.width, "")
			return "Terminal review", header + body, []key.Binding{hint("f", "filter"), hint("?", "guide"), quitKey}
		case !result.Coverage.Complete:
			return "Terminal review", header + ansi.Wrap("No findings in the scanned areas. Press c for coverage.", r.width, ""), []key.Binding{hint("f", "filter"), hint("?", "guide"), quitKey}
		default:
			return "Terminal review", header + ansi.Wrap("No relevant findings detected. Press c for coverage.", r.width, ""), []key.Binding{hint("f", "filter"), hint("?", "guide"), quitKey}
		}
	}
	if r.findings.SettingFilter() && r.findings.FilterValue() != "" && len(r.findings.VisibleItems()) == 0 {
		return "Terminal review", header + r.findings.FilterInput.View() + "\n\n" + muted.Render("No findings match this search."), keys[1:]
	}
	return "Terminal review", header + r.queue(), keys
}

func pathAt(path string, line int) string {
	if line > 0 {
		return path + ":" + strconv.Itoa(line)
	}
	return path
}

func (r *review) queueWidth() int {
	if r.width < 96 || r.height < 17 {
		return r.width
	}
	return r.width * 57 / 100
}

func (r *review) queue() string {
	queue := r.findings.View()
	if r.queueWidth() == r.width {
		return queue
	}
	finding, ok := r.selectedFinding()
	if !ok {
		return queue
	}

	width := r.width - r.queueWidth() - 4
	summary := strong.Render("Selected finding") + "\n" +
		severityText(finding.Severity) + muted.Render(" severity") + "\n" +
		ansi.Wrap(finding.Message, width, "") + "\n" +
		muted.Render(ansi.Wrap(pathAt(finding.Path, finding.Line), width, ""))
	if finding.Remediation != "" {
		summary += "\n\n" + muted.Render("Recommended action") + "\n" + ansi.Wrap(finding.Remediation, width, "")
	}
	height := max(1, r.height-r.findingsHeaderHeight())
	lines := strings.Split(summary, "\n")
	if len(lines) > height {
		lines = lines[:height]
		lines[len(lines)-1] = ansi.Truncate(lines[len(lines)-1], width-1, "") + "…"
		summary = strings.Join(lines, "\n")
	}
	left := lipgloss.NewStyle().Width(r.queueWidth()).Render(queue)
	right := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.Color("#66666d")).PaddingLeft(2).
		Render(summary)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
}

func (r *review) openFilters() tea.Cmd {
	option := func(label string, value model.Severity) huh.Option[string] {
		return huh.NewOption(label, string(value)).Selected(value == r.minSeverity)
	}
	field := huh.NewSelect[string]().Key("severity").Title("Minimum severity").
		Description("Change the review queue. Scan verdicts still use all findings.").
		Options(option("Low and above", model.SeverityLow),
			option("Medium and above", model.SeverityMedium),
			option("High and critical", model.SeverityHigh),
			option("Critical only", model.SeverityCritical))
	r.filters = huh.NewForm(huh.NewGroup(field)).
		WithTheme(huh.ThemeFunc(formTheme)).
		WithWidth(min(r.width, 54)).
		WithShowHelp(false)
	r.pane = filtersPane
	return r.filters.Init()
}

func (r *review) updateFilters(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "esc" {
		r.filters = nil
		r.pane = findingsPane
		return nil
	}
	_, cmd := r.filters.Update(msg)
	switch r.filters.State {
	case huh.StateCompleted:
		r.minSeverity = model.Severity(r.filters.GetString("severity"))
		r.filters = nil
		r.selectRepo(r.repository)
		return nil
	case huh.StateAborted:
		r.filters = nil
		r.pane = findingsPane
		return nil
	}
	return cmd
}
