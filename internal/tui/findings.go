package tui

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
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

var badgeWidth = lipgloss.Width("▍ " + severityBadge(model.SeverityCritical))

func (d findingRows) Height() int                         { return d.titleLines + 1 }
func (d findingRows) Spacing() int                        { return d.spacing }
func (d findingRows) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (d findingRows) Render(w io.Writer, m list.Model, index int, item list.Item) {
	f := item.(findingItem).finding
	width := max(1, m.Width()-badgeWidth)
	marker := "  "
	titleStyle := lipgloss.NewStyle().Foreground(theme.text)
	if index == m.Index() {
		marker = accent.Render("▍ ")
		titleStyle = strong
	}
	title := strings.Split(ansi.Wrap(f.Message, width, ""), "\n")
	lines := make([]string, 0, d.Height())
	for i, line := range title[:min(len(title), d.titleLines)] {
		prefix := strings.Repeat(" ", badgeWidth)
		if i == 0 {
			prefix = marker + severityBadge(f.Severity)
		}
		if i == d.titleLines-1 && len(title) > d.titleLines {
			line = ansi.Truncate(line, max(1, width-1), "") + "…"
		}
		lines = append(lines, prefix+titleStyle.Render(ansi.Truncate(line, width, "…")))
	}
	rule := " · " + f.RuleID
	path := tailWithin(pathAt(f.Path, f.Line), max(1, width-lipgloss.Width(rule)))
	lines = append(lines, strings.Repeat(" ", badgeWidth)+muted.Render(path)+divider.Render(rule))
	for len(lines) < d.Height() {
		lines = append(lines, "")
	}
	fmt.Fprint(w, strings.Join(lines, "\n"))
}

func severityCounts(findings []model.Finding) string {
	if len(findings) == 0 {
		return muted.Render("0 findings")
	}
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range severities {
		if counts[s] > 0 {
			parts = append(parts, severityText(s)+muted.Render(fmt.Sprintf(" %d", counts[s])))
		}
	}
	return strings.Join(parts, muted.Render(" · "))
}

var severities = []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow}

const sidebarWidth = 34

func (r *review) wide() bool { return r.width >= 88 && r.height >= 14 }

func (r *review) queueWidth() int {
	if r.wide() {
		return r.width - sidebarWidth - 3
	}
	return r.width
}

func (r *review) findingsHeaderHeight() int {
	rows := 1
	if r.notice != "" {
		rows++
	}
	if !r.wide() {
		rows++
	}
	return rows + 1
}

func (r *review) selectedFinding() (model.Finding, bool) {
	item, ok := r.findings.SelectedItem().(findingItem)
	return item.finding, ok
}

func (r *review) findingsScreen() (string, string, []key.Binding) {
	keys := []key.Binding{hint("enter", "detail"), hint("/", "search"), hint("↑↓", "move"), hint("f", "filter"), hint("h", "handoff"), hint("?", "keys"), quitKey}
	if len(r.report.Results) == 0 {
		return "Review", "This report contains no repositories.", []key.Binding{quitKey}
	}
	result := r.report.Results[r.repository]
	var header string
	if !r.wide() {
		header += severityCounts(result.Findings) + "\n"
	}
	if r.notice != "" {
		header += warning.Render(ansi.Truncate(r.notice, r.queueWidth(), "…")) + "\n"
	}
	banner := r.banner()
	if hidden := len(result.Findings) - len(r.findings.Items()); hidden > 0 && len(r.findings.Items()) > 0 {
		note := muted.Render(fmt.Sprintf("%d hidden · f to show", hidden))
		if banner == "" {
			banner = note
		} else {
			banner += muted.Render("  ·  ") + note
		}
	}
	header += ansi.Truncate(banner, r.queueWidth(), "…") + "\n"
	if r.findings.SettingFilter() {
		keys = []key.Binding{hint("enter", "apply"), hint("esc", "clear"), hint("ctrl+c", "quit")}
	}

	var main string
	switch {
	case len(r.findings.Items()) == 0:
		keys = []key.Binding{hint("f", "filter"), hint("?", "keys"), quitKey}
		switch {
		case len(result.Findings) != 0:
			label := fmt.Sprintf("%d findings hidden by display options.", len(result.Findings))
			if len(result.Findings) == 1 {
				label = "1 finding hidden by display options."
			}
			main = ansi.Wrap(label+" Press f to lower the minimum severity, or use --detail all.", r.queueWidth(), "")
		case !result.Coverage.Complete:
			main = ansi.Wrap("No findings in the scanned areas. Press 3 for what was not scanned.", r.queueWidth(), "")
		default:
			main = ansi.Wrap("No relevant findings detected. Press 3 to check coverage.", r.queueWidth(), "")
		}
	case r.findings.SettingFilter() && r.findings.FilterValue() != "" && len(r.findings.VisibleItems()) == 0:
		main = r.findings.FilterInput.View() + "\n\n" + muted.Render("No findings match this search.")
		keys = keys[1:]
	default:
		main = r.findings.View()
	}
	main = header + main
	if !r.wide() {
		return "Review", main, keys
	}
	left := lipgloss.NewStyle().Width(r.queueWidth()).Render(main)
	side := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(theme.subtle).PaddingLeft(2).Width(sidebarWidth + 2).
		Render(r.sidebar(result))
	return "Review", lipgloss.JoinHorizontal(lipgloss.Top, left, " ", side), keys
}

func (r *review) banner() string {
	switch {
	case r.reminder != nil && r.reminder.Timedout():
		return accent.Render("Reminder · time to decide the next action · t dismiss")
	case r.reminder != nil:
		return muted.Render("Reminder · " + r.reminder.View() + " left · t cancel")
	case r.fixes == 1:
		return muted.Render("1 finding with a suggested fix")
	case r.fixes > 1:
		return muted.Render(fmt.Sprintf("%d findings with a suggested fix", r.fixes))
	}
	return ""
}

func label(text string) string { return divider.Render(strings.ToUpper(text)) }

func (r *review) sidebar(result model.RepoResult) string {
	width := sidebarWidth - 2
	lines := []string{
		label("report"),
		strong.Render(tailWithin(result.Target, width)),
		statusBadge(result.DecisionStatus()),
		severityCounts(result.Findings),
		"",
		label("severity"),
	}
	total := max(1, len(result.Findings))
	counts := map[model.Severity]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}
	for _, s := range severities {
		n := counts[s]
		fill := 0
		if n > 0 {
			fill = max(1, n*14/total)
		}
		meter := lipgloss.NewStyle().Foreground(severityColor(s)).Render(strings.Repeat("█", fill)) + divider.Render(strings.Repeat("░", 14-fill))
		lines = append(lines, lipgloss.NewStyle().Width(9).Render(severityText(s))+meter+muted.Render(fmt.Sprintf(" %d", n)))
	}
	coverage := lipgloss.NewStyle().Foreground(theme.ok).Render("● complete")
	if !result.Coverage.Complete {
		coverage = lipgloss.NewStyle().Foreground(theme.medium).Render("◐ partial")
	}
	var facts []string
	if result.Duration > 0 {
		facts = append(facts, result.Duration.Round(time.Millisecond).String())
	}
	if result.ScanMode != "" {
		facts = append(facts, string(result.ScanMode)+" scan")
	}
	scan := strings.Join(facts, " · ")
	lines = append(lines, "", label("coverage"), coverage+muted.Render(fmt.Sprintf(" · %d files", result.Coverage.FilesScanned)), muted.Render(scan))
	if skipped := len(result.Coverage.Skipped); skipped > 0 {
		lines = append(lines, muted.Render(fmt.Sprintf("%d skipped areas · press 3", skipped)))
	}

	if f, ok := r.selectedFinding(); ok {
		lines = append(lines, "", label("selected"), severityText(f.Severity)+divider.Render(" · ")+muted.Render(f.RuleID))
		lines = append(lines, strings.Split(ansi.Wrap(f.Message, width, ""), "\n")...)
		lines = append(lines, muted.Render(tailWithin(pathAt(f.Path, f.Line), width)))
		if f.Remediation != "" {
			lines = append(lines, "", label("next step"))
			lines = append(lines, strings.Split(ansi.Wrap(f.Remediation, width, ""), "\n")...)
		}
	}
	height := max(1, r.height)
	if len(lines) > height {
		lines = lines[:height]
	}
	return strings.Join(lines, "\n")
}

func (r *review) rowDelegate() findingRows {
	rows := findingRows{titleLines: 1}
	if r.height >= 18 {
		rows.spacing = 1
		if r.queueWidth() < 68 {
			rows.titleLines = 2
		}
	}
	return rows
}

func (r *review) clickRow(x, y int) tea.Cmd {
	if r.pane != findingsPane || x >= r.queueWidth() || len(r.findings.VisibleItems()) == 0 {
		return nil
	}
	rows := r.rowDelegate()
	top := r.findingsHeaderHeight()
	if y < top {
		return nil
	}
	offset := (y - top) / (rows.Height() + rows.Spacing())
	index := r.findings.Paginator.Page*r.findings.Paginator.PerPage + offset
	if index >= len(r.findings.VisibleItems()) {
		return nil
	}
	if index == r.findings.Index() {
		if f, ok := r.selectedFinding(); ok {
			r.showDetail(f)
		}
		return nil
	}
	r.findings.Select(index)
	return nil
}

func (r *review) wheel(msg tea.MouseWheelMsg) tea.Cmd {
	down := msg.Mouse().Button == tea.MouseWheelDown
	switch r.pane {
	case findingsPane:
		if down {
			r.findings.CursorDown()
		} else {
			r.findings.CursorUp()
		}
	case repositoriesPane:
		if down {
			r.repos.MoveDown(1)
		} else {
			r.repos.MoveUp(1)
		}
	case detailPane, coveragePane, handoffPane:
		var cmd tea.Cmd
		r.detail, cmd = r.detail.Update(msg)
		return cmd
	}
	return nil
}

func pathAt(path string, line int) string {
	if line > 0 {
		return path + ":" + strconv.Itoa(line)
	}
	return path
}

func (r *review) openFilters() tea.Cmd {
	option := func(label string, value model.Severity) huh.Option[string] {
		return huh.NewOption(label, string(value)).Selected(value == r.minSeverity)
	}
	field := huh.NewSelect[string]().Key("severity").Title("Minimum severity").
		Description("Changes the list only. The verdict and exit code use every finding.").
		Options(option("Low and above", model.SeverityLow),
			option("Medium and above", model.SeverityMedium),
			option("High and critical", model.SeverityHigh),
			option("Critical only", model.SeverityCritical))
	r.filters = huh.NewForm(huh.NewGroup(field)).
		WithTheme(huh.ThemeFunc(formTheme)).
		WithWidth(56).
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
