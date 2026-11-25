package tui

import (
	"fmt"
	"strings"
	"unicode"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Kevin-Umali/repyy/internal/output"
)

const chromeRows = 5

func (m *session) bodyWidth() int  { return max(1, min(140, m.width-4)) }
func (m *session) bodyHeight() int { return max(1, m.height-chromeRows) }
func (m *session) left() int       { return (m.width - m.bodyWidth()) / 2 }

func (m *session) View() tea.View {
	view := tea.NewView("")
	view.AltScreen = true
	view.MouseMode = tea.MouseModeCellMotion
	view.WindowTitle = m.windowTitle()
	view.ProgressBar = m.terminalProgress()
	if m.width < 40 || m.height < 14 {
		view.Content = "Terminal too small.\nResize to 40 × 14 or press Ctrl+C."
		return view
	}
	view.Content = m.render()
	return view
}

func (m *session) render() string {
	width, left := m.bodyWidth(), m.left()
	section, body, keys := m.screen()
	dialogTitle, dialog, dialogKeys := m.dialog()
	if dialog != "" {
		keys = dialogKeys
	}

	lines := []string{m.headerBar(section, width), divider.Render(strings.Repeat("─", width)), ""}
	content := strings.Split(body, "\n")
	height := m.bodyHeight()
	if len(content) > height {
		content = content[:height]
	}
	for len(content) < height {
		content = append(content, "")
	}
	lines = append(lines, content...)
	lines = append(lines, m.statusBar(width), m.help.ShortHelpView(keys))
	margin := strings.Repeat(" ", left)
	for i, line := range lines {
		lines[i] = margin + ansi.Truncate(line, width, "…")
	}

	layers := []*lipgloss.Layer{lipgloss.NewLayer(strings.Join(lines, "\n")).ID("frame")}
	if m.reviewVisible() {
		x := left
		for i, label := range m.review.tabLabels() {
			tab := lipgloss.NewLayer(label).ID(fmt.Sprintf("tab:%d", i+1)).X(x).Y(1).Z(2)
			layers = append(layers, tab)
			x += tab.Width() + 2
		}
		layers = append(layers, lipgloss.NewLayer(strings.Repeat(" ", x-left)).X(left).Y(1).Z(1))
	}
	if dialog != "" {
		box := dialogBox(dialogTitle, dialog, min(width, 68))
		layer := lipgloss.NewLayer(box).ID("dialog").Z(3)
		layers = append(layers, layer.X(max(0, (m.width-layer.Width())/2)).Y(max(1, (m.height-layer.Height())/2)))
	}
	m.hits = lipgloss.NewCompositor(layers...)
	return m.hits.Render()
}

func (m *session) reviewVisible() bool {
	switch m.phase {
	case ready, choosingFormat, enteringDestination, exporting:
		return len(m.review.report.Results) > 0
	}
	return false
}

func (m *session) headerBar(section string, width int) string {
	title := accent.Render("r╱") + "  " + strong.Render("repyy") + divider.Render("  /  ") + muted.Render(section)
	if !m.reviewVisible() {
		return title
	}
	result := m.review.report.Results[m.review.repository]
	badge := statusBadge(result.DecisionStatus())
	room := width - lipgloss.Width(title) - lipgloss.Width(badge) - 4
	if room < 8 {
		return title
	}
	target := muted.Render(tailWithin(result.Target, room))
	gap := width - lipgloss.Width(title) - lipgloss.Width(target) - lipgloss.Width(badge) - 2
	return title + strings.Repeat(" ", max(1, gap)) + target + "  " + badge
}

func (m *session) statusBar(width int) string {
	mode, message, position := m.status()
	left := modePill(mode)
	if message != "" {
		left += "  " + message
	}
	if position == "" {
		return left
	}
	position = muted.Render(position)
	gap := width - lipgloss.Width(left) - lipgloss.Width(position)
	if gap < 2 {
		return left
	}
	return left + strings.Repeat(" ", gap) + position
}

func (m *session) status() (mode, message, position string) {
	switch m.phase {
	case home, workspace, workspaceGuide:
		return "HOME", "", ""
	case enteringTarget:
		return "SCAN", "", ""
	case picking:
		return "OPEN", muted.Render(m.pickerHint()), ""
	case loading, cancelling:
		if m.openingReport {
			return "OPEN", "", m.elapsed.View()
		}
		return "SCAN", "", m.elapsed.View()
	case failed:
		return "ERROR", "", ""
	case choosingFormat, enteringDestination, exporting:
		return "EXPORT", "", ""
	}
	switch {
	case m.review.flash != "":
		message = accent.Render("✓ " + m.review.flash)
	case m.exportMessage != "":
		message = accent.Render(m.exportMessage)
	}
	if m.review.pane == findingsPane || m.review.pane == detailPane {
		if total := len(m.review.findings.VisibleItems()); total > 0 {
			position = fmt.Sprintf("%d / %d", m.review.findings.Index()+1, total)
		}
	}
	return "REVIEW", message, position
}

func (m *session) pickerHint() string {
	if m.pickerNotice != "" {
		return m.pickerNotice
	}
	return "Directories and .json reports"
}

func (m *session) windowTitle() string {
	switch m.phase {
	case loading:
		if m.openingReport {
			return "repyy · opening report"
		}
		return "repyy · scanning"
	case ready:
		if len(m.review.report.Results) > 0 {
			result := m.review.report.Results[m.review.repository]
			return "repyy · " + output.SanitizeSourceText(result.Target) + " · " + result.DecisionStatus()
		}
	}
	return "repyy"
}

// terminalProgress drives the terminal's own progress indicator (OSC 9;4: taskbar, tab or dock),
// so a long scan is visible even when the window is in the background.
func (m *session) terminalProgress() *tea.ProgressBar {
	switch m.phase {
	case loading:
		if m.openingReport || m.opts.Targets == 0 || m.task == nil {
			return &tea.ProgressBar{State: tea.ProgressBarIndeterminate}
		}
		return &tea.ProgressBar{State: tea.ProgressBarDefault, Value: int(100 * m.task.completed.Load() / int64(m.opts.Targets))}
	case cancelling:
		return &tea.ProgressBar{State: tea.ProgressBarWarning, Value: 100}
	case failed:
		return &tea.ProgressBar{State: tea.ProgressBarError, Value: 100}
	default:
		return &tea.ProgressBar{State: tea.ProgressBarNone}
	}
}

func keyGrid(groups [][]key.Binding) string {
	var bindings []key.Binding
	for _, group := range groups {
		bindings = append(bindings, group...)
	}
	cell := func(b key.Binding) string {
		return accent.Width(8).Render(b.Help().Key) + lipgloss.NewStyle().Foreground(theme.text).Width(21).Render(b.Help().Desc)
	}
	half := (len(bindings) + 1) / 2
	rows := make([]string, half)
	for i := range half {
		rows[i] = cell(bindings[i])
		if i+half < len(bindings) {
			rows[i] += "  " + cell(bindings[i+half])
		}
	}
	return strings.Join(rows, "\n")
}

func dialogBox(title, body string, width int) string {
	inner := width - 6
	content := accent.Render(title) + "\n\n" + body
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(theme.accent).
		Padding(1, 2).Width(width).
		Render(lipgloss.NewStyle().Width(inner).Render(content))
}

func (m *session) dialog() (string, string, []key.Binding) {
	back := hint("esc", "cancel")
	switch m.phase {
	case choosingFormat:
		return "Export report", m.form.View(), []key.Binding{hint("↑↓", "choose"), hint("enter", "continue"), back}
	case enteringDestination:
		body := m.form.View()
		if m.exportMessage != "" {
			body = warning.Render(m.exportMessage) + "\n\n" + body
		}
		return "Export report", body, []key.Binding{hint("enter", "save"), back}
	case exporting:
		return "Export report", m.spinner.View() + " Saving " + strings.ToUpper(m.exportFormat) + " report…", nil
	case ready:
		switch m.review.pane {
		case filtersPane:
			return "Display filters", m.review.filters.View(), []key.Binding{hint("↑↓", "choose"), hint("enter", "apply"), back}
		case helpPane:
			body := keyGrid(reviewKeys.FullHelp()) + "\n\n" +
				muted.Render("Save a scan with --format json, reopen it with repyy report FILE --format tui.")
			return "Keys", body, []key.Binding{hint("?", "close"), hint("esc", "close")}
		}
	}
	return "", "", nil
}

func (m *session) screen() (string, string, []key.Binding) {
	switch m.phase {
	case home, workspace, workspaceGuide, enteringTarget:
		return m.formScreen()
	case choosingFormat, enteringDestination, exporting:
		return m.review.screen()
	case picking:
		// File names come from the filesystem. Strip terminal sequences and
		// controls before adding the picker view to the terminal frame.
		files := strings.Split(ansi.Strip(m.picker.View()), "\n")
		for i, line := range files {
			files[i] = output.SanitizeSourceText(line)
		}
		body := strong.Render("Open a saved Repyy JSON report") + "\n" +
			muted.Render(tailWithin(output.SanitizeSourceText(m.picker.CurrentDirectory), m.bodyWidth())) + "\n\n" +
			strings.Join(files, "\n")
		keys := []key.Binding{hint("↑↓", "move"), hint("←", "parent"), hint("enter", "open"), quitKey}
		if m.opts.Home {
			keys = append([]key.Binding{hint("esc", "workspace")}, keys...)
		}
		return "Open report", body, keys
	case failed:
		message := "Unable to open report"
		if !m.openingReport {
			message = "Unable to run scan"
		}
		body := lipgloss.NewStyle().Foreground(theme.critical).Bold(true).Render("✕ "+message) + "\n\n" +
			ansi.Wrap(output.SanitizeSourceText(m.err.Error()), m.bodyWidth(), "")
		keys := []key.Binding{hint("r", "retry"), quitKey}
		if m.opts.PickReport || m.opts.PromptTarget || m.opts.Home {
			keys = append([]key.Binding{hint("esc", "back")}, keys...)
		}
		return "Error", body, keys
	case ready:
		section, body, keys := m.review.screen()
		if m.opts.Export != nil && !m.editing() {
			keys = append([]key.Binding{hint("e", "export")}, keys...)
		}
		if m.opts.Home && m.review.pane == findingsPane && !m.editing() && !m.review.findings.IsFiltered() {
			keys = append([]key.Binding{hint("esc", "workspace")}, keys...)
		}
		return section, body, keys
	default:
		return m.loadingScreen()
	}
}

func (m *session) loadingScreen() (string, string, []key.Binding) {
	section, title := "Opening report", "Loading saved report"
	if !m.openingReport {
		section, title = "Scan", "Scanning repositories"
	}
	if m.phase == cancelling {
		title = "Cancelling and cleaning up"
	}
	body := "\n" + m.spinner.View() + " " + strong.Render(title) + "\n"
	if m.loadPath != "" {
		body += muted.Render(output.SanitizeSourceText(m.loadPath)) + "\n"
	}
	body += "\n"
	if !m.openingReport {
		var complete int
		if m.task != nil {
			complete = int(m.task.completed.Load())
		}
		body += m.meter.View() + "\n\n"
		body += strong.Render(fmt.Sprintf("%d%%", 100*complete/m.opts.Targets)) +
			muted.Render(fmt.Sprintf("  ·  %d of %d repositories finished", complete, m.opts.Targets))
		if m.opts.Timeout > 0 {
			body += "\n" + muted.Render("Per-repository timeout "+m.opts.Timeout.String())
		}
		body += "\n\n" + muted.Render("Static analysis only: nothing in the target is installed or run.")
	} else {
		body += muted.Render("Reading and validating the report")
	}
	if m.phase == cancelling {
		return section, body, nil
	}
	return section, body, []key.Binding{hint("q", "cancel")}
}

func tailWithin(value string, width int) string {
	length := ansi.StringWidth(value)
	if length <= width {
		return value
	}
	if width <= 1 {
		return "…"
	}
	return ansi.TruncateLeft(value, length-width+1, "…")
}

func plainEvidence(value string) string {
	return strings.Map(func(r rune) rune {
		if r != '\n' && unicode.IsControl(r) {
			return '�'
		}
		return r
	}, value)
}

func hint(keys, label string) key.Binding {
	return key.NewBinding(key.WithKeys(keys), key.WithHelp(keys, label))
}

var quitKey = hint("q", "quit")
