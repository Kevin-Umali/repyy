package tui

import (
	"fmt"
	"strings"
	"unicode"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Kevin-Umali/repyy/internal/output"
)

var (
	surface = lipgloss.NewStyle().Foreground(lipgloss.Color("#dedee5")).Background(lipgloss.Color("#242426"))
	bar     = surface.Background(lipgloss.Color("#36363a"))
	accent  = lipgloss.NewStyle().Foreground(lipgloss.Color("#f1b199")).Bold(true)
	warning = accent
	strong  = lipgloss.NewStyle().Bold(true)
	muted   = lipgloss.NewStyle().Foreground(lipgloss.Color("#b3b3bc"))
	divider = lipgloss.NewStyle().Foreground(lipgloss.Color("#66666d"))
)

func (m *session) View() tea.View {
	content := "Terminal too small.\nResize to 36 × 16 or press Ctrl+C."
	if m.width >= 36 && m.height >= 16 {
		width := m.bodyWidth()
		section, body, keys := m.screen()
		margin := strings.Repeat(" ", (m.width-width)/2)
		top := lipgloss.NewStyle().Width(width).Render(accent.Render("r╱") + "  " + strong.Render("repyy") +
			divider.Render("  /  ") + muted.Render(section))
		rule := divider.Render(strings.Repeat("─", width))
		navigation := rule
		if m.phase == ready && len(m.review.report.Results) > 0 {
			navigation = m.review.tabs()
		}

		lines := strings.Split(body, "\n")
		height := m.bodyHeight()
		if len(lines) > height {
			lines = lines[:height]
		}
		for len(lines) < height {
			lines = append(lines, "")
		}
		row := func(line string) string {
			return surface.Width(m.width).Render(margin + ansi.Truncate(line, width, "…"))
		}
		frame := []string{row(""), row(top), row(navigation)}
		for _, line := range lines {
			frame = append(frame, row(line))
		}
		if m.phase == ready && m.exportMessage != "" {
			rule = accent.Render(m.exportMessage)
		}
		frame = append(frame, row(rule), row(m.help.ShortHelpView(keys)))
		content = strings.Join(frame, "\n")
	}
	view := tea.NewView(content)
	view.AltScreen = true
	return view
}

func (m *session) screen() (string, string, []key.Binding) {
	switch m.phase {
	case home, workspace, workspaceGuide, enteringTarget, choosingFormat, enteringDestination, exporting:
		return m.formScreen()
	case picking:
		// File names come from the filesystem. Strip terminal sequences and
		// controls before adding the picker view to the terminal frame.
		files := strings.Split(ansi.Strip(m.picker.View()), "\n")
		for i, line := range files {
			files[i] = output.SanitizeSourceText(line)
		}
		body := "Open a saved Repyy JSON report\n" + muted.Render(tailWithin(output.SanitizeSourceText(m.picker.CurrentDirectory), m.bodyWidth())) + "\n"
		notice := m.pickerNotice
		if notice == "" {
			notice = "Directories and .json reports"
		}
		body += warning.Render(notice) + "\n" + strings.Join(files, "\n")
		keys := []key.Binding{hint("↑↓", "move"), hint("←", "parent"), hint("enter", "open"), quitKey}
		if m.opts.Home {
			keys = append([]key.Binding{hint("esc", "workspace")}, keys...)
		}
		return "REPORT PICKER", body, keys
	case failed:
		message := "Unable to open report"
		if !m.openingReport {
			message = "Unable to run scan"
		}
		body := warning.Render(message) + "\n\n" + ansi.Wrap(output.SanitizeSourceText(m.err.Error()), m.bodyWidth(), "")
		keys := []key.Binding{hint("r", "retry"), quitKey}
		if m.opts.PickReport || m.opts.PromptTarget || m.opts.Home {
			keys = append([]key.Binding{hint("esc", "back")}, keys...)
		}
		return "ERROR", body, keys
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
		section := "REPORT LOADING"
		title := "Loading saved report"
		if !m.openingReport {
			section, title = "SCAN PROGRESS", "Scanning repositories"
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
			body += m.meter.View() + "\n"
			body += fmt.Sprintf("%d%%  ·  %d of %d repositories finished  ·  %s elapsed", 100*complete/m.opts.Targets, complete, m.opts.Targets, m.elapsed.View())
			if m.opts.Timeout > 0 {
				body += "\n" + muted.Render("Per-repository timeout "+m.opts.Timeout.String())
			}
		} else {
			body += muted.Render("Reading and validating the report")
		}
		if m.phase == cancelling {
			return section, body, nil
		}
		return section, body, []key.Binding{hint("q", "cancel")}
	}
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
