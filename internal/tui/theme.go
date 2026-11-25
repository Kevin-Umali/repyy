package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"

	"github.com/Kevin-Umali/repyy/internal/model"
)

type palette struct {
	text, muted, subtle, panel, accent, onAccent color.Color
	critical, high, medium, low, ok              color.Color
}

var theme palette

var (
	accent  lipgloss.Style
	warning lipgloss.Style
	strong  lipgloss.Style
	muted   lipgloss.Style
	divider lipgloss.Style
	bar     lipgloss.Style
)

func init() { setTheme(true) }

func setTheme(dark bool) {
	c := lipgloss.LightDark(dark)
	theme = palette{
		text:     c(lipgloss.Color("#26262b"), lipgloss.Color("#dedee5")),
		muted:    c(lipgloss.Color("#6b6b75"), lipgloss.Color("#9a9aa4")),
		subtle:   c(lipgloss.Color("#cfcfd6"), lipgloss.Color("#46464c")),
		panel:    c(lipgloss.Color("#efeff3"), lipgloss.Color("#2c2c31")),
		accent:   c(lipgloss.Color("#b0522c"), lipgloss.Color("#f1b199")),
		onAccent: c(lipgloss.Color("#ffffff"), lipgloss.Color("#1d1d20")),
		critical: c(lipgloss.Color("#c62828"), lipgloss.Color("#ff7b72")),
		high:     c(lipgloss.Color("#b0522c"), lipgloss.Color("#f1b199")),
		medium:   c(lipgloss.Color("#8a6a00"), lipgloss.Color("#e6c56b")),
		low:      c(lipgloss.Color("#2f5f8f"), lipgloss.Color("#93b7dc")),
		ok:       c(lipgloss.Color("#2e7d32"), lipgloss.Color("#8fd19e")),
	}
	accent = lipgloss.NewStyle().Foreground(theme.accent).Bold(true)
	warning = accent
	strong = lipgloss.NewStyle().Foreground(theme.text).Bold(true)
	muted = lipgloss.NewStyle().Foreground(theme.muted)
	divider = lipgloss.NewStyle().Foreground(theme.subtle)
	bar = lipgloss.NewStyle().Foreground(theme.text).Background(theme.panel)
}

func severityColor(s model.Severity) color.Color {
	switch s {
	case model.SeverityCritical:
		return theme.critical
	case model.SeverityHigh:
		return theme.high
	case model.SeverityMedium:
		return theme.medium
	default:
		return theme.low
	}
}

func severityText(s model.Severity) string {
	return lipgloss.NewStyle().Foreground(severityColor(s)).Bold(s.Rank() >= model.SeverityHigh.Rank()).Render(string(s))
}

func severityBadge(s model.Severity) string {
	return lipgloss.NewStyle().Foreground(severityColor(s)).Bold(true).Width(5).Render(map[model.Severity]string{
		model.SeverityCritical: "CRIT", model.SeverityHigh: "HIGH", model.SeverityMedium: "MED", model.SeverityLow: "LOW",
	}[s])
}

func statusBadge(status string) string {
	bg := theme.accent
	switch status {
	case "SCAN INCOMPLETE":
		bg = theme.medium
	case "NO RELEVANT FINDINGS DETECTED":
		bg = theme.ok
	case "FINDINGS DETECTED":
		bg = theme.critical
	}
	return lipgloss.NewStyle().Foreground(theme.onAccent).Background(bg).Bold(true).Padding(0, 1).Render(status)
}

func modePill(mode string) string {
	return lipgloss.NewStyle().Foreground(theme.onAccent).Background(theme.accent).Bold(true).Padding(0, 1).Render(mode)
}
