package tui

import (
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var wordmark = []string{
	"█▀█ █▀▀ █▀█ █ █ █ █   /",
	"█▀▄ ██▄ █▀▀ ▀█▀ ▀█▀  / ",
}

var workspaces = []struct {
	audience experience
	key      string
	name     string
	lines    [2]string
}{
	{userExperience, "1", "User", [2]string{"Scan, review findings,", "share an HTML report"}},
	{developerExperience, "2", "Developer", [2]string{"SARIF for code scanning,", "exit codes for CI"}},
	{agentExperience, "3", "Agent", [2]string{"JSON report and a", "Markdown handoff brief"}},
}

const (
	cardGap       = 2
	homeCardsTop  = 5
	homeCardsRows = 5
)

func (m *session) showHome() {
	m.clearWorkspace()
	m.audience = ""
	m.form = nil
	m.phase = home
}

func (m *session) homeKey(k string) (tea.Cmd, bool) {
	switch k {
	case "left", "h", "shift+tab", "up", "k":
		m.homeChoice = (m.homeChoice + len(workspaces) - 1) % len(workspaces)
	case "right", "l", "tab", "down", "j":
		m.homeChoice = (m.homeChoice + 1) % len(workspaces)
	case "enter", "space":
		return m.showWorkspace(workspaces[m.homeChoice].audience), true
	default:
		return nil, false
	}
	return nil, true
}

func (m *session) cardWidth() int {
	return min(30, (m.bodyWidth()-cardGap*(len(workspaces)-1))/len(workspaces))
}

func (m *session) cardsStacked() bool { return m.cardWidth() < 24 }

func (m *session) homeView() string {
	stops := lipgloss.Blend1D(len([]rune(wordmark[0])), theme.text, theme.muted)
	var mark strings.Builder
	for _, row := range wordmark {
		for i, r := range []rune(row) {
			style := lipgloss.NewStyle().Foreground(stops[i]).Bold(true)
			if r == '/' {
				style = accent
			}
			mark.WriteString(style.Render(string(r)))
		}
		mark.WriteString("\n")
	}
	body := mark.String() + "\n" + muted.Render("Scan a repository before you run it. Choose a workspace.") + "\n\n"

	if m.cardsStacked() {
		for i, w := range workspaces {
			marker, name := "  ", strong.Render(w.name)
			if i == m.homeChoice {
				marker, name = accent.Render("› "), accent.Render(w.name)
			}
			body += marker + muted.Render(w.key) + "  " + lipgloss.NewStyle().Width(11).Render(name) + muted.Render(w.lines[0]+" "+w.lines[1]) + "\n"
		}
	} else {
		cards := make([]string, len(workspaces))
		for i, w := range workspaces {
			border, title := theme.subtle, strong.Render(w.key+"  "+w.name)
			if i == m.homeChoice {
				border, title = theme.accent, accent.Render(w.key+"  "+w.name)
			}
			cards[i] = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).
				Padding(0, 1).Width(m.cardWidth()).
				Render(title + "\n" + muted.Render(w.lines[0]) + "\n" + muted.Render(w.lines[1]))
		}
		body += lipgloss.JoinHorizontal(lipgloss.Top, cards[0], strings.Repeat(" ", cardGap), cards[1], strings.Repeat(" ", cardGap), cards[2])
	}
	return body + "\n\n" + muted.Render("Every workspace reads the target as data. Nothing in it is installed or run.")
}

func (m *session) homeKeys() []key.Binding {
	return []key.Binding{hint("1–3", "open"), hint("←→", "choose"), hint("enter", "open"), quitKey}
}

func (m *session) homeCardAt(x, y int) int {
	if m.cardsStacked() {
		if row := y - homeCardsTop; row >= 0 && row < len(workspaces) {
			return row
		}
		return -1
	}
	if y < homeCardsTop || y >= homeCardsTop+homeCardsRows {
		return -1
	}
	span := m.cardWidth() + cardGap
	if i := x / span; i < len(workspaces) && x%span < m.cardWidth() {
		return i
	}
	return -1
}

func (m *session) click(mouse tea.Mouse) tea.Cmd {
	if mouse.Button != tea.MouseLeft {
		return nil
	}
	if m.hits != nil {
		if id := m.hits.Hit(mouse.X, mouse.Y).ID(); strings.HasPrefix(id, "tab:") && m.phase == ready && !m.editing() {
			_, cmd := m.review.navigate(strings.TrimPrefix(id, "tab:"))
			return cmd
		}
	}
	x, y := mouse.X-m.left(), mouse.Y-(chromeRows-2)
	switch m.phase {
	case home:
		if i := m.homeCardAt(x, y); i >= 0 {
			if i == m.homeChoice {
				return m.showWorkspace(workspaces[i].audience)
			}
			m.homeChoice = i
		}
	case ready:
		if !m.editing() {
			return m.review.clickRow(x, y)
		}
	}
	return nil
}
