package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
)

const choiceKey = "choice"

type exportResult struct {
	path string
	err  error
}

func (m *session) formWidth() int { return min(m.bodyWidth(), 58) }

func (m *session) setForm(next phase, field huh.Field) {
	m.phase = next
	m.form = huh.NewForm(huh.NewGroup(field)).
		WithWidth(m.formWidth()).
		WithShowHelp(false).
		WithTheme(huh.ThemeFunc(formTheme))
}

func formTheme(dark bool) *huh.Styles {
	styles := huh.ThemeBase(dark)
	field := styles.Focused
	field.Base = lipgloss.NewStyle()
	field.Card = field.Base
	field.Title = strong
	field.Description = muted
	field.SelectSelector = accent.SetString("› ")
	field.SelectedOption = accent
	field.UnselectedOption = lipgloss.NewStyle()
	field.ErrorIndicator = warning.SetString(" !")
	field.ErrorMessage = warning
	field.TextInput.Prompt = accent
	field.TextInput.Text = lipgloss.NewStyle()
	field.TextInput.Placeholder = muted
	field.TextInput.Cursor = accent
	styles.Focused = field
	styles.Blurred = field
	return styles
}

type experience string

const (
	userExperience      experience = "User Experience"
	developerExperience experience = "Developer Experience"
	agentExperience     experience = "Agent Experience"
)

func (m *session) clearWorkspace() {
	m.report = model.Report{}
	m.review = review{}
	m.task, m.err = nil, nil
	m.exportMessage = ""
	m.loadPath = ""
}

func (m *session) showHome() {
	m.clearWorkspace()
	m.audience = ""
	m.setForm(home, huh.NewSelect[string]().Key(choiceKey).Title("Choose your workspace").
		Options(
			huh.NewOption("1  ◉  User Experience", string(userExperience)),
			huh.NewOption("2  ⌘  Developer Experience", string(developerExperience)),
			huh.NewOption("3  ◇  Agent Experience", string(agentExperience)),
		))
}

func (m *session) showWorkspace(audience experience) tea.Cmd {
	m.clearWorkspace()
	m.audience = audience
	m.openingReport = false
	description := "Inspect and share HTML reports."
	options := []huh.Option[string]{
		huh.NewOption("Scan a repository", "scan"),
		huh.NewOption("Open a saved report", "report"),
	}
	switch audience {
	case developerExperience:
		description = "Export SARIF or set up CI."
		options = append(options, huh.NewOption("Open CI recipes", "guide"), huh.NewOption("Scan current directory", "cwd"))
	case agentExperience:
		description = "Prepare a local JSON handoff."
		options = append(options, huh.NewOption("Open agent handoff guide", "guide"))
	}
	m.setForm(workspace, huh.NewSelect[string]().Key(choiceKey).Title(string(audience)).
		Description(description).Options(options...))
	return m.form.Init()
}

func (m *session) showWorkflowGuide() {
	m.phase = workspaceGuide
	m.workflowGuide = viewport.New()
	m.resizeWorkflowGuide()
}

func (m *session) resizeWorkflowGuide() {
	m.workflowGuide.SetWidth(m.bodyWidth())
	m.workflowGuide.SetHeight(m.bodyHeight())
	m.workflowGuide.SetContent(renderWorkflowGuide(m.bodyWidth(), m.audience))
}

func (m *session) showTargetForm() {
	m.openingReport = false
	m.setForm(enteringTarget, huh.NewInput().Key(choiceKey).Title("Repository path or Git URL").
		Description("Local checkout or remote Git repository.").
		Placeholder("./repository").Validate(required("Enter a repository path or Git URL.")))
}

func required(message string) func(string) error {
	return func(value string) error {
		if strings.TrimSpace(value) == "" {
			return errors.New(message)
		}
		return nil
	}
}

func (m *session) showExportFormats() tea.Cmd {
	m.exportMessage = ""
	defaultFormat := "html"
	switch m.audience {
	case developerExperience:
		defaultFormat = "sarif"
	case agentExperience:
		defaultFormat = "json"
	}
	m.setForm(choosingFormat, huh.NewSelect[string]().Key(choiceKey).Title("Report format").
		Description("Exports include all findings.").
		Options(
			huh.NewOption("HTML   ·  Read and share", "html").Selected(defaultFormat == "html"),
			huh.NewOption("JSON   ·  Agent handoff", "json").Selected(defaultFormat == "json"),
			huh.NewOption("SARIF  ·  Code scanning", "sarif").Selected(defaultFormat == "sarif"),
		))
	return m.form.Init()
}

func (m *session) showExportPath(path string) tea.Cmd {
	m.setForm(enteringDestination, huh.NewInput().Key(choiceKey).Title("Save "+strings.ToUpper(m.exportFormat)+" report").
		Description("Choose a new file. Existing files stay untouched.").
		Value(&path).Validate(required("Enter a destination file path.")))
	return m.form.Init()
}

func (m *session) updateForm(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "esc" {
		switch m.phase {
		case choosingFormat, enteringDestination:
			m.form = nil
			m.exportMessage = ""
			m.phase = ready
			return nil
		default:
			return tea.Quit
		}
	}

	_, cmd := m.form.Update(msg)
	if m.form.State != huh.StateCompleted {
		return cmd
	}
	value := m.form.GetString(choiceKey)
	m.form = nil

	switch m.phase {
	case home:
		return m.showWorkspace(experience(value))
	case workspace:
		switch value {
		case "report":
			m.showPicker()
			return m.Init()
		case "guide":
			m.showWorkflowGuide()
			return nil
		case "cwd":
			return m.startLoad(".")
		default:
			m.showTargetForm()
			return m.form.Init()
		}
	case enteringTarget:
		return m.startLoad(value)
	case choosingFormat:
		m.exportFormat = value
		return m.showExportPath("repyy-report." + value)
	case enteringDestination:
		return m.startExport(value)
	default:
		return nil
	}
}

func (m *session) startExport(path string) tea.Cmd {
	m.phase = exporting
	m.exportMessage = ""
	done := make(chan exportResult, 1)
	m.exportDone = done
	report, format, export := m.report, m.exportFormat, m.opts.Export
	go func() {
		defer close(done)
		done <- exportResult{path: path, err: export(report, format, path)}
	}()
	return func() tea.Msg { return <-done }
}

func (m *session) finishExport(result exportResult) tea.Cmd {
	m.exportDone = nil
	if result.err != nil {
		m.exportMessage = output.SanitizeSourceText(result.err.Error())
		if errors.Is(result.err, os.ErrExist) {
			m.exportMessage = "That file already exists. Choose a different path."
		}
		return m.showExportPath(result.path)
	}
	m.phase = ready
	m.exportMessage = "Saved " + strings.ToUpper(m.exportFormat) + " report to " + output.SanitizeSourceText(result.path)
	return nil
}

func (m *session) retry(msg tea.Msg) tea.Cmd {
	k, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return nil
	}
	switch k.String() {
	case "r":
		if m.loadPath != "" || !m.openingReport || !m.opts.PickReport && !m.opts.Home {
			return m.startLoad(m.loadPath)
		}
		m.showPicker()
		return m.Init()
	case "esc":
		switch {
		case m.openingReport && (m.opts.PickReport || m.opts.Home):
			if m.picker.CurrentDirectory == "" {
				m.showPicker()
			} else {
				m.phase, m.err = picking, nil
			}
			return m.Init()
		case m.opts.PromptTarget || m.opts.Home:
			m.showTargetForm()
			return m.form.Init()
		}
	}
	return nil
}

func (m *session) formScreen() (string, string, []key.Binding) {
	enter := hint("enter", "continue")
	back := hint("esc", "cancel")
	switch m.phase {
	case home:
		return "Home", "\n" + m.form.View(), []key.Binding{hint("1–3", "open workspace"), hint("↑↓", "choose"), enter, quitKey}
	case workspace:
		return "Workspace", "\n" + m.form.View(), []key.Binding{hint("↑↓", "choose"), enter, hint("esc", "home"), quitKey}
	case workspaceGuide:
		return string(m.audience), m.workflowGuide.View(), []key.Binding{hint("↑↓", "scroll"), hint("esc", "workspace"), quitKey}
	case enteringTarget:
		return "Scan a repository", "\n" + m.form.View(), []key.Binding{hint("enter", "scan"), back}
	case choosingFormat:
		return "Export report", "\n" + m.form.View(), []key.Binding{hint("↑↓", "choose"), enter, back}
	case enteringDestination:
		body := m.form.View()
		if m.exportMessage != "" {
			body = warning.Render(ansi.Wrap(m.exportMessage, m.bodyWidth(), "")) + "\n\n" + body
		}
		return "Export report", body, []key.Binding{hint("enter", "save"), back}
	default:
		return "Export report", fmt.Sprintf("Saving %s report…", strings.ToUpper(m.exportFormat)), nil
	}
}
