package tui

import (
	"fmt"
	"strconv"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/paginator"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/timer"
	"charm.land/bubbles/v2/tree"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/charmbracelet/x/ansi"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
)

type pane uint8

const (
	findingsPane pane = iota
	detailPane
	repositoriesPane
	coveragePane
	locationsPane
	notesPane
	helpPane
	filtersPane
	handoffPane
)

type review struct {
	report       model.Report
	presentation output.Options
	notice       string
	readerText   string
	minSeverity  model.Severity
	pane         pane
	repository   int
	width        int
	height       int
	fixes        int
	flash        string
	handoffFrom  pane

	findings  list.Model
	repos     table.Model
	pages     paginator.Model
	detail    viewport.Model
	locations tree.Model
	notes     textarea.Model
	reminder  *timer.Model
	filters   *huh.Form
}

func newReview(report model.Report, opts Options) review {
	findings := list.New(nil, findingRows{titleLines: 1}, 76, 12)
	findings.Title = "Findings"
	findings.Styles.Title = strong
	findings.Paginator.Type = paginator.Arabic
	findings.Paginator.ArabicFormat = "%d / %d"
	findings.Styles.ArabicPagination = muted
	findings.Styles.TitleBar = lipgloss.NewStyle()
	findings.Styles.StatusBar = muted
	findings.Styles.PaginationStyle = muted
	findings.FilterInput.Prompt = "Search  "
	findings.FilterInput.Placeholder = "severity, message, rule or path"
	search := textinput.StyleState{Prompt: strong, Placeholder: muted}
	findings.FilterInput.SetStyles(textinput.Styles{Focused: search, Blurred: search, Cursor: textinput.CursorStyle{Color: lipgloss.Color("#f1b199")}})

	findings.SetShowTitle(false)
	findings.SetShowStatusBar(false)
	findings.SetShowHelp(false)
	findings.DisableQuitKeybindings()

	styles := table.DefaultStyles()
	styles.Header = strong.Padding(0, 1)
	styles.Cell = lipgloss.NewStyle().Padding(0, 1)
	styles.Selected = bar.Bold(true)
	repos := table.New(table.WithFocused(true), table.WithStyles(styles))

	notes := textarea.New()
	notes.Prompt = "  "
	notes.Placeholder = "What should you verify before running this repository?"
	notes.CharLimit = 4000
	notes.ShowLineNumbers = false
	editor := textarea.StyleState{Placeholder: muted, Selection: lipgloss.NewStyle().Reverse(true)}
	notes.SetStyles(textarea.Styles{Focused: editor, Blurred: editor, Cursor: textarea.CursorStyle{Color: lipgloss.Color("#f1b199")}})

	detail := viewport.New()
	detail.SoftWrap = true
	r := review{
		report: report, presentation: opts.Presentation, minSeverity: opts.Presentation.MinSeverity, notice: output.SanitizeSourceText(opts.Notice),
		findings: findings, repos: repos, pages: paginator.New(), detail: detail, notes: notes,
	}
	r.pages.Type = paginator.Arabic
	r.pages.ArabicFormat = "Page %d of %d"
	if len(report.Results) > 0 {
		r.selectRepo(0)
	}
	return r
}

func (r *review) selectRepo(index int) {
	r.repository = index
	result := r.report.Results[index]
	r.fixes = 0
	for _, f := range result.Findings {
		if f.Remediation != "" && f.Disposition != model.DispositionInformational {
			r.fixes++
		}
	}
	presentation := r.presentation
	presentation.MinSeverity = r.minSeverity
	visible := output.ReviewFindings(result.Findings, presentation)
	items := make([]list.Item, 0, len(visible))
	for _, f := range visible {
		items = append(items, findingItem{f})
	}
	r.findings.ResetFilter()
	r.findings.ResetSelected()
	r.findings.SetItems(items)
	r.pane = findingsPane
}

func (r *review) resize(width, height int) {
	r.width, r.height = width, height
	r.findings.SetDelegate(r.rowDelegate())
	r.findings.SetSize(r.queueWidth(), max(1, height-r.findingsHeaderHeight()))
	r.detail.SetWidth(min(width, 84))
	r.detail.SetHeight(max(1, height-2))
	switch r.pane {
	case coveragePane, detailPane, handoffPane:
		r.detail.SetContent(ansi.Wrap(r.readerText, r.detail.Width(), ""))
	}
	r.notes.SetWidth(min(76, width))
	r.notes.SetHeight(max(1, height-3))
	if r.pane == locationsPane {
		r.locations.SetSize(width, max(1, height-2))
	}
	r.resizeRepos()
}

func (r *review) resizeRepos() {
	if len(r.report.Results) == 0 {
		return
	}
	rowsPerPage := max(1, r.height-5)
	r.pages.PerPage = rowsPerPage
	r.pages.SetTotalPages(len(r.report.Results))
	r.pages.Page = min(r.pages.Page, r.pages.TotalPages-1)

	statusWidth := min(14, r.width/3)
	r.repos.SetWidth(r.width)
	columns := []table.Column{
		{Title: "Repository", Width: max(8, r.width-statusWidth-21)},
		{Title: "Status", Width: statusWidth},
		{Title: "Files", Width: 5},
		{Title: "Findings", Width: 8},
	}
	if r.width < 46 {
		columns[0].Width = max(8, r.width-statusWidth-14)
		columns[2].Width = 0
	}
	r.repos.SetColumns(columns)
	r.repos.SetHeight(rowsPerPage + 1)
	r.setRepoRows()
}

func (r *review) setRepoRows() {
	start, end := r.pages.GetSliceBounds(len(r.report.Results))
	rows := make([]table.Row, 0, end-start)
	for _, result := range r.report.Results[start:end] {
		status := "Review"
		switch result.DecisionStatus() {
		case "SCAN INCOMPLETE":
			status = "Incomplete"
		case "NO RELEVANT FINDINGS DETECTED":
			status = "No findings"
		case "FINDINGS DETECTED":
			status = "Findings"
		}
		rows = append(rows, table.Row{result.Target, status, strconv.Itoa(result.Coverage.FilesScanned), strconv.Itoa(len(result.Findings))})
	}
	r.repos.SetRows(rows)
}

func (r *review) update(msg tea.Msg) tea.Cmd {
	switch msg.(type) {
	case timer.TickMsg, timer.StartStopMsg:
		if r.reminder != nil {
			updated, cmd := r.reminder.Update(msg)
			r.reminder = &updated
			return cmd
		}
	}

	if r.pane == filtersPane {
		return r.updateFilters(msg)
	}
	k, pressed := msg.(tea.KeyPressMsg)
	if pressed {
		r.flash = ""
		if r.pane == notesPane && k.String() == "esc" {
			r.notes.Blur()
			r.pane = findingsPane
			return nil
		}
		if r.pane != notesPane && !(r.pane == findingsPane && r.findings.SettingFilter()) {
			if handled, cmd := r.navigate(k.String()); handled {
				return cmd
			}
		}
	}

	var cmd tea.Cmd
	switch r.pane {
	case findingsPane:
		r.findings, cmd = r.findings.Update(msg)
	case detailPane, coveragePane, handoffPane:
		r.detail, cmd = r.detail.Update(msg)
	case locationsPane:
		r.locations, cmd = r.locations.Update(msg)
	case notesPane:
		r.notes, cmd = r.notes.Update(msg)
	case repositoriesPane:
		page := r.pages.Page
		r.pages, cmd = r.pages.Update(msg)
		if page != r.pages.Page {
			r.repos.SetCursor(0)
			r.setRepoRows()
			return cmd
		}
		r.repos, cmd = r.repos.Update(msg)
	}
	return cmd
}

func (r *review) navigate(action string) (bool, tea.Cmd) {
	if r.pane == helpPane {
		if action == "?" || action == "esc" || action == "q" {
			r.pane = findingsPane
		}
		return true, nil
	}
	if action == "esc" && r.pane != findingsPane {
		switch {
		case r.pane == locationsPane || r.pane == handoffPane && r.handoffFrom == detailPane:
			if f, ok := r.selectedFinding(); ok {
				r.showDetail(f)
			}
		default:
			r.pane = findingsPane
		}
		return true, nil
	}
	switch action {
	case "1":
		r.pane = findingsPane
		return true, nil
	case "2", "r":
		if len(r.report.Results) > 0 {
			r.openRepositories()
		}
		return true, nil
	case "3", "c":
		if len(r.report.Results) > 0 {
			r.showCoverage()
		}
		return true, nil
	}
	switch {
	case action == "y" && (r.pane == findingsPane || r.pane == detailPane):
		if f, ok := r.selectedFinding(); ok {
			location := pathAt(f.Path, f.Line)
			r.flash = "Copied " + location
			return true, tea.SetClipboard(location)
		}
		return true, nil
	case action == "y" && r.pane == handoffPane:
		r.flash = "Copied handoff brief"
		return true, tea.SetClipboard(r.readerText)
	case action == "h" && (r.pane == findingsPane || r.pane == detailPane) && len(r.report.Results) > 0:
		r.handoffFrom = r.pane
		r.openReader(handoffPane, handoffBrief(r.report, r.report.Results[r.repository]))
		return true, nil
	case (action == "[" || action == "]") && r.pane == detailPane:
		r.stepFinding(map[string]int{"[": -1, "]": 1}[action])
		return true, nil
	}
	if r.pane == detailPane && action == "l" {
		if f, ok := r.selectedFinding(); ok {
			r.showLocations(f)
		}
		return true, nil
	}
	if r.pane == repositoriesPane && action == "enter" {
		if row := r.repos.SelectedRow(); row != nil {
			start, _ := r.pages.GetSliceBounds(len(r.report.Results))
			r.selectRepo(start + r.repos.Cursor())
		}
		return true, nil
	}
	if r.pane != findingsPane {
		return false, nil
	}

	switch action {
	case "?":
		r.pane = helpPane
	case "enter":
		if f, ok := r.selectedFinding(); ok {
			r.showDetail(f)
		}
	case "f":
		if len(r.report.Results) > 0 {
			return true, r.openFilters()
		}
	case "n":
		r.pane = notesPane
		return true, r.notes.Focus()
	case "t":
		if r.reminder != nil {
			r.reminder = nil
			return true, nil
		}
		countdown := timer.New(5 * time.Minute)
		r.reminder = &countdown
		return true, countdown.Init()
	default:
		return false, nil
	}
	return true, nil
}

func (r *review) screen() (string, string, []key.Binding) {
	back := hint("esc", "back")
	scroll := hint("↑↓", "scroll")
	switch r.pane {
	case repositoriesPane:
		body := fmt.Sprintf("%d repositories  ·  %s\n\n", len(r.report.Results), r.pages.View()) + r.repos.View()
		return "Repositories", body, []key.Binding{hint("↑↓", "move"), hint("←→", "page"), hint("enter", "open"), back, quitKey}
	case detailPane:
		position := fmt.Sprintf("Finding %d of %d", r.findings.Index()+1, len(r.findings.VisibleItems()))
		return position, r.detail.View(), []key.Binding{hint("[ ]", "prev/next"), scroll, hint("l", "locations"), hint("y", "copy path"), back, quitKey}
	case handoffPane:
		return "Handoff brief", r.detail.View(), []key.Binding{hint("y", "copy brief"), scroll, back, quitKey}
	case coveragePane:
		return "Coverage", r.detail.View(), []key.Binding{scroll, back, quitKey}
	case locationsPane:
		return "Evidence locations", "Expand a file to inspect its matches.\n\n" + r.locations.View(), []key.Binding{hint("↑↓", "move"), hint("enter", "expand"), back, quitKey}
	case notesPane:
		return "Review notes", "Scratch notes · kept for this session\n\n" + r.notes.View(), []key.Binding{hint("esc", "return to findings")}
	default:
		return r.findingsScreen()
	}
}

func (r *review) openRepositories() {
	r.pages.Page = r.repository / r.pages.PerPage
	r.setRepoRows()
	r.repos.SetCursor(r.repository % r.pages.PerPage)
	r.pane = repositoriesPane
}

func (r *review) tabLabels() []string {
	active := 0
	switch r.pane {
	case repositoriesPane:
		active = 1
	case coveragePane:
		active = 2
	}
	labels := []string{"1 Findings", "2 Repositories", "3 Coverage"}
	if r.width < 44 {
		labels = []string{"1 Queue", "2 Repos", "3 Scope"}
	}
	for i, label := range labels {
		if i == active {
			labels[i] = accent.Render("● " + label)
		} else {
			labels[i] = muted.Render(label)
		}
	}
	return labels
}

func (r *review) stepFinding(delta int) {
	next := r.findings.Index() + delta
	if next < 0 || next >= len(r.findings.VisibleItems()) {
		return
	}
	r.findings.Select(next)
	if f, ok := r.selectedFinding(); ok {
		r.showDetail(f)
	}
}
