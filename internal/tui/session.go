// Package tui provides the interactive scan and report viewer.
package tui

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"time"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/stopwatch"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/term"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
)

type Options struct {
	Presentation output.Options
	Targets      int
	PickReport   bool
	Notice       string
	Timeout      time.Duration
	Home         bool
	PromptTarget bool
	OpenReport   LoadReport
	Export       func(report model.Report, format, path string) error
}

// LoadReport scans targets or reads a saved report. Each finished scan calls onComplete.
type LoadReport func(ctx context.Context, selectedPath string, onComplete func()) (model.Report, string, error)

func IsTerminal(file *os.File) bool {
	return file != nil && os.Getenv("TERM") != "dumb" && term.IsTerminal(file.Fd())
}

// Run returns the original report so display filters never affect exit policy.
func Run(stdin, stdout *os.File, opts Options, load LoadReport) (model.Report, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSession(ctx, opts, load)
	profile := colorprofile.ASCII
	if opts.Presentation.Color {
		profile = max(colorprofile.ANSI, colorprofile.Detect(stdout, os.Environ()))
	}
	_, err := tea.NewProgram(m, tea.WithInput(stdin), tea.WithOutput(stdout), tea.WithColorProfile(profile)).Run()
	cancel()
	if m.task != nil {
		<-m.task.done
	}
	if m.exportDone != nil {
		<-m.exportDone
	}
	if errors.Is(err, tea.ErrInterrupted) {
		return model.Report{}, context.Canceled
	}
	if err != nil {
		return model.Report{}, err
	}
	if m.phase == failed {
		return model.Report{}, displayError{cause: m.err}
	}
	if m.opts.Home {
		return model.Report{}, nil
	}
	if m.phase != ready {
		return model.Report{}, context.Canceled
	}
	return m.report, nil
}

type displayError struct{ cause error }

func (e displayError) Error() string { return output.SanitizeSourceText(e.cause.Error()) }
func (e displayError) Unwrap() error { return e.cause }

type phase uint8

const (
	home phase = iota
	workspace
	workspaceGuide
	enteringTarget
	picking
	loading
	cancelling
	ready
	failed
	choosingFormat
	enteringDestination
	exporting
)

type loadResult struct {
	report model.Report
	err    error
	notice string
}

type loadTask struct {
	done      chan struct{}
	cancel    context.CancelFunc
	completed atomic.Int64
	result    loadResult
}

type session struct {
	ctx           context.Context
	opts          Options
	load          LoadReport
	phase         phase
	audience      experience
	workflowGuide viewport.Model
	task          *loadTask
	report        model.Report
	err           error
	pickerNotice  string
	width, height int
	openingReport bool
	loadPath      string
	form          *huh.Form
	exportFormat  string
	exportMessage string
	exportDone    chan exportResult

	spinner spinner.Model
	meter   progress.Model
	elapsed stopwatch.Model
	picker  filepicker.Model
	help    help.Model
	review  review
}

func newSession(ctx context.Context, opts Options, load LoadReport) *session {
	m := &session{
		ctx: ctx, opts: opts, load: load, phase: loading, help: help.New(),
		openingReport: opts.Targets == 0 && !opts.PromptTarget,
	}
	m.resize(80, 24)
	switch {
	case opts.Home:
		m.showHome()
	case opts.PromptTarget:
		m.showTargetForm()
	case opts.PickReport:
		m.showPicker()
	}
	m.help.Styles = help.Styles{ShortKey: strong, ShortSeparator: muted, Ellipsis: muted}
	return m
}

func (m *session) showPicker() {
	picker := filepicker.New()
	picker.CurrentDirectory, m.err = os.Getwd()
	picker.AllowedTypes = []string{".json"}
	picker.AutoHeight = false
	picker.ShowPermissions = false
	picker.ShowSize = false
	picker.Styles = filepicker.Styles{
		EmptyDirectory: lipgloss.NewStyle().SetString("No files in this directory."),
	}
	picker.SetHeight(max(1, m.height-9))
	m.openingReport = true
	m.picker = picker
	m.pickerNotice = ""
	m.phase = picking
	if m.err != nil {
		m.phase = failed
	}
}

func (m *session) resize(width, height int) {
	m.width, m.height = width, height
	m.picker.SetHeight(max(1, height-9))
	m.help.SetWidth(m.bodyWidth())
	m.meter.SetWidth(max(1, min(width-4, 40)))
	if m.form != nil {
		m.form.WithWidth(m.formWidth())
	}
	if m.phase == workspaceGuide {
		m.resizeWorkflowGuide()
	}
	if m.phase == ready {
		m.review.resize(m.bodyWidth(), m.bodyHeight())
	}
}

func (m *session) Init() tea.Cmd {
	switch m.phase {
	case home, workspace, enteringTarget:
		return m.form.Init()
	case picking:
		return m.picker.Init()
	case loading:
		return m.startLoad("")
	default:
		return nil
	}
}

func (m *session) startLoad(path string) tea.Cmd {
	ctx, cancel := context.WithCancel(m.ctx)
	task := &loadTask{done: make(chan struct{}), cancel: cancel}
	load := m.load
	if m.opts.Home && m.openingReport {
		load = m.opts.OpenReport
	}
	m.loadPath = path
	m.task = task
	m.phase = loading
	m.err = nil
	m.pickerNotice = ""
	m.spinner = spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(accent))
	m.meter = progress.New(progress.WithWidth(max(1, min(m.bodyWidth(), 40))), progress.WithColors(lipgloss.Color("#f1b199")), progress.WithFillCharacters('━', '─'), progress.WithoutPercentage())
	m.elapsed = stopwatch.New()
	go func() {
		defer close(task.done)
		defer cancel()
		task.result.report, task.result.notice, task.result.err = load(ctx, path, func() { task.completed.Add(1) })
	}()
	wait := func() tea.Msg {
		<-task.done
		return task.result
	}
	return tea.Batch(wait, m.spinner.Tick, m.elapsed.Init())
}

func (m *session) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.resize(msg.Width, msg.Height)
		return m, nil
	case exportResult:
		return m, m.finishExport(msg)
	case loadResult:
		if m.phase == cancelling || errors.Is(msg.err, context.Canceled) {
			if m.opts.Home {
				return m, m.showWorkspace(m.audience)
			}
			m.phase = cancelling
			return m, tea.Quit
		}
		if msg.err != nil {
			m.phase, m.err = failed, msg.err
			return m, nil
		}
		m.phase, m.report = ready, msg.report
		opts := m.opts
		if msg.notice != "" {
			opts.Notice = msg.notice
		}
		m.review = newReview(output.SanitizeReport(msg.report), opts)
		m.review.resize(m.bodyWidth(), m.bodyHeight())
		return m, nil
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" && !m.editing() {
			switch m.phase {
			case loading:
				m.phase = cancelling
				m.task.cancel()
				return m, nil
			case cancelling, exporting:
				return m, nil
			default:
				return m, tea.Quit
			}
		}
		if m.phase == home || m.phase == workspace {
			switch msg.String() {
			case "1":
				return m, m.showWorkspace(userExperience)
			case "2":
				return m, m.showWorkspace(developerExperience)
			case "3":
				return m, m.showWorkspace(agentExperience)
			}
		}
		if msg.String() == "esc" && m.opts.Home {
			switch {
			case m.phase == workspace:
				m.showHome()
				return m, m.form.Init()
			case m.phase == workspaceGuide || m.phase == enteringTarget || m.phase == picking ||
				m.phase == ready && m.review.pane == findingsPane && !m.review.findings.SettingFilter() && !m.review.findings.IsFiltered():
				return m, m.showWorkspace(m.audience)
			}
		}
		if msg.String() == "e" && m.phase == ready && !m.editing() && m.opts.Export != nil {
			return m, m.showExportFormats()
		}
	}

	var cmd tea.Cmd
	switch m.phase {
	case home, workspace, enteringTarget, choosingFormat, enteringDestination:
		cmd = m.updateForm(msg)
	case workspaceGuide:
		m.workflowGuide, cmd = m.workflowGuide.Update(msg)
	case picking:
		m.picker, cmd = m.picker.Update(msg)
		if selected, path := m.picker.DidSelectFile(msg); selected {
			return m, m.startLoad(path)
		}
		if disabled, _ := m.picker.DidSelectDisabledFile(msg); disabled {
			m.pickerNotice = "Select a .json scan report."
		}
	case loading, cancelling:
		var elapsed tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		m.elapsed, elapsed = m.elapsed.Update(msg)
		var meter tea.Cmd
		m.meter, meter = m.meter.Update(msg)
		if m.task != nil && !m.openingReport && m.opts.Targets > 0 {
			fraction := float64(m.task.completed.Load()) / float64(m.opts.Targets)
			if fraction != m.meter.Percent() {
				meter = m.meter.SetPercent(fraction)
			}
		}
		cmd = tea.Batch(cmd, elapsed, meter)
	case ready:
		cmd = m.review.update(msg)
	case failed:
		cmd = m.retry(msg)
	}
	return m, cmd
}

func (m *session) editing() bool {
	return m.phase == enteringTarget || m.phase == enteringDestination || m.phase == choosingFormat || m.phase == ready && (m.review.pane == notesPane || m.review.pane == filtersPane ||
		m.review.pane == findingsPane && m.review.findings.SettingFilter())
}

func (m *session) bodyWidth() int  { return max(1, min(114, m.width-4)) }
func (m *session) bodyHeight() int { return max(1, m.height-6) }
