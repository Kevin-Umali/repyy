package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/tree"
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
	body := "\n" + severityText(f.Severity) + muted.Render(" severity · "+string(f.Confidence)+" confidence") + "\n" +
		strong.Render(f.Message) + "\n" +
		muted.Render(pathAt(f.Path, f.Line)) + "\n"
	if f.Remediation != "" {
		body += "\n" + accent.Render("Recommended action") + "\n" + f.Remediation + "\n"
	}
	if f.Evidence != "" {
		body += "\n" + strong.Render("Evidence") + "\n" + plainEvidence(f.Evidence) + "\n"
	}
	body += "\n" + strong.Render("Detection") + "\n" +
		f.RuleID + " · " + strings.ReplaceAll(f.Category, "-", " ")
	if f.Disposition != "" {
		body += " · " + string(f.Disposition)
	}
	if f.Occurrences > 1 {
		body += fmt.Sprintf("\n%d occurrences", f.Occurrences)
	}
	if f.LocationsOmitted > 0 {
		body += fmt.Sprintf("\n%d additional locations omitted", f.LocationsOmitted)
	}
	if len(f.ContributingRuleIDs) > 0 {
		body += "\nRelated rules  " + strings.Join(f.ContributingRuleIDs, ", ")
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
	body := strong.Render(result.Target) + "\n" + result.DecisionStatus() + "\n"
	body += fmt.Sprintf("%d files · %d bytes · %s elapsed", result.Coverage.FilesScanned, result.Coverage.BytesScanned, result.Duration.Round(time.Millisecond))
	if result.ScanMode != "" {
		body += " · " + string(result.ScanMode) + " scan"
	}
	if result.Error != "" {
		body += "\n\n" + warning.Render("Scan error") + "\n" + result.Error
	}
	for _, items := range []struct {
		title  string
		values []string
	}{{"Warnings", result.Coverage.Warnings}, {"Skipped areas", result.Coverage.Skipped}} {
		if len(items.values) != 0 {
			body += "\n\n" + strong.Render(items.title) + "\n" + strings.Join(items.values, "\n")
		}
	}
	if result.Resolved != "" {
		body += "\n\nRetained checkout  " + result.Resolved
	}
	if r.notice != "" {
		body += "\n\n" + strong.Render("Intelligence notice") + "\n" + r.notice
	}
	body += "\n\n" + r.report.Limitation
	r.openReader(coveragePane, body)
}
