package output

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
)

type htmlReportView struct {
	ReportID     string
	ToolVersion  string
	RulesVersion string
	Intelligence model.IntelligenceInfo
	GeneratedAt  string
	Repositories []htmlRepoView
	Severities   []string
	Confidences  []string
	Dispositions []string
	Categories   []string
	Rules        []string
	Files        []string
	ScriptHash   string
	StyleHash    string
}

type htmlRepoView struct {
	Target, Verdict, VerdictClass, Reason string
	FilesScanned, FindingCount            int
	ActionableCount                       int
	BytesScanned                          string
	Duration                              string
	Coverage                              model.Coverage
	Counts                                map[string]int
	ActionableCounts                      map[string]int
	DispositionCounts                     map[string]int
	Findings                              []htmlFindingView
	Files                                 []htmlFileView
	RepositoryURL, Revision               string
	Isolation                             *model.IsolationInfo
}

type htmlFindingView struct {
	model.Finding
	Rule       scan.RuleInfo
	Locations  []htmlLocationView
	FilePaths  []string
	SearchText string
}

type htmlLocationView struct {
	Label, Evidence, Link string
}

type htmlFileView struct {
	Path, Severity string
	Count          int
}

func htmlOut(w io.Writer, report model.Report) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	reportHash := sha256.Sum256(encoded)
	scriptHash := sha256.Sum256([]byte(htmlScript))
	styleHash := sha256.Sum256([]byte(htmlStyle))
	view := htmlReportView{
		ReportID: "sha256:" + hex.EncodeToString(reportHash[:]), ToolVersion: displayText(report.ToolVersion),
		RulesVersion: displayText(report.RulesVersion), Intelligence: report.Intelligence,
		GeneratedAt:  report.GeneratedAt.UTC().Format(time.RFC3339),
		Severities:   []string{"critical", "high", "medium", "low"},
		Confidences:  []string{"high", "medium", "low"},
		Dispositions: []string{"block", "review", "harden", "informational"},
		ScriptHash:   base64.StdEncoding.EncodeToString(scriptHash[:]),
		StyleHash:    base64.StdEncoding.EncodeToString(styleHash[:]),
	}
	view.Intelligence.Version = displayText(view.Intelligence.Version)
	view.Intelligence.Date = displayText(view.Intelligence.Date)
	view.Intelligence.Source = displayText(view.Intelligence.Source)
	categories, rules, files := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, repo := range report.Results {
		repoView := htmlRepoView{
			Target: displayText(repo.Target), Verdict: displayText(repo.Verdict), VerdictClass: strings.ToLower(strings.ReplaceAll(repo.Verdict, " ", "-")),
			Reason: htmlVerdictReason(repo), FilesScanned: repo.Coverage.FilesScanned,
			BytesScanned: formatHTMLBytes(repo.Coverage.BytesScanned), Duration: formatHTMLDuration(repo.Duration),
			Coverage: repo.Coverage, Counts: map[string]int{}, ActionableCounts: map[string]int{}, DispositionCounts: map[string]int{}, FindingCount: len(repo.Findings),
		}
		if repo.Isolation != nil {
			repoView.Isolation = &model.IsolationInfo{
				Backend:      displayText(repo.Isolation.Backend),
				ImageDigest:  displayText(repo.Isolation.ImageDigest),
				FetchNetwork: displayText(repo.Isolation.FetchNetwork),
				ScanNetwork:  displayText(repo.Isolation.ScanNetwork),
			}
		}
		repoView.Coverage.Warnings = append([]string(nil), repo.Coverage.Warnings...)
		repoView.Coverage.Skipped = append([]string(nil), repo.Coverage.Skipped...)
		for index := range repoView.Coverage.Warnings {
			repoView.Coverage.Warnings[index] = displayText(repoView.Coverage.Warnings[index])
		}
		for index := range repoView.Coverage.Skipped {
			repoView.Coverage.Skipped[index] = displayText(repoView.Coverage.Skipped[index])
		}
		if base, _, ok := remoteSourceBase(repo.Source); ok {
			repoView.RepositoryURL = base
			repoView.Revision = repo.Source.Revision
		}
		fileCounts := map[string]*htmlFileView{}
		repoFindings := append([]model.Finding(nil), repo.Findings...)
		sortFindings(repoFindings, "severity")
		for _, finding := range repoFindings {
			repoView.Counts[string(finding.Severity)]++
			repoView.DispositionCounts[string(finding.Disposition)]++
			if finding.Disposition != model.DispositionInformational {
				repoView.ActionableCount++
				repoView.ActionableCounts[string(finding.Severity)]++
			}
			info, ok := scan.LookupRuleInfo(finding.RuleID)
			if !ok {
				info = scan.RuleInfo{ID: finding.RuleID, Category: finding.Category, Severity: finding.Severity, Confidence: finding.Confidence, Disposition: finding.Disposition, Description: finding.Message, Rationale: "This finding was produced by a custom or newer rule.", LegitimateUse: "Review the matched context before deciding whether it is expected.", Remediation: finding.Remediation, MatchScope: "raw", ApplicablePaths: []string{"custom rule paths"}}
			}
			findingView := htmlFindingView{Finding: finding, Rule: info}
			findingView.ContributingRuleIDs = append([]string(nil), finding.ContributingRuleIDs...)
			findingView.RuleID = displayText(findingView.RuleID)
			findingView.Category = displayText(findingView.Category)
			findingView.Context = displayText(findingView.Context)
			findingView.Path = displayText(findingView.Path)
			findingView.Message = displayText(findingView.Message)
			findingView.Remediation = displayText(findingView.Remediation)
			for index := range findingView.ContributingRuleIDs {
				findingView.ContributingRuleIDs[index] = displayText(findingView.ContributingRuleIDs[index])
			}
			searchParts := []string{findingView.RuleID, findingView.Category, findingView.Path, findingView.Message, findingView.Evidence, string(findingView.Disposition)}
			locations := finding.Locations
			if len(locations) == 0 {
				locations = []model.Location{{Path: finding.Path, StartLine: finding.Line, Evidence: finding.Evidence}}
			}
			for _, location := range locations {
				path := displayText(location.Path)
				findingView.Locations = append(findingView.Locations, htmlLocationView{Label: formatLocation(location), Evidence: displayText(location.Evidence), Link: remoteSourceLink(repo.Source, location)})
				findingView.FilePaths = appendUnique(findingView.FilePaths, path)
				searchParts = append(searchParts, path, displayText(location.Evidence))
				files[path] = true
			}
			findingView.Path = strings.Join(findingView.FilePaths, "\n")
			findingView.SearchText = strings.ToLower(strings.Join(searchParts, " "))
			repoView.Findings = append(repoView.Findings, findingView)
			categories[displayText(finding.Category)] = true
			rules[displayText(finding.RuleID)] = true
			for _, path := range findingView.FilePaths {
				entry := fileCounts[path]
				if entry == nil {
					entry = &htmlFileView{Path: path, Severity: string(finding.Severity)}
					fileCounts[path] = entry
				}
				entry.Count++
				if model.Severity(entry.Severity).Rank() < finding.Severity.Rank() {
					entry.Severity = string(finding.Severity)
				}
			}
		}
		for _, entry := range fileCounts {
			repoView.Files = append(repoView.Files, *entry)
		}
		sort.Slice(repoView.Files, func(i, j int) bool {
			left, right := repoView.Files[i], repoView.Files[j]
			if model.Severity(left.Severity).Rank() != model.Severity(right.Severity).Rank() {
				return model.Severity(left.Severity).Rank() > model.Severity(right.Severity).Rank()
			}
			if left.Count != right.Count {
				return left.Count > right.Count
			}
			return left.Path < right.Path
		})
		view.Repositories = append(view.Repositories, repoView)
	}
	view.Categories = sortedKeys(categories)
	view.Rules = sortedKeys(rules)
	view.Files = sortedKeys(files)
	tmpl, err := template.New("report").Funcs(template.FuncMap{"join": strings.Join}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, view)
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func truncateHTMLText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func htmlVerdictReason(repo model.RepoResult) string {
	if repo.Error != "" {
		return "The scan backend failed before completion: " + truncateHTMLText(displayText(repo.Error), 1024) + ". Rerun after correcting the backend or target."
	}
	if repo.Verdict == model.VerdictIncomplete {
		return "Scan coverage was incomplete. Review warnings and skipped areas before relying on this result."
	}
	if repo.Verdict == model.VerdictNoFindings {
		return "No enabled rule matched within the completed scan. This does not prove the repository is safe."
	}
	if finding, ok := highestPriorityFinding(repo.Findings, repo.Verdict == model.VerdictDoNotRun); ok {
		return fmt.Sprintf("Highest-priority finding: %s at %s.", displayText(finding.RuleID), formatLocation(model.Location{Path: finding.Path, StartLine: finding.Line}))
	}
	return "Review the findings and their surrounding source context before running this repository."
}

func formatHTMLDuration(duration time.Duration) string {
	if duration < time.Second {
		return duration.Round(time.Millisecond).String()
	}
	return duration.Round(time.Second).String()
}

func formatHTMLBytes(value int64) string {
	const unit = int64(1024)
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	number := float64(value)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB"} {
		number /= float64(unit)
		if number < float64(unit) || suffix == "TiB" {
			return fmt.Sprintf("%.1f %s", number, suffix)
		}
	}
	return fmt.Sprintf("%d B", value)
}

func remoteSourceLink(source *model.SourceInfo, location model.Location) string {
	if location.StartLine <= 0 || strings.Contains(location.Path, "!") {
		return ""
	}
	base, host, ok := remoteSourceBase(source)
	if !ok {
		return ""
	}
	segments := strings.Split(strings.TrimPrefix(location.Path, "/"), "/")
	for index := range segments {
		if segments[index] == "" || segments[index] == "." || segments[index] == ".." || strings.ContainsAny(segments[index], "\r\n\x00") {
			return ""
		}
		segments[index] = url.PathEscape(segments[index])
	}
	path := strings.Join(segments, "/")
	anchor := fmt.Sprintf("#L%d", location.StartLine)
	if location.EndLine > location.StartLine {
		anchor += fmt.Sprintf("-L%d", location.EndLine)
	}
	switch host {
	case "github.com":
		return base + "/blob/" + source.Revision + "/" + path + anchor
	case "gitlab.com":
		return base + "/-/blob/" + source.Revision + "/" + path + anchor
	case "bitbucket.org":
		return base + "/src/" + source.Revision + "/" + path + fmt.Sprintf("#lines-%d", location.StartLine)
	default:
		return ""
	}
}

func remoteSourceBase(source *model.SourceInfo) (string, string, bool) {
	if source == nil || source.RepositoryURL == "" || source.Revision == "" {
		return "", "", false
	}
	parsed, err := url.Parse(source.RepositoryURL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Host != host || host != "github.com" && host != "gitlab.com" && host != "bitbucket.org" {
		return "", "", false
	}
	for _, char := range source.Revision {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return "", "", false
		}
	}
	if len(source.Revision) < 40 || len(source.Revision) > 64 {
		return "", "", false
	}
	repositorySegments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(repositorySegments) < 2 {
		return "", "", false
	}
	for index, segment := range repositorySegments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\r\n\x00") {
			return "", "", false
		}
		repositorySegments[index] = url.PathEscape(segment)
	}
	base := "https://" + host + "/" + strings.Join(repositorySegments, "/")
	return base, host, true
}

const htmlScript = `(() => {
  document.documentElement.classList.add('js');
  const cards = [...document.querySelectorAll('[data-finding]')];
  const controls = [...document.querySelectorAll('[data-filter]')];
	const empty = document.querySelector('[data-empty]');
  const apply = () => {
    const values = Object.fromEntries(controls.map((el) => [el.dataset.filter, el.value.toLowerCase()]));
    let visible = 0;
    for (const card of cards) {
      const matches = (!values.search || card.dataset.search.includes(values.search)) &&
        (!values.severity || card.dataset.severity === values.severity) &&
		(!values.confidence || card.dataset.confidence === values.confidence) &&
		(!values.disposition || (values.disposition === 'actionable' ? card.dataset.disposition !== 'informational' : card.dataset.disposition === values.disposition)) &&
		(!values.category || card.dataset.category === values.category) &&
		(!values.rule || card.dataset.rule === values.rule) &&
        (!values.file || card.dataset.file.split('\n').includes(values.file));
      card.hidden = !matches;
      if (matches) visible++;
    }
    for (const repo of document.querySelectorAll('.repo')) {
      const repoCards = [...repo.querySelectorAll('[data-finding]:not([hidden])')];
      const repoFiles = new Set(repoCards.flatMap((card) => card.dataset.file.split('\n').filter(Boolean)));
      for (const row of repo.querySelectorAll('[data-file-row]')) row.hidden = !repoFiles.has(row.dataset.file);
      const count = repo.querySelector('[data-repo-visible-count]');
      if (count) count.textContent = String(repoCards.length);
    }
    document.querySelector('[data-visible-count]').textContent = String(visible);
	empty.hidden = visible !== 0;
  };
  for (const control of controls) control.addEventListener(control.tagName === 'INPUT' ? 'input' : 'change', apply);
	document.querySelector('[data-reset]').addEventListener('click', () => {
		for (const control of controls) control.value = control.dataset.filter === 'disposition' ? 'actionable' : '';
		apply();
	});
  const setView = (selected) => {
    for (const section of document.querySelectorAll('[data-view-panel]')) section.hidden = section.dataset.viewPanel !== selected;
    for (const candidate of document.querySelectorAll('[data-view]')) {
      const active = candidate.dataset.view === selected;
      candidate.setAttribute('aria-pressed', String(active));
    }
  };
  const viewButtons = [...document.querySelectorAll('[data-view]')];
  for (const button of viewButtons) {
    button.addEventListener('click', () => setView(button.dataset.view));
    button.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault();
      const next = viewButtons[(viewButtons.indexOf(button) + (event.key === 'ArrowRight' ? 1 : -1) + viewButtons.length) % viewButtons.length];
      next.focus();
      setView(next.dataset.view);
    });
  }
  setView('findings');
  apply();
})();`

const htmlStyle = `:root {
  color-scheme: light;
  font: 100%/1.5 system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
  font-optical-sizing: auto;
  --bg: #f5f5f7;
  --surface: rgba(245, 245, 247, .88);
  --field: #fff;
  --text: #1d1d1f;
  --secondary: #68686d;
  --tertiary: #78787e;
  --line: #dedee2;
  --soft: rgba(120, 120, 128, .08);
  --code: #f2f2f7;
  --accent: #b8401f;
  --critical: #d70015;
  --high: #b8401f;
  --medium: #9a6700;
  --low: #0071a4;
}
* { box-sizing: border-box }
html { background: var(--bg) }
body { margin: 0; background: var(--bg); color: var(--text) }
main { width: min(100% - 2rem, 980px); margin: 0 auto; padding: 4.5rem 0 6rem }
.skip-link { position: fixed; top: .75rem; left: .75rem; z-index: 100; padding: .55rem .8rem; border-radius: .5rem; background: var(--text); color: var(--field); transform: translateY(-200%) }
.skip-link:focus { transform: translateY(0) }
h1, h2, h3, p { margin-top: 0 }
h1 { margin-bottom: .65rem; font-size: clamp(2.25rem, 6vw, 3.75rem); line-height: 1.02; letter-spacing: -.04em; font-weight: 700 }
h2 { font-size: 1.5rem; line-height: 1.2; letter-spacing: -.022em }
h3 { font-size: 1.0625rem; line-height: 1.35; letter-spacing: -.012em }
a { color: var(--accent); text-underline-offset: .15em }
.eyebrow { margin-bottom: .7rem; color: var(--secondary); font-size: .75rem; font-weight: 600; letter-spacing: .06em; text-transform: uppercase }
.masthead { padding-bottom: 2rem; border-bottom: 1px solid var(--line) }
.report-brand { display: inline-flex; align-items: baseline; margin-bottom: 3rem; font-size: 1.7rem; font-weight: 750; letter-spacing: -.06em }
.report-brand span { color: var(--accent) }
.report-brand small { margin-left: 1rem; color: var(--secondary); font-size: .8rem; font-weight: 450; letter-spacing: 0 }
.meta { display: flex; flex-wrap: wrap; gap: .35rem 1.25rem; color: var(--secondary); font-size: .875rem }
.meta .pill { padding: 0; border: 0; border-radius: 0 }
.muted { color: var(--secondary) }
.spaced { margin-top: 1rem }
.masthead .spaced { overflow-wrap: anywhere; font: .75rem/1.5 ui-monospace, SFMono-Regular, Menlo, monospace }
.review-controls { display: none; position: sticky; top: 0; z-index: 10; margin: 0 -1rem; padding: .8rem 1rem 1rem; background: var(--surface); border-bottom: 1px solid var(--line); backdrop-filter: blur(20px) saturate(180%) }
.js .review-controls { display: block }
.filters { display: grid; grid-template-columns: minmax(14rem, 1fr) auto auto; gap: .5rem }
.filters input, .filters select, button { min-height: 2.5rem; border: 1px solid var(--line); border-radius: .65rem; background: var(--field); color: var(--text); padding: .45rem .7rem; font: inherit }
.filters input { min-width: 0 }
.more-filters { grid-column: 1 / -1 }
.more-filters summary, details > summary { width: fit-content; color: var(--accent); cursor: pointer; font-weight: 500 }
.more-filters-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .5rem; margin-top: .65rem }
.reset { min-height: auto; margin-top: .65rem; padding: .2rem 0; border: 0; background: transparent; color: var(--accent); font-size: .875rem }
button { cursor: pointer }
button:active, select:active { transform: scale(.98); transition: transform 100ms ease-out }
:focus-visible { outline: 3px solid color-mix(in srgb, var(--accent) 35%, transparent); outline-offset: 2px }
.view-switch { display: flex; align-items: center; gap: .25rem; width: fit-content; margin: 0 0 .75rem; padding: .2rem; border-radius: .7rem; background: var(--soft) }
.view-switch button { min-height: 2rem; padding: .25rem .75rem; border: 0; background: transparent }
.view-switch button[aria-pressed=true] { background: var(--field); box-shadow: 0 1px 3px rgba(0, 0, 0, .12) }
.view-switch .pill { margin-left: .35rem; padding-right: .55rem; color: var(--secondary); font-size: .8125rem }
.repo { padding-top: 1rem }
.repo-heading { display: flex; justify-content: space-between; gap: 2rem; align-items: start; margin-top: 1.8rem }
.repo-heading h2 { margin-bottom: .35rem; overflow-wrap: anywhere }
.repo-heading .eyebrow { margin-bottom: .45rem }
.reason { max-width: 46rem; margin: .3rem 0 1.5rem; color: var(--secondary) }
.verdict { display: inline-flex; align-items: center; gap: .45rem; color: var(--secondary); font-size: .8125rem; font-weight: 650; letter-spacing: .02em; text-transform: uppercase }
.verdict::before { width: .55rem; height: .55rem; border-radius: 50%; background: currentColor; content: "" }
.do-not-run { color: var(--critical) }
.review-required { color: var(--medium) }
.no-findings { color: #248a3d }
.scan-incomplete { color: var(--secondary) }
.summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); margin: 1.5rem 0 0; padding: 1.2rem 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line) }
.summary-grid > div { padding: 0 1.25rem; border-left: 1px solid var(--line) }
.summary-grid > div:first-child { padding-left: 0; border-left: 0 }
.summary-grid dt { color: var(--secondary); font-size: .75rem; font-weight: 550 }
.summary-grid dd { margin: .15rem 0 0; font-size: 1.75rem; line-height: 1.1; font-weight: 650; letter-spacing: -.025em }
.scan-meta { display: flex; flex-wrap: wrap; gap: .25rem 1.1rem; margin: .75rem 0 2rem; color: var(--secondary); font-size: .8125rem }
.scan-meta span + span::before { content: "·"; margin-right: 1.1rem; color: var(--tertiary) }
.empty-state { margin: 1.5rem 0; padding: 1.25rem; border-radius: .8rem; background: var(--soft); color: var(--secondary); text-align: center }
.section-heading { margin: 2rem 0 .5rem }
.finding { position: relative; padding: 1.4rem 0 1.55rem 1rem; border-top: 1px solid var(--line) }
.finding::before { position: absolute; top: 1.7rem; left: 0; width: .38rem; height: .38rem; border-radius: 50%; background: var(--low); content: "" }
.finding[data-severity=critical]::before { background: var(--critical) }
.finding[data-severity=high]::before { background: var(--high) }
.finding[data-severity=medium]::before { background: var(--medium) }
.finding-head { display: flex; justify-content: space-between; gap: 1.25rem; align-items: baseline }
.finding h3 { margin-bottom: .3rem }
.tags { display: flex; flex-wrap: wrap; gap: .2rem; color: var(--secondary); font-size: .75rem }
.tags span + span::before { content: "·"; margin: 0 .4rem; color: var(--tertiary) }
.location { margin: 1rem 0 }
.location strong { font-size: .875rem; overflow-wrap: anywhere }
pre { margin: .4rem 0 0; padding: .7rem .8rem; overflow-wrap: anywhere; border-radius: .45rem; background: var(--code); color: var(--text); white-space: pre-wrap; font: .8125rem/1.45 ui-monospace, SFMono-Regular, Menlo, monospace }
.finding details { margin-top: 1rem }
.guidance { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; margin-top: 1rem; color: var(--secondary); font-size: .875rem }
.guidance strong { color: var(--text) }
.coverage { margin-top: 2.5rem; padding: 1.25rem; border-radius: .8rem; background: var(--soft) }
.coverage h3 { margin-bottom: .35rem }
.coverage p:last-child, .coverage ul:last-child { margin-bottom: 0 }
.file-row { display: flex; justify-content: space-between; gap: 1rem; padding: .9rem 0; border-top: 1px solid var(--line); font-size: .875rem }
.file-list { margin: 0; padding: 0; list-style: none }
.file-row span:first-child { overflow-wrap: anywhere }
.file-row span:last-child { flex: none; color: var(--secondary) }
.report-footer { margin-top: 1.5rem }
[hidden] { display: none !important }
@media (max-width: 720px) {
  main { width: min(100% - 1.5rem, 980px); padding-top: 2.5rem }
  .filters { grid-template-columns: 1fr 1fr }
  .filters input { grid-column: 1 / -1 }
  .more-filters-grid { grid-template-columns: 1fr 1fr }
  .repo-heading { display: block }
  .repo-heading .verdict { margin-bottom: 1rem }
  .summary-grid { grid-template-columns: 1fr 1fr; row-gap: 1.25rem }
  .summary-grid > div:nth-child(3) { padding-left: 0; border-left: 0 }
  .finding-head { display: block }
  .guidance { grid-template-columns: 1fr; gap: .75rem }
}
@media (max-width: 460px) {
  .filters, .more-filters-grid { grid-template-columns: 1fr }
  .filters select, .more-filters-grid select { width: 100% }
  .summary-grid { grid-template-columns: 1fr }
  .summary-grid > div { padding: .7rem 0; border-left: 0; border-top: 1px solid var(--line) }
  .summary-grid > div:first-child { border-top: 0 }
  .file-row { display: block }
}
@media (prefers-reduced-transparency: reduce) { .review-controls { background: var(--bg); backdrop-filter: none } }
@media (prefers-contrast: more) { :root { --surface: var(--bg); --line: currentColor } .filters input, .filters select, button { border-color: currentColor } }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; transition: none !important } }
@media print {
  :root { color-scheme: light; --bg: #fff; --text: #000; --secondary: #444; --line: #bbb; --soft: #f5f5f5; --code: #f5f5f5 }
  body { background: #fff; color: #000 }
  main { width: 100%; padding: 0 }
  .review-controls { display: none }
  .masthead, .finding, .coverage, .file-row { break-inside: avoid }
  details > summary { display: none }
  details > * { display: block !important }
}`

const htmlTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{{.StyleHash}}'; script-src 'sha256-{{.ScriptHash}}'; img-src data:; base-uri 'none'; form-action 'none'; connect-src 'none'; object-src 'none'">
<title>repyy security review</title><style>` + htmlStyle + `</style></head><body><a class="skip-link" href="#report-content">Skip to report</a><main id="report-content">
<header class="masthead" aria-labelledby="report-title"><div class="report-brand" aria-label="repyy report">repyy<span aria-hidden="true">/</span><small>Report</small></div><p class="eyebrow">Read-only repository preflight</p><h1 id="report-title">repyy security review</h1><div class="meta" aria-label="Report metadata"><span class="pill">repyy {{.ToolVersion}}</span><span class="pill">rules {{.RulesVersion}}</span><span class="pill">intelligence {{.Intelligence.Version}}</span><span class="pill">generated <time datetime="{{.GeneratedAt}}">{{.GeneratedAt}}</time></span></div><p class="muted spaced">Report <code>{{.ReportID}}</code></p></header>
<section class="review-controls" aria-label="Review controls">
<div class="view-switch" role="group" aria-label="Report view"><button data-view="findings" aria-pressed="true" type="button">Findings</button><button data-view="files" aria-pressed="false" type="button">Files</button><span class="pill"><output data-visible-count aria-live="polite">0</output> results</span></div>
<section class="filters" aria-label="Finding filters">
<input data-filter="search" type="search" placeholder="Search findings" aria-label="Search findings">
<select data-filter="severity" aria-label="Severity"><option value="">All severities</option>{{range .Severities}}<option>{{.}}</option>{{end}}</select>
<select data-filter="disposition" aria-label="Disposition"><option value="actionable" selected>Review queue</option><option value="">All dispositions</option>{{range .Dispositions}}<option>{{.}}</option>{{end}}</select>
<details class="more-filters"><summary>More filters</summary><div class="more-filters-grid">
<select data-filter="confidence" aria-label="Confidence"><option value="">All confidence</option>{{range .Confidences}}<option>{{.}}</option>{{end}}</select>
<select data-filter="category" aria-label="Category"><option value="">All categories</option>{{range .Categories}}<option>{{.}}</option>{{end}}</select>
<select data-filter="rule" aria-label="Rule"><option value="">All rules</option>{{range .Rules}}<option>{{.}}</option>{{end}}</select>
<select data-filter="file" aria-label="File"><option value="">All files</option>{{range .Files}}<option>{{.}}</option>{{end}}</select>
</div><button class="reset" data-reset type="button">Reset filters</button></details></section></section>
<p class="empty-state" data-empty role="status" aria-live="polite" hidden>No findings match the current filters.</p>
{{range .Repositories}}<article class="repo" aria-label="Repository review for {{.Target}}"><header class="repo-heading"><div><p class="eyebrow">Repository</p><h2>{{.Target}}</h2><p class="muted"><output data-repo-visible-count aria-live="polite">{{.FindingCount}}</output> visible findings</p>{{if .RepositoryURL}}<p class="muted">Source <a href="{{.RepositoryURL}}" rel="noreferrer">{{.RepositoryURL}}</a> at <code>{{.Revision}}</code></p>{{end}}</div><strong class="verdict {{.VerdictClass}}" role="status">{{.Verdict}}</strong></header><p class="reason">{{.Reason}}</p><dl class="summary-grid" aria-label="Review summary"><div><dt>Needs attention</dt><dd>{{.ActionableCount}}</dd></div><div><dt>Critical priority</dt><dd>{{index .ActionableCounts "critical"}}</dd></div><div><dt>High priority</dt><dd>{{index .ActionableCounts "high"}}</dd></div><div><dt>Files scanned</dt><dd>{{.FilesScanned}}</dd></div></dl><p class="scan-meta"><span>{{.FindingCount}} total findings</span><span>{{index .Counts "high"}} high total</span><span>{{index .Counts "medium"}} medium</span><span>{{index .Counts "low"}} low</span><span>{{index .DispositionCounts "block"}} block</span><span>{{index .DispositionCounts "review"}} review</span><span>{{index .DispositionCounts "harden"}} harden</span><span>{{index .DispositionCounts "informational"}} informational</span><span>{{.BytesScanned}}</span><span>{{.Duration}}</span></p>
<section data-view-panel="findings" aria-label="Findings for {{.Target}}"><h2 class="section-heading">Findings</h2>{{if not .Findings}}<p>No enabled rule matched. This is not a guarantee that the repository is safe.</p>{{end}}{{range .Findings}}<article class="finding" data-finding data-search="{{.SearchText}}" data-severity="{{.Severity}}" data-confidence="{{.Confidence}}" data-disposition="{{.Disposition}}" data-category="{{.Category}}" data-rule="{{.RuleID}}" data-file="{{.Path}}"><header class="finding-head"><div><h3>{{.RuleID}} · {{.Message}}</h3><p class="tags"><span>{{.Severity}}</span><span>{{.Confidence}} confidence</span><span>{{.Disposition}}</span><span>{{.Context}}</span><span>{{.Category}}</span></p></div><span aria-label="{{.Occurrences}} occurrence{{if ne .Occurrences 1}}s{{end}}">{{.Occurrences}} occurrence{{if ne .Occurrences 1}}s{{end}}</span></header>{{range .Locations}}<div class="location">{{if .Link}}<a href="{{.Link}}" rel="noreferrer">{{.Label}}</a>{{else}}<strong>{{.Label}}</strong>{{end}}{{if .Evidence}}<pre aria-label="Redacted evidence"><code>{{.Evidence}}</code></pre>{{end}}</div>{{end}}{{if .LocationsOmitted}}<p class="muted">{{.LocationsOmitted}} additional locations omitted by report limits.</p>{{end}}{{if .ContributingRuleIDs}}<p><strong>Contributing rules:</strong> {{join .ContributingRuleIDs ", "}}</p>{{end}}<details><summary>Why this was flagged and what to do</summary><div class="guidance"><div><strong>Why it matters</strong><p>{{.Rule.Rationale}}</p>{{if .Rule.ApplicablePaths}}<p><strong>Applies to:</strong> {{join .Rule.ApplicablePaths ", "}}</p>{{end}}</div><div><strong>Common legitimate use</strong><p>{{.Rule.LegitimateUse}}</p></div><div><strong>Recommended action</strong><p>{{.Remediation}}</p></div></div></details></article>{{end}}</section>
<section data-view-panel="files" aria-label="Files with findings for {{.Target}}"><h2 class="section-heading">Files</h2><ul class="file-list">{{range .Files}}<li class="file-row" data-file-row data-file="{{.Path}}"><span>{{.Path}}</span><span>{{.Count}} findings · highest {{.Severity}}</span></li>{{end}}</ul></section>
{{if .Isolation}}<p class="isolation muted">Isolation: {{.Isolation.Backend}} · scan network {{.Isolation.ScanNetwork}}{{if .Isolation.ImageDigest}} · image {{.Isolation.ImageDigest}}{{end}}</p>{{end}}<section class="coverage" aria-label="Scan coverage"><h3>Coverage</h3><p>{{if .Coverage.Complete}}Complete{{else}}Incomplete{{end}} · {{.Coverage.FilesScanned}} files · {{.BytesScanned}}</p>{{if .Coverage.Warnings}}<h4>Warnings</h4><ul>{{range .Coverage.Warnings}}<li>{{.}}</li>{{end}}</ul>{{end}}{{if .Coverage.Skipped}}<h4>Skipped areas</h4><ul>{{range .Coverage.Skipped}}<li>{{.}}</li>{{end}}</ul>{{end}}</section></article>{{end}}
<footer class="muted report-footer">Findings are repository evidence, not proof that code executed or a host was compromised. Runtime behavior, host processes and credential stores, remote CI logs, and network traffic are not inspected. NO FINDINGS does not guarantee that a repository is safe.</footer></main><script>` + htmlScript + `</script></body></html>`
