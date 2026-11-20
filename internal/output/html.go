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
	ToolCommit   string
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
	ScanMode                              string
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
		ToolCommit:   displayText(report.ToolCommit),
		RulesVersion: displayText(report.RulesVersion), Intelligence: report.Intelligence,
		GeneratedAt:  report.GeneratedAt.UTC().Format(time.RFC3339),
		Severities:   []string{"critical", "high", "medium", "low"},
		Confidences:  []string{"high", "medium", "low"},
		Dispositions: []string{"block", "review", "harden", "informational"},
		ScriptHash:   base64.StdEncoding.EncodeToString(scriptHash[:]),
		StyleHash:    base64.StdEncoding.EncodeToString(styleHash[:]),
	}
	if view.ToolCommit == "" {
		view.ToolCommit = "unknown"
	}
	view.Intelligence.Version = displayText(view.Intelligence.Version)
	view.Intelligence.Date = displayText(view.Intelligence.Date)
	view.Intelligence.Source = displayText(view.Intelligence.Source)
	categories, rules, files := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, repo := range report.Results {
		repoView := htmlRepoView{
			ScanMode:          "unknown (not recorded)",
			Target:            displayText(repo.Target),
			Verdict:           displayText(repo.DecisionStatus()),
			VerdictClass:      strings.ToLower(strings.ReplaceAll(repo.Verdict, " ", "-")),
			Reason:            htmlVerdictReason(repo),
			FilesScanned:      repo.Coverage.FilesScanned,
			BytesScanned:      formatHTMLBytes(repo.Coverage.BytesScanned),
			Duration:          formatHTMLDuration(repo.Duration),
			Coverage:          repo.Coverage,
			Counts:            map[string]int{},
			ActionableCounts:  map[string]int{},
			DispositionCounts: map[string]int{},
			FindingCount:      len(repo.Findings),
		}
		if repo.ScanMode != "" {
			repoView.ScanMode = displayText(string(repo.ScanMode))
		} else if repo.Isolation != nil && repo.Isolation.Backend != "" {
			// Older Docker reports already record their backend explicitly.
			repoView.ScanMode = displayText(repo.Isolation.Backend)
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
