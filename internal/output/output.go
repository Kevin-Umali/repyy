// Package output renders scan reports without exposing unredacted source data.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
)

// Options controls human-facing rendering without changing scan policy.
type Options struct {
	Detail        string
	MinSeverity   model.Severity
	MinConfidence model.Confidence
	GroupBy       string
	Color         bool
}

// DefaultOptions returns the prioritized interactive presentation defaults.
func DefaultOptions() Options {
	return Options{Detail: "review", MinSeverity: model.SeverityLow, MinConfidence: model.ConfidenceLow, GroupBy: "severity"}
}

// Write serializes a report in terminal, JSON, or SARIF form.
func Write(w io.Writer, format string, report model.Report) error {
	return WriteWithOptions(w, format, report, DefaultOptions())
}

// WriteWithOptions serializes a report with presentation-only options.
func WriteWithOptions(w io.Writer, format string, report model.Report, opts Options) error {
	report = sanitizedReport(report)
	switch format {
	case "terminal":
		return terminal(w, report, opts)
	case "json":
		return jsonOut(w, report)
	case "sarif":
		return sarifOut(w, report)
	case "html":
		return htmlOut(w, report)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func sanitizedReport(report model.Report) model.Report {
	report.Results = append([]model.RepoResult(nil), report.Results...)
	for resultIndex := range report.Results {
		report.Results[resultIndex].Findings = append([]model.Finding(nil), report.Results[resultIndex].Findings...)
		for findingIndex := range report.Results[resultIndex].Findings {
			finding := &report.Results[resultIndex].Findings[findingIndex]
			scan.NormalizeFinding(finding)
			finding.Evidence = scan.SanitizeEvidence(finding.Evidence)
			finding.Locations = append([]model.Location(nil), finding.Locations...)
			for locationIndex := range finding.Locations {
				finding.Locations[locationIndex].Evidence = scan.SanitizeEvidence(finding.Locations[locationIndex].Evidence)
			}
		}
	}
	return report
}

func terminal(w io.Writer, report model.Report, opts Options) error {
	paint := func(code, value string) string {
		if !opts.Color {
			return value
		}
		return "\x1b[" + code + "m" + value + "\x1b[0m"
	}
	fmt.Fprintf(w, "repyy %s — read-only repository preflight\n", displayText(report.ToolVersion))
	fmt.Fprintf(w, "rules %s · intelligence %s (%s, %s)\n\n", displayText(report.RulesVersion), displayText(report.Intelligence.Version), displayText(report.Intelligence.Date), displayText(report.Intelligence.Source))
	for _, result := range report.Results {
		verdictColor := "33"
		if result.Verdict == model.VerdictDoNotRun {
			verdictColor = "31;1"
		} else if result.Verdict == model.VerdictNoFindings {
			verdictColor = "32"
		}
		fmt.Fprintf(w, "%s · %s\n", paint(verdictColor, displayText(result.Verdict)), displayText(abbreviateHome(result.Target)))
		if result.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", displayText(result.Error))
		}
		counts := map[model.Severity]int{}
		for _, f := range result.Findings {
			counts[f.Severity]++
		}
		fmt.Fprintf(w, "  critical %d · high %d · medium %d · low %d · files %d · %s\n", counts[model.SeverityCritical], counts[model.SeverityHigh], counts[model.SeverityMedium], counts[model.SeverityLow], result.Coverage.FilesScanned, coverageLabel(result.Coverage))
		printVerdictReason(w, result)

		visible := filterFindings(result.Findings, opts)
		if opts.Detail != "summary" {
			sortFindings(visible, opts.GroupBy)
			lastGroup := ""
			for _, f := range visible {
				group := findingGroup(f, opts.GroupBy)
				if group != lastGroup {
					fmt.Fprintf(w, "\n  %s\n", strings.ToUpper(displayText(group)))
					lastGroup = group
				}
				label := strings.ToUpper(string(f.Severity)) + " · " + strings.ToUpper(string(f.Confidence))
				fmt.Fprintf(w, "  %s  %s · %s\n", paint(severityColor(f.Severity), label), displayText(f.RuleID), displayText(f.Message))
				locations := f.Locations
				if len(locations) == 0 {
					locations = []model.Location{{Path: f.Path, StartLine: f.Line, Evidence: f.Evidence}}
				}
				for _, location := range locations {
					fmt.Fprintf(w, "      %s\n", formatLocation(location))
					for _, evidenceLine := range strings.Split(location.Evidence, "\n") {
						if evidenceLine != "" {
							fmt.Fprintf(w, "        %s\n", evidenceLine)
						}
					}
				}
				if f.LocationsOmitted > 0 {
					fmt.Fprintf(w, "      … %d additional locations omitted\n", f.LocationsOmitted)
				}
				if f.Remediation != "" {
					fmt.Fprintf(w, "      fix: %s\n", displayText(f.Remediation))
				}
				if len(f.ContributingRuleIDs) > 0 {
					fmt.Fprintf(w, "      contributing rules: %s\n", displayText(strings.Join(f.ContributingRuleIDs, ", ")))
				}
			}
		}
		hidden := len(result.Findings) - len(visible)
		if hidden > 0 {
			switch opts.Detail {
			case "summary":
				fmt.Fprintf(w, "\n  showing 0 of %d findings; use --detail review or --detail all to display them.\n", len(result.Findings))
			case "all":
				fmt.Fprintf(w, "\n  showing %d of %d findings; %d hidden by display filters.\n", len(visible), len(result.Findings), hidden)
			default:
				fmt.Fprintf(w, "\n  showing %d of %d findings; %d contextual or filtered findings hidden; use --detail all or lower the display thresholds.\n", len(visible), len(result.Findings), hidden)
			}
		}
		for _, warning := range result.Coverage.Warnings {
			fmt.Fprintf(w, "  warning: %s\n", displayText(warning))
		}
		if len(result.Coverage.Skipped) > 0 {
			fmt.Fprintf(w, "  skipped areas: %d (use --format json or html for details)\n", len(result.Coverage.Skipped))
		}
		if result.Resolved != "" {
			fmt.Fprintf(w, "  retained checkout: %s\n", displayText(abbreviateHome(result.Resolved)))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "Findings are repository evidence, not proof that code executed or a host was compromised.")
	fmt.Fprintln(w, "NO FINDINGS does not guarantee that a repository is safe.")
	return nil
}

func filterFindings(findings []model.Finding, opts Options) []model.Finding {
	if opts.Detail == "summary" {
		return nil
	}
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if opts.Detail == "review" && finding.Disposition == model.DispositionInformational {
			continue
		}
		if finding.Severity.Rank() < opts.MinSeverity.Rank() || finding.Confidence.Rank() < opts.MinConfidence.Rank() {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func sortFindings(findings []model.Finding, groupBy string) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		switch groupBy {
		case "file":
			if left.Path != right.Path {
				return left.Path < right.Path
			}
		case "rule":
			if left.RuleID != right.RuleID {
				return left.RuleID < right.RuleID
			}
		default:
			if left.Disposition.Rank() != right.Disposition.Rank() {
				return left.Disposition.Rank() > right.Disposition.Rank()
			}
		}
		if left.Severity.Rank() != right.Severity.Rank() {
			return left.Severity.Rank() > right.Severity.Rank()
		}
		if left.Confidence.Rank() != right.Confidence.Rank() {
			return left.Confidence.Rank() > right.Confidence.Rank()
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		if left.Message != right.Message {
			return left.Message < right.Message
		}
		return left.Fingerprint < right.Fingerprint
	})
}

func findingGroup(f model.Finding, groupBy string) string {
	switch groupBy {
	case "file":
		return f.Path
	case "rule":
		return f.RuleID
	default:
		return string(f.Disposition)
	}
}

func printVerdictReason(w io.Writer, result model.RepoResult) {
	if result.Verdict == model.VerdictIncomplete {
		fmt.Fprintln(w, "  why: scan coverage was incomplete; review warnings and skipped areas")
		return
	}
	if result.Verdict == model.VerdictNoFindings {
		fmt.Fprintln(w, "  why: no enabled rule matched within the completed scan")
		return
	}
	if finding, ok := highestPriorityFinding(result.Findings, result.Verdict == model.VerdictDoNotRun); ok {
		fmt.Fprintf(w, "  why: %s at %s\n", displayText(finding.RuleID), formatLocation(model.Location{Path: finding.Path, StartLine: finding.Line}))
	}
}

func highestPriorityFinding(findings []model.Finding, blocksOnly bool) (model.Finding, bool) {
	candidates := append([]model.Finding(nil), findings...)
	if blocksOnly {
		candidates = candidates[:0]
		for _, finding := range findings {
			if finding.Disposition == model.DispositionBlock {
				candidates = append(candidates, finding)
			}
		}
	}
	if len(candidates) == 0 {
		return model.Finding{}, false
	}
	sortFindings(candidates, "severity")
	return candidates[0], true
}

func coverageLabel(coverage model.Coverage) string {
	if coverage.Complete {
		return "complete"
	}
	return "incomplete"
}

func formatLocation(location model.Location) string {
	value := displayText(location.Path)
	if location.StartLine > 0 {
		value += fmt.Sprintf(":%d", location.StartLine)
		if location.EndLine > location.StartLine {
			value += fmt.Sprintf("-%d", location.EndLine)
		}
	}
	return value
}

func displayText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, value)
}

func abbreviateHome(value string) string {
	home, err := os.UserHomeDir()
	if err == nil && (value == home || strings.HasPrefix(value, home+string(os.PathSeparator))) {
		return "~" + strings.TrimPrefix(value, home)
	}
	return value
}

func severityColor(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "31;1"
	case model.SeverityHigh:
		return "31"
	case model.SeverityMedium:
		return "33"
	default:
		return "36"
	}
}

func jsonOut(w io.Writer, report model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

type sarif struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifLocation   `json:"locations"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}
type sarifInvocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	Properties          map[string]any `json:"properties,omitempty"`
}

func sarifOut(w io.Writer, report model.Report) error {
	rules := map[string]sarifRule{}
	results := []sarifResult{}
	success := true
	for _, repo := range report.Results {
		if repo.Error != "" || !repo.Coverage.Complete {
			success = false
		}
		for _, f := range repo.Findings {
			rules[f.RuleID] = sarifRule{ID: f.RuleID, ShortDescription: sarifMessage{Text: f.Message}, Properties: map[string]string{"category": f.Category, "severity": string(f.Severity), "confidence": string(f.Confidence), "context": f.Context, "disposition": string(f.Disposition)}}
			level := "warning"
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
				level = "error"
			} else if f.Severity == model.SeverityLow {
				level = "note"
			}
			findingLocations := f.Locations
			if len(findingLocations) == 0 {
				findingLocations = []model.Location{{Path: f.Path, StartLine: f.Line}}
			}
			locations := make([]sarifLocation, 0, len(findingLocations))
			for _, findingLocation := range findingLocations {
				loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: findingLocation.Path}}
				if findingLocation.StartLine > 0 {
					loc.Region = &sarifRegion{StartLine: findingLocation.StartLine, EndLine: findingLocation.EndLine}
				}
				locations = append(locations, sarifLocation{PhysicalLocation: loc})
			}
			message := f.Message
			if f.Evidence != "" {
				message += "; evidence: " + f.Evidence
			}
			results = append(results, sarifResult{RuleID: f.RuleID, Level: level, Message: sarifMessage{Text: message}, Locations: locations, Fingerprints: map[string]string{"repyy/v1": f.Fingerprint}})
		}
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	properties := map[string]any{
		"rulesVersion": report.RulesVersion,
		"intelligence": report.Intelligence,
	}
	doc := sarif{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "repyy", Version: report.ToolVersion, InformationURI: "https://github.com/Kevin-Umali/repyy", Rules: ruleList}}, Results: results, Invocations: []sarifInvocation{{ExecutionSuccessful: success, Properties: properties}}}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
