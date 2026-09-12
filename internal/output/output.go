// Package output renders scan reports without exposing unredacted source data.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// Write serializes a report in terminal, JSON, or SARIF form.
func Write(w io.Writer, format string, report model.Report) error {
	switch format {
	case "terminal":
		return terminal(w, report)
	case "json":
		return jsonOut(w, report)
	case "sarif":
		return sarifOut(w, report)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func terminal(w io.Writer, report model.Report) error {
	fmt.Fprintf(w, "repyy %s — read-only repository preflight\n\n", report.ToolVersion)
	for _, result := range report.Results {
		fmt.Fprintf(w, "%s  %s\n", result.Verdict, result.Target)
		if result.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", result.Error)
		}
		counts := map[model.Severity]int{}
		for _, f := range result.Findings {
			counts[f.Severity]++
		}
		fmt.Fprintf(w, "  critical %d | high %d | medium %d | low %d | files %d\n", counts[model.SeverityCritical], counts[model.SeverityHigh], counts[model.SeverityMedium], counts[model.SeverityLow], result.Coverage.FilesScanned)
		for _, f := range result.Findings {
			location := f.Path
			if f.Line > 0 {
				location += fmt.Sprintf(":%d", f.Line)
			}
			fmt.Fprintf(w, "  [%s/%s/%s] %s %s", f.Severity, f.Confidence, f.Context, f.RuleID, location)
			if f.Occurrences > 1 {
				fmt.Fprintf(w, " (%d matches)", f.Occurrences)
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "    %s\n", f.Message)
			if f.Evidence != "" {
				fmt.Fprintf(w, "    evidence: %s\n", f.Evidence)
			}
		}
		for _, warning := range result.Coverage.Warnings {
			fmt.Fprintf(w, "  warning: %s\n", warning)
		}
		if len(result.Coverage.Skipped) > 0 {
			fmt.Fprintf(w, "  skipped areas: %d (use JSON for details)\n", len(result.Coverage.Skipped))
		}
		if result.Resolved != "" {
			fmt.Fprintf(w, "  retained checkout: %s\n", result.Resolved)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "NO FINDINGS does not guarantee that a repository is safe.")
	return nil
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
			rules[f.RuleID] = sarifRule{ID: f.RuleID, ShortDescription: sarifMessage{Text: f.Message}, Properties: map[string]string{"category": f.Category, "severity": string(f.Severity), "confidence": string(f.Confidence), "context": f.Context}}
			level := "warning"
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
				level = "error"
			} else if f.Severity == model.SeverityLow {
				level = "note"
			}
			loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.Path}}
			if f.Line > 0 {
				loc.Region = &sarifRegion{StartLine: f.Line}
			}
			results = append(results, sarifResult{RuleID: f.RuleID, Level: level, Message: sarifMessage{Text: f.Message}, Locations: []sarifLocation{{PhysicalLocation: loc}}, Fingerprints: map[string]string{"repyy/v1": f.Fingerprint}})
		}
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	doc := sarif{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "repyy", Version: report.ToolVersion, InformationURI: "https://github.com/Kevin-Umali/repyy", Rules: ruleList}}, Results: results, Invocations: []sarifInvocation{{ExecutionSuccessful: success}}}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
