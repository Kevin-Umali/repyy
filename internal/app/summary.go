package app

import (
	"sort"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// scanSummary is the compact, agent-facing view of one repository result shared
// by `repyy guard` and `repyy mcp`. The full report stays available through
// `repyy scan --format json`.
type scanSummary struct {
	Target           string           `json:"target"`
	Verdict          string           `json:"verdict"`
	CoverageComplete bool             `json:"coverage_complete"`
	FilesScanned     int              `json:"files_scanned"`
	SkippedPaths     int              `json:"skipped_paths,omitempty"`
	Warnings         []string         `json:"warnings,omitempty"`
	Error            string           `json:"error,omitempty"`
	Counts           severityCounts   `json:"counts"`
	FailOn           model.Severity   `json:"fail_on"`
	ExceedsFailOn    bool             `json:"exceeds_fail_on"`
	AtOrAboveFailOn  int              `json:"at_or_above_fail_on"`
	TopFindings      []findingSummary `json:"top_findings"`
	FindingsOmitted  int              `json:"findings_omitted,omitempty"`
}

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

type findingSummary struct {
	RuleID     string           `json:"rule_id"`
	Severity   model.Severity   `json:"severity"`
	Confidence model.Confidence `json:"confidence"`
	Context    string           `json:"context,omitempty"`
	Path       string           `json:"path"`
	Line       int              `json:"line,omitempty"`
	Message    string           `json:"message"`
}

func (s scanSummary) incomplete() bool {
	return !s.CoverageComplete || s.Error != "" || s.Verdict == model.VerdictIncomplete
}

func summarizeResult(result model.RepoResult, failOn model.Severity, limit int) scanSummary {
	summary := scanSummary{
		Target:           result.Target,
		Verdict:          result.Verdict,
		CoverageComplete: result.Coverage.Complete,
		FilesScanned:     result.Coverage.FilesScanned,
		SkippedPaths:     len(result.Coverage.Skipped),
		Warnings:         result.Coverage.Warnings,
		Error:            result.Error,
		FailOn:           failOn,
		TopFindings:      []findingSummary{},
	}
	findings := append([]model.Finding(nil), result.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		return findings[i].Confidence.Rank() > findings[j].Confidence.Rank()
	})
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			summary.Counts.Critical++
		case model.SeverityHigh:
			summary.Counts.High++
		case model.SeverityMedium:
			summary.Counts.Medium++
		default:
			summary.Counts.Low++
		}
		summary.Counts.Total++
		if f.Severity.Rank() >= failOn.Rank() {
			summary.AtOrAboveFailOn++
			summary.ExceedsFailOn = true
		}
		if len(summary.TopFindings) < limit {
			summary.TopFindings = append(summary.TopFindings, findingSummary{RuleID: f.RuleID, Severity: f.Severity, Confidence: f.Confidence, Context: f.Context, Path: f.Path, Line: f.Line, Message: f.Message})
		}
	}
	summary.FindingsOmitted = len(findings) - len(summary.TopFindings)
	return summary
}
