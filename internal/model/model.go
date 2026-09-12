// Package model defines repyy's stable report-domain types.
package model

import "time"

// Severity expresses the potential impact of a finding.
type Severity string

// Supported finding severities, ordered from low to critical.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank returns the ordering used for sorting and threshold decisions.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	default:
		return 1
	}
}

// Confidence expresses how strongly the observed evidence supports a finding.
type Confidence string

// Supported confidence levels.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Finding is one deduplicated piece of scan evidence and its remediation.
type Finding struct {
	RuleID      string     `json:"rule_id" yaml:"rule_id"`
	Category    string     `json:"category" yaml:"category"`
	Severity    Severity   `json:"severity" yaml:"severity"`
	Confidence  Confidence `json:"confidence" yaml:"confidence"`
	Context     string     `json:"context" yaml:"context"`
	Path        string     `json:"path" yaml:"path"`
	Line        int        `json:"line,omitempty" yaml:"line,omitempty"`
	Occurrences int        `json:"occurrences" yaml:"occurrences"`
	Message     string     `json:"message" yaml:"message"`
	Evidence    string     `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation string     `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Fingerprint string     `json:"fingerprint" yaml:"fingerprint"`
}

// Coverage records what a scan inspected and where its visibility was incomplete.
type Coverage struct {
	Complete     bool     `json:"complete"`
	FilesScanned int      `json:"files_scanned"`
	BytesScanned int64    `json:"bytes_scanned"`
	Skipped      []string `json:"skipped,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// RepoResult contains the verdict and evidence for one requested repository.
type RepoResult struct {
	Target   string        `json:"target"`
	Resolved string        `json:"resolved,omitempty"`
	Verdict  string        `json:"verdict"`
	Findings []Finding     `json:"findings"`
	Coverage Coverage      `json:"coverage"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

// Report is the stable top-level document emitted by JSON and SARIF workflows.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	ToolVersion   string       `json:"tool_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Results       []RepoResult `json:"results"`
}

// Repository verdicts summarize findings without claiming that code is safe.
const (
	VerdictNoFindings = "NO FINDINGS"
	VerdictReview     = "REVIEW REQUIRED"
	VerdictDoNotRun   = "DO NOT RUN"
	VerdictIncomplete = "SCAN INCOMPLETE"
)
