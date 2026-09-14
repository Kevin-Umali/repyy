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

// Rank returns the ordering used by presentation filters.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

// Disposition describes the review action suggested by a finding. It is a
// presentation hint and does not participate in verdict or exit-code policy.
type Disposition string

// Supported finding dispositions, ordered from informational to blocking.
const (
	DispositionInformational Disposition = "informational"
	DispositionHarden        Disposition = "harden"
	DispositionReview        Disposition = "review"
	DispositionBlock         Disposition = "block"
)

// Rank returns the ordering used when presenting findings to a reviewer.
func (d Disposition) Rank() int {
	switch d {
	case DispositionBlock:
		return 4
	case DispositionReview:
		return 3
	case DispositionHarden:
		return 2
	default:
		return 1
	}
}

// Location identifies one occurrence of a finding. Evidence contains only the
// redacted matched text, never an unredacted source excerpt.
type Location struct {
	Path      string `json:"path" yaml:"path"`
	StartLine int    `json:"start_line,omitempty" yaml:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty" yaml:"end_line,omitempty"`
	Evidence  string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// Report location limits bound review detail while occurrence totals continue
// to describe all matches.
const (
	MaxLocationsPerFinding = 1_000
	MaxLocationsPerRepo    = 25_000
)

// Finding is one deduplicated piece of scan evidence and its remediation.
type Finding struct {
	RuleID              string      `json:"rule_id" yaml:"rule_id"`
	Category            string      `json:"category" yaml:"category"`
	Severity            Severity    `json:"severity" yaml:"severity"`
	Confidence          Confidence  `json:"confidence" yaml:"confidence"`
	Context             string      `json:"context" yaml:"context"`
	Path                string      `json:"path" yaml:"path"`
	Line                int         `json:"line,omitempty" yaml:"line,omitempty"`
	Occurrences         int         `json:"occurrences" yaml:"occurrences"`
	Message             string      `json:"message" yaml:"message"`
	Evidence            string      `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation         string      `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Fingerprint         string      `json:"fingerprint" yaml:"fingerprint"`
	Disposition         Disposition `json:"disposition,omitempty" yaml:"disposition,omitempty"`
	Locations           []Location  `json:"locations,omitempty" yaml:"locations,omitempty"`
	LocationsOmitted    int         `json:"locations_omitted,omitempty" yaml:"locations_omitted,omitempty"`
	ContributingRuleIDs []string    `json:"contributing_rule_ids,omitempty" yaml:"contributing_rule_ids,omitempty"`
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
	Target    string         `json:"target"`
	Resolved  string         `json:"resolved,omitempty"`
	Verdict   string         `json:"verdict"`
	Findings  []Finding      `json:"findings"`
	Coverage  Coverage       `json:"coverage"`
	Error     string         `json:"error,omitempty"`
	Duration  time.Duration  `json:"duration_ns"`
	Source    *SourceInfo    `json:"source,omitempty"`
	Isolation *IsolationInfo `json:"isolation,omitempty"`
}

// IsolationInfo records the execution boundary used for a repository scan.
// Network values are deliberately descriptive and stable for report readers.
type IsolationInfo struct {
	Backend      string `json:"backend"`
	ImageDigest  string `json:"image_digest,omitempty"`
	FetchNetwork string `json:"fetch_network"`
	ScanNetwork  string `json:"scan_network"`
}

// SourceInfo identifies a remote repository revision used for stable source
// links. It is omitted for local targets.
type SourceInfo struct {
	RepositoryURL string `json:"repository_url"`
	Revision      string `json:"revision"`
}

// IntelligenceInfo identifies the verified snapshot used for a scan.
type IntelligenceInfo struct {
	Version string `json:"version"`
	Date    string `json:"date"`
	Source  string `json:"source"`
}

// Report is the stable top-level document emitted by JSON and SARIF workflows.
type Report struct {
	SchemaVersion string           `json:"schema_version"`
	ToolCommit    string           `json:"tool_commit,omitempty"`
	Limitation    string           `json:"limitation,omitempty"`
	ToolVersion   string           `json:"tool_version"`
	RulesVersion  string           `json:"rules_version"`
	Intelligence  IntelligenceInfo `json:"intelligence"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Results       []RepoResult     `json:"results"`
}

// Repository verdicts summarize findings without claiming that code is safe.
const (
	VerdictNoFindings = "NO FINDINGS"
	VerdictReview     = "REVIEW REQUIRED"
	VerdictDoNotRun   = "DO NOT RUN"
	VerdictIncomplete = "SCAN INCOMPLETE"
)

// DecisionStatus presents an overall result without changing schema-1 verdict values.
func (r RepoResult) DecisionStatus() string {
	if !r.Coverage.Complete || r.Error != "" || r.Verdict == VerdictIncomplete {
		return "SCAN INCOMPLETE"
	}
	switch r.Verdict {
	case VerdictNoFindings:
		return "NO RELEVANT FINDINGS DETECTED"
	case VerdictDoNotRun:
		return "FINDINGS DETECTED"
	default:
		return "REVIEW REQUIRED"
	}
}

// Limitation accompanies overall results in every report format.
const Limitation = "Repyy performs static analysis. A result with no relevant findings does not prove that the repository is safe."
