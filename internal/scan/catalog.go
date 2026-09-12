package scan

import (
	"sort"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// RuleInfo is the review-facing metadata shared by terminal and HTML reports.
type RuleInfo struct {
	ID                    string            `json:"id"`
	Category              string            `json:"category"`
	Severity              model.Severity    `json:"severity"`
	Confidence            model.Confidence  `json:"confidence"`
	Disposition           model.Disposition `json:"disposition"`
	Description           string            `json:"description"`
	Rationale             string            `json:"rationale"`
	LegitimateUse         string            `json:"legitimate_use"`
	Remediation           string            `json:"remediation"`
	MatchScope            string            `json:"match_scope"`
	ApplicablePaths       []string          `json:"applicable_paths"`
	AllowContextDowngrade bool              `json:"allow_context_downgrade"`
}

func applyRuleDefaults(rule *Rule) {
	if rule.MatchScope == "" && codeScopedRule(rule.ID) {
		rule.MatchScope = "code"
	}
	if rule.MatchScope == "" {
		rule.MatchScope = "raw"
	}
	if rule.Rationale == "" {
		rule.Rationale = categoryRationale(rule.Category)
	}
	if rule.LegitimateUse == "" {
		rule.LegitimateUse = categoryLegitimateUse(rule.Category)
	}
	if rule.Disposition == "" {
		rule.Disposition = defaultRuleDisposition(rule.ID, rule.Category, rule.Severity, rule.Confidence)
	}
	if rule.AllowContextDowngrade == nil {
		value := !strings.HasPrefix(rule.ID, "IOC-") && !strings.HasPrefix(rule.ID, "SECRET-")
		rule.AllowContextDowngrade = &value
	}
}

func codeScopedRule(id string) bool {
	switch id {
	case "EXEC-001", "EXEC-002", "BACKDOOR-001", "IMPORT-001", "IMPORT-003", "PROTO-001", "ENV-001", "FINGERPRINT-001", "UNSERIALIZE-001", "PATH-001":
		return true
	default:
		return false
	}
}

func defaultRuleDisposition(id, category string, severity model.Severity, confidence model.Confidence) model.Disposition {
	if id == "CICD-003" || strings.HasPrefix(id, "REPO-") || category == "repository-hygiene" {
		return model.DispositionHarden
	}
	if severity == model.SeverityLow || confidence == model.ConfidenceLow || category == "process-capability" {
		return model.DispositionInformational
	}
	if severity == model.SeverityCritical && confidence == model.ConfidenceHigh {
		return model.DispositionBlock
	}
	return model.DispositionReview
}

func categoryRationale(category string) string {
	return "This rule identifies " + strings.ReplaceAll(category, "-", " ") + " behavior that can affect repository trust or execution safety."
}

func categoryLegitimateUse(category string) string {
	switch category {
	case "process-execution", "process-capability":
		return "Build, test, and development tooling often starts reviewed local processes."
	case "environment-access":
		return "Applications commonly read explicitly named configuration variables."
	case "ci-workflow-integrity":
		return "Version tags are common and convenient, but they are not immutable."
	case "repository-hygiene":
		return "Private or early-stage repositories may intentionally omit public documentation."
	case "remote-fetch":
		return "Installers and update tools may retrieve content from reviewed, pinned sources."
	case "dynamic-execution":
		return "Frameworks and developer tools sometimes evaluate generated or sandboxed code."
	default:
		return "The behavior may be legitimate when its inputs, destination, and execution context are understood."
	}
}

// BuiltinRuleCatalog returns complete metadata for behavioral and structured
// rule families. Dynamic package-advisory IDs use the IOC-PKG-* fallback.
func BuiltinRuleCatalog() []RuleInfo {
	items := make([]RuleInfo, 0)
	seen := map[string]bool{}
	for _, rule := range BuiltinRules() {
		items = append(items, infoFromRule(rule))
		seen[rule.ID] = true
	}
	for _, item := range structuredRuleCatalog() {
		if !seen[item.ID] {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func infoFromRule(rule Rule) RuleInfo {
	allow := true
	if rule.AllowContextDowngrade != nil {
		allow = *rule.AllowContextDowngrade
	}
	paths := append([]string(nil), rule.Globs...)
	if len(paths) == 0 {
		paths = []string{"**"}
	}
	return RuleInfo{
		ID: rule.ID, Category: rule.Category, Severity: rule.Severity,
		Confidence: rule.Confidence, Disposition: rule.Disposition,
		Description: rule.Description, Rationale: rule.Rationale,
		LegitimateUse: rule.LegitimateUse, Remediation: rule.Remediation,
		MatchScope: rule.MatchScope, ApplicablePaths: paths, AllowContextDowngrade: allow,
	}
}

func structuredRuleCatalog() []RuleInfo {
	type entry struct {
		id, category, description, remediation string
		severity                               model.Severity
		confidence                             model.Confidence
	}
	entries := []entry{
		{"ARCHIVE-001", "archive-traversal", "Archive entry escapes its extraction root", "Do not extract the archive.", model.SeverityCritical, model.ConfidenceHigh},
		{"BINARY-001", "compiled-binary", "Compiled executable content is present", "Verify the binary provenance and hash before use.", model.SeverityHigh, model.ConfidenceHigh},
		{"COMBO-001", "collection-and-exfiltration", "Collection appears alongside network transfer", "Verify the collected data and destination before running the repository.", model.SeverityHigh, model.ConfidenceHigh},
		{"COMBO-002", "fetch-and-execute", "Network retrieval appears alongside execution", "Do not run until the fetched content and execution path are verified.", model.SeverityCritical, model.ConfidenceHigh},
		{"COMBO-003", "evasion-and-execution", "Environment evasion appears alongside execution", "Verify the environment checks and execution path.", model.SeverityHigh, model.ConfidenceHigh},
		{"EXECBIT-001", "executable-file", "File has executable permissions", "Review whether this file needs to be executable.", model.SeverityLow, model.ConfidenceMedium},
		{"GITHOOK-002", "git-hook", "Active Git hook contains execution or remote-fetch behavior", "Disable the hook and review it before running Git commands.", model.SeverityCritical, model.ConfidenceHigh},
		{"IOC-HASH-SHA256", "known-malicious-file", "File hash matches confirmed intelligence", "Isolate the file and follow incident-response procedures.", model.SeverityCritical, model.ConfidenceHigh},
		{"IOC-PKG-*", "known-malicious-package", "Package declaration matches confirmed intelligence", "Review the advisory and resolved package before installation.", model.SeverityCritical, model.ConfidenceHigh},
		{"OBFS-004", "minified-or-obfuscated", "Very long single line", "Review generated or minified content and its provenance.", model.SeverityLow, model.ConfidenceLow},
		{"OBFS-005", "high-entropy-code", "High-entropy content appears beside execution", "Decode and inspect the content in an isolated environment.", model.SeverityMedium, model.ConfidenceMedium},
		{"PKG-001", "package-lifecycle", "Package lifecycle script is present", "Review the script before installing dependencies.", model.SeverityMedium, model.ConfidenceMedium},
		{"PKG-002", "suspicious-dependency-source", "Dependency uses a non-registry source", "Verify and pin the dependency source.", model.SeverityHigh, model.ConfidenceMedium},
		{"PKG-003", "suspicious-dependency-version", "Dependency uses a placeholder-like version", "Verify the package name and version.", model.SeverityMedium, model.ConfidenceMedium},
		{"PKG-004", "package-binary", "Package exposes an executable command", "Inspect the executable before installing globally.", model.SeverityLow, model.ConfidenceMedium},
		{"PKG-005", "dependency-confusion", "Dependency uses an unusually high major version", "Verify registry ownership and the resolved artifact.", model.SeverityMedium, model.ConfidenceMedium},
		{"PKG-006", "package-binary", "Package binary target escapes the package or embeds execution", "Constrain the target to a reviewed local file.", model.SeverityHigh, model.ConfidenceHigh},
		{"PKG-007", "package-script", "Package script downloads and executes content", "Review the script before running package-manager commands.", model.SeverityHigh, model.ConfidenceMedium},
		{"REPO-001", "repository-hygiene", "Repository has no top-level README", "Ask the owner for setup and provenance documentation.", model.SeverityLow, model.ConfidenceHigh},
		{"REPO-002", "repository-hygiene", "Repository has no top-level license", "Clarify the code origin and permitted use.", model.SeverityLow, model.ConfidenceHigh},
		{"SYMLINK-001", "escaping-symlink", "Symbolic link escapes the repository", "Remove or replace the escaping link.", model.SeverityHigh, model.ConfidenceHigh},
		{"SYMLINK-002", "broken-symlink", "Symbolic link target is unavailable", "Review the link target and packaging.", model.SeverityMedium, model.ConfidenceMedium},
	}
	items := make([]RuleInfo, 0, len(entries))
	for _, value := range entries {
		items = append(items, RuleInfo{
			ID: value.id, Category: value.category, Severity: value.severity, Confidence: value.confidence,
			Disposition: defaultRuleDisposition(value.id, value.category, value.severity, value.confidence),
			Description: value.description, Rationale: categoryRationale(value.category),
			LegitimateUse: categoryLegitimateUse(value.category), Remediation: value.remediation,
			MatchScope: "structured", ApplicablePaths: structuredApplicablePaths(value.id), AllowContextDowngrade: !strings.HasPrefix(value.id, "IOC-"),
		})
	}
	return items
}

func structuredApplicablePaths(id string) []string {
	switch {
	case strings.HasPrefix(id, "PKG-"), id == "IOC-PKG-*":
		return []string{"package.json and supported dependency manifests"}
	case strings.HasPrefix(id, "REPO-"):
		return []string{"repository root"}
	case strings.HasPrefix(id, "COMBO-"):
		return []string{"executable source files"}
	case id == "ARCHIVE-001":
		return []string{"archive entries"}
	case id == "GITHOOK-002":
		return []string{".git/hooks/*"}
	default:
		return []string{"**"}
	}
}

// LookupRuleInfo resolves a concrete rule ID, including dynamic package IOCs.
func LookupRuleInfo(id string) (RuleInfo, bool) {
	lookup := id
	if strings.HasPrefix(id, "IOC-PKG-") {
		lookup = "IOC-PKG-*"
	}
	for _, item := range BuiltinRuleCatalog() {
		if item.ID == lookup {
			if lookup != id {
				item.ID = id
			}
			return item, true
		}
	}
	return RuleInfo{}, false
}

// NormalizeFinding fills additive review fields when reading a legacy report.
func NormalizeFinding(f *model.Finding) {
	if len(f.Locations) == 0 && f.Path != "" {
		f.Locations = []model.Location{{Path: f.Path, StartLine: f.Line, Evidence: f.Evidence}}
	}
	if f.Occurrences == 0 {
		f.Occurrences = len(f.Locations)
		if f.Occurrences == 0 {
			f.Occurrences = 1
		}
	}
	if detailed := len(f.Locations) + f.LocationsOmitted; f.Occurrences < detailed {
		f.Occurrences = detailed
	}
	if len(f.Locations) > 0 {
		f.Path = f.Locations[0].Path
		f.Line = f.Locations[0].StartLine
		f.Evidence = f.Locations[0].Evidence
	}
	if f.Disposition == "" {
		f.Disposition = dispositionForFinding(*f)
	}
}

// SanitizeEvidence applies the same redaction and UTF-8-safe truncation used
// while scanning. Report conversion calls it again so legacy inputs cannot
// bypass current presentation safeguards.
func SanitizeEvidence(value string) string {
	return safeEvidence([]byte(value))
}

func dispositionForFinding(f model.Finding) model.Disposition {
	if f.Severity == model.SeverityCritical && f.Confidence == model.ConfidenceHigh && (f.Context == "executable" || f.Context == "manifest-hook" || f.Context == "ci-workflow" || f.Context == "confirmed-ioc") {
		return model.DispositionBlock
	}
	if f.RuleID == "CICD-003" || strings.HasPrefix(f.RuleID, "REPO-") || f.Category == "repository-hygiene" {
		return model.DispositionHarden
	}
	switch f.Context {
	case "documentation", "example", "test-fixture", "evidence", "generated", "dependency", "detection-definition", "metadata":
		return model.DispositionInformational
	}
	if f.Severity == model.SeverityLow || f.Confidence == model.ConfidenceLow || f.Category == "process-capability" {
		return model.DispositionInformational
	}
	return model.DispositionReview
}
