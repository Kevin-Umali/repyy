package output

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
)

// SanitizeReport copies and redacts report content before human or machine display.
func SanitizeReport(report model.Report) model.Report {
	report.ToolVersion = sanitizeSourceText(report.ToolVersion)
	report.ToolCommit = sanitizeSourceText(report.ToolCommit)
	report.Limitation = model.Limitation
	report.RulesVersion = sanitizeSourceText(report.RulesVersion)
	report.Intelligence.Version = sanitizeSourceText(report.Intelligence.Version)
	report.Intelligence.Date = sanitizeSourceText(report.Intelligence.Date)
	report.Intelligence.Source = sanitizeSourceText(report.Intelligence.Source)
	report.Results = append([]model.RepoResult(nil), report.Results...)
	for resultIndex := range report.Results {
		result := &report.Results[resultIndex]
		result.ScanMode = model.ScanMode(sanitizeSourceText(string(result.ScanMode)))
		result.Target = sanitizeSourceText(result.Target)
		result.Resolved = sanitizeSourceText(result.Resolved)
		result.Verdict = sanitizeSourceText(result.Verdict)
		result.Error = sanitizeSourceText(result.Error)
		result.Coverage.Warnings = sanitizeSourceTexts(result.Coverage.Warnings)
		result.Coverage.Skipped = sanitizeSourceTexts(result.Coverage.Skipped)
		if result.Source != nil {
			source := *result.Source
			source.RepositoryURL = sanitizeSourceText(source.RepositoryURL)
			source.Revision = sanitizeSourceText(source.Revision)
			result.Source = &source
		}
		if result.Isolation != nil {
			isolation := *result.Isolation
			isolation.Backend = sanitizeSourceText(isolation.Backend)
			isolation.ImageDigest = sanitizeSourceText(isolation.ImageDigest)
			isolation.FetchNetwork = sanitizeSourceText(isolation.FetchNetwork)
			isolation.ScanNetwork = sanitizeSourceText(isolation.ScanNetwork)
			result.Isolation = &isolation
		}
		result.Findings = append([]model.Finding(nil), result.Findings...)
		for findingIndex := range result.Findings {
			finding := &result.Findings[findingIndex]
			scan.NormalizeFinding(finding)
			finding.RuleID = sanitizeSourceText(finding.RuleID)
			finding.Category = sanitizeSourceText(finding.Category)
			finding.Context = sanitizeSourceText(finding.Context)
			finding.Path = sanitizeSourceText(finding.Path)
			finding.Message = sanitizeSourceText(finding.Message)
			finding.Evidence = scan.SanitizeEvidence(finding.Evidence)
			finding.Remediation = sanitizeSourceText(finding.Remediation)
			finding.Fingerprint = sanitizeSourceText(finding.Fingerprint)
			finding.ContributingRuleIDs = sanitizeSourceTexts(finding.ContributingRuleIDs)
			finding.Locations = append([]model.Location(nil), finding.Locations...)
			for locationIndex := range finding.Locations {
				finding.Locations[locationIndex].Path = sanitizeSourceText(finding.Locations[locationIndex].Path)
				finding.Locations[locationIndex].Evidence = scan.SanitizeEvidence(finding.Locations[locationIndex].Evidence)
			}
		}
	}
	return report
}

// Source-derived strings can appear in fields that are not evidence, such as
// package script names, paths, targets, and backend errors. Keep their shape
// intact while applying the same credential patterns used for evidence.
func sanitizeSourceText(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, value)
	value = sourceSecretAssignmentRedactor.ReplaceAllString(value, "$1=[REDACTED]")
	for _, redactor := range sourceSecretRedactors {
		value = redactor.ReplaceAllString(value, "[REDACTED]")
	}
	return value
}

// SanitizeSourceText makes source-derived text safe for human-facing output
// written outside the report renderer, such as live scan progress.
func SanitizeSourceText(value string) string {
	return sanitizeSourceText(value)
}

func sanitizeSourceTexts(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = sanitizeSourceText(value)
	}
	return out
}

var sourceSecretAssignmentRedactor = regexp.MustCompile(`(?i)\b(token|password|secret|api[_-]?key|access[_-]?token|client[_-]?secret|_authToken|_password)\b\s*[=:]\s*(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,;]+)`)

var sourceSecretRedactors = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`sk_live_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{16,}`),
	regexp.MustCompile(`(?i)(?:https?|ssh)://[^/@\s]+@`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
}
