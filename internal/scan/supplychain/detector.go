// Package supplychain inspects package manifests, build configuration, and
// package-manager wrappers without resolving or executing dependencies.
package supplychain

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/manifest"
	"github.com/Kevin-Umali/repyy/internal/model"
)

// FindingFactory preserves the scanner's fingerprint and location conventions.
type FindingFactory func(id, category string, severity model.Severity, confidence model.Confidence, path string, line int, message, evidence, remediation string) model.Finding

// Detector uses the scanner's finding and evidence policies while keeping
// ecosystem-specific parsing in this package.
type Detector struct {
	newFinding     FindingFactory
	redactEvidence func([]byte) string
}

// New binds the supply-chain parsers to the scanner's finding policies.
func New(newFinding FindingFactory, redactEvidence func([]byte) string) Detector {
	return Detector{newFinding: newFinding, redactEvidence: redactEvidence}
}

func (d Detector) finding(id, category string, severity model.Severity, confidence model.Confidence, path string, line int, message, evidence, remediation string) model.Finding {
	return d.newFinding(id, category, severity, confidence, path, line, message, evidence, remediation)
}

func (d Detector) safeEvidence(value []byte) string {
	return d.redactEvidence(value)
}

func innerPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "!")
	return parts[len(parts)-1]
}

func lineForToken(data []byte, token string) int {
	return manifest.DeclarationLine(data, token)
}

func suspiciousCommand(value string) bool {
	lower := strings.ToLower(value)
	hasFetch := strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ") || strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
	hasExec := strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") || strings.Contains(lower, "eval") || strings.Contains(lower, "node -e") || strings.Contains(lower, "python -c") || strings.Contains(lower, "powershell")
	return hasFetch && hasExec || strings.Contains(lower, "base64") && hasExec
}

var windowsAbsPath = regexp.MustCompile(`(?i)^[a-z]:[\\/]`)
