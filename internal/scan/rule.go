package scan

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// Rule defines one declarative, non-executing content matcher.
type Rule struct {
	ID                    string            `yaml:"id" json:"id"`
	Category              string            `yaml:"category" json:"category"`
	Severity              model.Severity    `yaml:"severity" json:"severity"`
	Confidence            model.Confidence  `yaml:"confidence" json:"confidence"`
	Description           string            `yaml:"description" json:"description"`
	Pattern               string            `yaml:"pattern" json:"pattern"`
	Globs                 []string          `yaml:"globs,omitempty" json:"globs,omitempty"`
	Remediation           string            `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	Rationale             string            `yaml:"rationale,omitempty" json:"rationale,omitempty"`
	LegitimateUse         string            `yaml:"legitimate_use,omitempty" json:"legitimate_use,omitempty"`
	Disposition           model.Disposition `yaml:"disposition,omitempty" json:"disposition,omitempty"`
	MatchScope            string            `yaml:"match_scope,omitempty" json:"match_scope,omitempty"`
	AllowContextDowngrade *bool             `yaml:"allow_context_downgrade,omitempty" json:"allow_context_downgrade,omitempty"`
	re                    *regexp.Regexp
}

// Compile validates a rule and prepares its regular expression.
func (r *Rule) Compile() error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Category) == "" || strings.TrimSpace(r.Description) == "" {
		return fmt.Errorf("rule id, category, and description are required")
	}
	switch r.Severity {
	case model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical:
	default:
		return fmt.Errorf("rule %s has invalid severity %q", r.ID, r.Severity)
	}
	switch r.Confidence {
	case model.ConfidenceLow, model.ConfidenceMedium, model.ConfidenceHigh:
	default:
		return fmt.Errorf("rule %s has invalid confidence %q", r.ID, r.Confidence)
	}
	applyRuleDefaults(r)
	if r.MatchScope == "" {
		r.MatchScope = "raw"
	}
	switch r.MatchScope {
	case "raw", "code", "structured":
	default:
		return fmt.Errorf("rule %s has invalid match scope %q", r.ID, r.MatchScope)
	}
	if r.Disposition != "" {
		switch r.Disposition {
		case model.DispositionBlock, model.DispositionReview, model.DispositionHarden, model.DispositionInformational:
		default:
			return fmt.Errorf("rule %s has invalid disposition %q", r.ID, r.Disposition)
		}
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("rule %s: %w", r.ID, err)
	}
	r.re = re
	return nil
}

// Applies reports whether the rule's optional globs include path.
func (r Rule) Applies(path string) bool {
	if len(r.Globs) == 0 {
		return true
	}
	path = strings.ToLower(filepath.ToSlash(innerPath(path)))
	base := filepath.Base(path)
	for _, glob := range r.Globs {
		glob = strings.ToLower(filepath.ToSlash(glob))
		if ok, _ := filepath.Match(glob, base); ok {
			return true
		}
		if ok, _ := filepath.Match(glob, path); ok {
			return true
		}
		if strings.HasPrefix(glob, "**/") {
			if ok, _ := filepath.Match(strings.TrimPrefix(glob, "**/"), base); ok {
				return true
			}
		}
	}
	return false
}
