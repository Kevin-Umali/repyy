package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestLoadCustomRuleAndExpiringSuppression(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	body := `version: 1
rules:
  - id: LOCAL-001
    category: local
    severity: high
    confidence: high
    description: local marker
    pattern: "danger-marker"
    globs: ["*.txt"]
suppressions:
  - fingerprint: "sha256:abc"
    reason: reviewed
    expires: "2099-01-01"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 1 || !ActiveSuppressions(cfg, time.Now()).Covers(model.Finding{Fingerprint: "sha256:abc"}) {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Rules[0].MatchScope != "raw" {
		t.Fatalf("custom rules must default to raw matching, got %q", cfg.Rules[0].MatchScope)
	}
}

func TestRejectsStructuredCustomRule(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	body := "version: 1\nrules:\n  - id: LOCAL-001\n    category: local\n    severity: high\n    confidence: high\n    description: local marker\n    pattern: marker\n    match_scope: structured\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("structured custom rule should be rejected")
	}
}

func TestRejectsExecutableRuleConcepts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nrules:\n  - id: bad\n    category: x\n    severity: high\n    confidence: high\n    description: x\n    pattern: '[unterminated'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("invalid regex should be rejected")
	}
}

func loadConfig(t *testing.T, body string) (File, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "repyy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestRuleAndPathSuppressionSurvivesLineChanges(t *testing.T) {
	t.Parallel()
	cfg, err := loadConfig(t, `version: 1
suppressions:
  - rule: SECRET-001
    path: "tests/certs/**"
    reason: TLS test fixtures generated for the test suite
  - rule: EXEC-002
    path: scripts/release.js
    reason: release script runs git
`)
	if err != nil {
		t.Fatal(err)
	}
	active := ActiveSuppressions(cfg, time.Now())
	cases := []struct {
		finding model.Finding
		covered bool
	}{
		{model.Finding{RuleID: "SECRET-001", Path: "tests/certs/valid/server.key", Line: 1}, true},
		{model.Finding{RuleID: "SECRET-001", Path: "tests/certs/valid/server.key", Line: 40}, true},
		{model.Finding{RuleID: "SECRET-001", Path: "src/server.key"}, false},
		{model.Finding{RuleID: "SECRET-003", Path: "tests/certs/valid/server.key"}, false},
		{model.Finding{RuleID: "EXEC-002", Path: "scripts/release.js"}, true},
		{model.Finding{RuleID: "EXEC-002", Path: "scripts/release.jsx"}, false},
	}
	for _, tc := range cases {
		if got := active.Covers(tc.finding); got != tc.covered {
			t.Errorf("Covers(%s %s) = %v, want %v", tc.finding.RuleID, tc.finding.Path, got, tc.covered)
		}
	}
}

func TestSuppressionNeedsANarrowTarget(t *testing.T) {
	t.Parallel()
	for name, entry := range map[string]string{
		"rule without path":    "rule: EXEC-001",
		"path without rule":    "path: src/**",
		"no target":            "expires: \"2099-01-01\"",
		"fingerprint and rule": "fingerprint: sha256:abc\n    rule: EXEC-001\n    path: src/a.js",
		"malformed path glob":  "rule: EXEC-001\n    path: \"src/[\"",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfig(t, "version: 1\nsuppressions:\n  - reason: reviewed\n    "+entry+"\n"); err == nil {
				t.Fatal("expected the suppression to be rejected")
			}
		})
	}
}

func TestExpiredRuleSuppressionIsInactive(t *testing.T) {
	t.Parallel()
	cfg, err := loadConfig(t, "version: 1\nsuppressions:\n  - rule: EXEC-001\n    path: src/a.js\n    reason: reviewed\n    expires: \"2020-01-01\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if ActiveSuppressions(cfg, time.Now()).Covers(model.Finding{RuleID: "EXEC-001", Path: "src/a.js"}) {
		t.Fatal("expired suppression still applies")
	}
}
