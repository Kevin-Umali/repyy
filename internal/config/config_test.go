package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadCustomRuleAndExpiringSuppression(t *testing.T) {
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
	if len(cfg.Rules) != 1 || !ActiveSuppressions(cfg, time.Now())["sha256:abc"] {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestRejectsExecutableRuleConcepts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nrules:\n  - id: bad\n    category: x\n    severity: high\n    confidence: high\n    description: x\n    pattern: '[unterminated'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("invalid regex should be rejected")
	}
}
