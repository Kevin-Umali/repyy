// Package config loads explicit, trusted rules and suppressions.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"gopkg.in/yaml.v3"
)

// Suppression disables reviewed findings with an auditable reason. It names either
// one finding fingerprint, or a rule and a path glob. A fingerprint includes the line,
// so a rule and path survive edits elsewhere in the file. A path ending in "/**"
// covers everything under that directory; any other path is a path.Match pattern.
type Suppression struct {
	Fingerprint string `yaml:"fingerprint,omitempty"`
	Rule        string `yaml:"rule,omitempty"`
	Path        string `yaml:"path,omitempty"`
	Reason      string `yaml:"reason"`
	Expires     string `yaml:"expires,omitempty"`
}

func (s Suppression) validate() error {
	switch {
	case s.Reason == "":
		return errors.New("every suppression needs a reason")
	case s.Fingerprint != "" && (s.Rule != "" || s.Path != ""):
		return errors.New("a suppression names a fingerprint or a rule and path, not both")
	case s.Fingerprint == "" && (s.Rule == "" || s.Path == ""):
		return errors.New("every suppression needs a fingerprint, or a rule and a path")
	}
	if _, err := path.Match(strings.TrimSuffix(s.Path, "/**"), ""); err != nil {
		return fmt.Errorf("invalid suppression path %q", s.Path)
	}
	if s.Expires != "" {
		if _, err := time.Parse("2006-01-02", s.Expires); err != nil {
			return fmt.Errorf("invalid suppression expiry %q", s.Expires)
		}
	}
	return nil
}

func (s Suppression) covers(f model.Finding) bool {
	if s.Fingerprint != "" {
		return s.Fingerprint == f.Fingerprint
	}
	if s.Rule != f.RuleID {
		return false
	}
	if dir, ok := strings.CutSuffix(s.Path, "/**"); ok {
		return strings.HasPrefix(f.Path, dir+"/")
	}
	matched, _ := path.Match(s.Path, f.Path)
	return matched
}

// Suppressions are the suppressions active at one point in time.
type Suppressions []Suppression

// Covers reports whether any active suppression covers the finding.
func (active Suppressions) Covers(f model.Finding) bool {
	for _, s := range active {
		if s.covers(f) {
			return true
		}
	}
	return false
}

// File is the trusted external configuration accepted by the CLI.
type File struct {
	Version      int           `yaml:"version"`
	Rules        []scan.Rule   `yaml:"rules,omitempty"`
	Suppressions []Suppression `yaml:"suppressions,omitempty"`
}

// Load reads and validates a trusted configuration file.
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var cfg File
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return File{}, err
	}
	if cfg.Version != 1 {
		return File{}, fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	for i := range cfg.Rules {
		if err := cfg.Rules[i].Compile(); err != nil {
			return File{}, err
		}
		if cfg.Rules[i].MatchScope == "structured" {
			return File{}, fmt.Errorf("custom rule %s cannot use structured match scope", cfg.Rules[i].ID)
		}
	}
	for _, s := range cfg.Suppressions {
		if err := s.validate(); err != nil {
			return File{}, err
		}
	}
	return cfg, nil
}

// ActiveSuppressions returns the suppressions that have not expired.
func ActiveSuppressions(cfg File, now time.Time) Suppressions {
	var active Suppressions
	for _, s := range cfg.Suppressions {
		if s.Expires != "" {
			expires, _ := time.Parse("2006-01-02", s.Expires)
			if now.After(expires.Add(24*time.Hour - time.Nanosecond)) {
				continue
			}
		}
		active = append(active, s)
	}
	return active
}
