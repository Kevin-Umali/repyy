// Package config loads explicit, trusted rules and suppressions.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/Kevin-Umali/repyy/internal/scan"
	"gopkg.in/yaml.v3"
)

// Suppression disables one stable finding fingerprint with an auditable reason.
type Suppression struct {
	Fingerprint string `yaml:"fingerprint"`
	Reason      string `yaml:"reason"`
	Expires     string `yaml:"expires,omitempty"`
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
	}
	for _, s := range cfg.Suppressions {
		if s.Fingerprint == "" || s.Reason == "" {
			return File{}, fmt.Errorf("every suppression needs fingerprint and reason")
		}
		if s.Expires != "" {
			if _, err := time.Parse("2006-01-02", s.Expires); err != nil {
				return File{}, fmt.Errorf("invalid suppression expiry %q", s.Expires)
			}
		}
	}
	return cfg, nil
}

// ActiveSuppressions returns unexpired suppression fingerprints.
func ActiveSuppressions(cfg File, now time.Time) map[string]bool {
	out := map[string]bool{}
	for _, s := range cfg.Suppressions {
		if s.Expires != "" {
			expires, _ := time.Parse("2006-01-02", s.Expires)
			if now.After(expires.Add(24*time.Hour - time.Nanosecond)) {
				continue
			}
		}
		out[s.Fingerprint] = true
	}
	return out
}
