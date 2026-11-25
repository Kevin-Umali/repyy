package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Kevin-Umali/repyy/internal/config"
	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"io"
	"sort"
	"strings"
	"time"
)

func runIntel(args []string, stdout io.Writer) (int, error) {
	store, err := intel.NewDefaultStore()
	if err != nil {
		return 2, err
	}
	if len(args) == 0 {
		return 3, errors.New("usage: repyy intel status [--format terminal|json] | update | rollback")
	}
	switch args[0] {
	case "status":
		format := "terminal"
		if len(args) == 3 && args[1] == "--format" {
			format = args[2]
		} else if len(args) != 1 {
			return 3, errors.New("usage: repyy intel status [--format terminal|json]")
		}
		status := store.Inspect(time.Now().UTC())
		if format == "json" {
			return encodeJSON(stdout, status)
		}
		if format != "terminal" {
			return 3, errors.New("--format must be terminal or json")
		}
		printIntelStatus(stdout, status)
		return 0, nil
	case "update":
		if len(args) != 1 {
			return 3, errors.New("usage: repyy intel update")
		}
		status, err := store.Update(context.Background(), time.Now().UTC())
		if err != nil {
			return 2, err
		}
		printIntelStatus(stdout, status)
		return 0, nil
	case "rollback":
		if len(args) != 1 {
			return 3, errors.New("usage: repyy intel rollback")
		}
		status, err := store.Rollback(time.Now().UTC())
		if err != nil {
			return 2, err
		}
		printIntelStatus(stdout, status)
		return 0, nil
	case "export":
		if len(args) != 1 {
			return 3, errors.New("usage: repyy intel export")
		}
		return encodeJSON(stdout, intel.BuiltinSnapshot())
	default:
		return 3, fmt.Errorf("unknown intel command %q", args[0])
	}
}

func encodeJSON(stdout io.Writer, value any) (int, error) {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return 2, err
	}
	return 0, nil
}

func printIntelStatus(stdout io.Writer, status intel.Status) {
	freshness := "current"
	if status.Stale {
		freshness = "stale"
	}
	fmt.Fprintf(stdout, "intelligence %s (%s) — %s, %s, verified; %d packages, %d hashes\n", status.SnapshotVersion, status.SnapshotDate, status.Source, freshness, status.Packages, status.FileHashes)
	if status.Warning != "" {
		fmt.Fprintf(stdout, "warning: %s\n", status.Warning)
	}
}

func runRules(args []string, stdout io.Writer) (int, error) {
	if len(args) >= 1 && args[0] == "catalog" {
		format := "terminal"
		if len(args) == 3 && args[1] == "--format" {
			format = args[2]
		} else if len(args) != 1 {
			return 3, errors.New("usage: repyy rules catalog [--format terminal|json]")
		}
		catalog := scan.BuiltinRuleCatalogDocument()
		if format == "json" {
			return encodeJSON(stdout, catalog)
		}
		if format != "terminal" {
			return 3, errors.New("--format must be terminal or json")
		}
		fmt.Fprintf(stdout, "Behavioral ruleset %s (%d rules)\n", catalog.RulesVersion, len(catalog.Rules))
		for _, rule := range catalog.Rules {
			fmt.Fprintf(stdout, "%-18s %-28s %s\n", rule.ID, rule.Category, rule.Description)
		}
		return 0, nil
	}
	if len(args) >= 1 && args[0] == "explain" {
		if len(args) < 2 {
			return 3, errors.New("usage: repyy rules explain <rule-id> [--format terminal|json]")
		}
		id, format := args[1], "terminal"
		if len(args) == 4 && args[2] == "--format" {
			format = args[3]
		} else if len(args) != 2 {
			return 3, errors.New("usage: repyy rules explain <rule-id> [--format terminal|json]")
		}
		info, code, err := explainRule(id)
		if err != nil {
			return code, err
		}
		if format == "json" {
			return encodeJSON(stdout, info)
		}
		if format != "terminal" {
			return 3, errors.New("--format must be terminal or json")
		}
		fmt.Fprintf(stdout, "%s — %s\n\nseverity: %s\nconfidence: %s\ndisposition: %s\ncategory: %s\nmatch scope: %s\npaths: %s\n\nWhy it matters\n  %s\n\nCommon legitimate use\n  %s\n\nRecommended action\n  %s\n", info.ID, info.Description, info.Severity, info.Confidence, info.Disposition, info.Category, info.MatchScope, strings.Join(info.ApplicablePaths, ", "), info.Rationale, info.LegitimateUse, info.Remediation)
		return 0, nil
	}
	if len(args) >= 1 && args[0] == "list" {
		format := "terminal"
		if len(args) == 3 && args[1] == "--format" {
			format = args[2]
		} else if len(args) != 1 {
			return 3, errors.New("usage: repyy rules list [--format terminal|json]")
		}
		store, err := intel.NewDefaultStore()
		if err != nil {
			return 2, err
		}
		snapshot, status := store.LoadActiveSnapshot(time.Now().UTC())
		packages := append([]intel.Package(nil), snapshot.Packages...)
		sort.Slice(packages, func(i, j int) bool {
			if packages[i].Ecosystem != packages[j].Ecosystem {
				return packages[i].Ecosystem < packages[j].Ecosystem
			}
			return strings.ToLower(packages[i].Name) < strings.ToLower(packages[j].Name)
		})
		if format == "json" {
			payload := struct {
				SnapshotVersion string           `json:"snapshot_version"`
				SnapshotDate    string           `json:"snapshot_date"`
				Stale           bool             `json:"stale"`
				Packages        []intel.Package  `json:"packages"`
				FileHashes      []intel.FileHash `json:"file_hashes"`
			}{snapshot.SnapshotVersion, snapshot.SnapshotDate, status.Stale, packages, snapshot.FileHashes}
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(payload); err != nil {
				return 3, err
			}
			return 0, nil
		}
		if format != "terminal" {
			return 3, fmt.Errorf("unsupported format %q; use terminal or json", format)
		}
		fmt.Fprintf(stdout, "Intelligence snapshot %s (%s, %s) — %d packages, %d file hashes\n\n", snapshot.SnapshotVersion, snapshot.SnapshotDate, status.Source, len(packages), len(snapshot.FileHashes))
		for _, p := range packages {
			affected := "review resolved version"
			if len(p.Affected) > 0 {
				affected = strings.Join(p.Affected, ", ")
			}
			fmt.Fprintf(stdout, "%-10s %-34s %-25s %s\n  %s\n  affected: %s\n  source: %s\n", p.Ecosystem, p.Name, p.AdvisoryID, p.Severity, p.Description, affected, p.SourceURL)
		}
		return 0, nil
	}
	if len(args) == 1 && args[0] == "check" {
		store, err := intel.NewDefaultStore()
		if err != nil {
			return 2, err
		}
		status := store.Inspect(time.Now().UTC())
		freshness := "current"
		if status.Stale {
			freshness = "stale; run 'repyy intel update' before relying on package-name IOCs"
		}
		fmt.Fprintf(stdout, "embedded ruleset %s; intelligence %s (%s, %s, %d packages, %d hashes); automatic network updates are disabled\n", scan.BuiltinRulesVersion, status.SnapshotVersion, status.Source, freshness, status.Packages, status.FileHashes)
		return 0, nil
	}
	if len(args) == 2 && args[0] == "validate" {
		cfg, err := config.Load(args[1])
		if err != nil {
			return 3, err
		}
		fmt.Fprintf(stdout, "valid config: %d custom rules, %d suppressions\n", len(cfg.Rules), len(cfg.Suppressions))
		return 0, nil
	}
	return 3, errors.New("usage: repyy rules validate <rules.yaml> | check | list [--format terminal|json] | explain <rule-id> [--format terminal|json]")
}

// explainRule returns the catalog entry for a rule ID, enriched with the active
// intelligence snapshot for package indicators, and the CLI exit code on error.
func explainRule(id string) (scan.RuleInfo, int, error) {
	info, ok := scan.LookupRuleInfo(id)
	if !ok {
		return scan.RuleInfo{}, 3, fmt.Errorf("unknown rule %q", id)
	}
	if strings.HasPrefix(id, "IOC-PKG-") {
		store, err := intel.NewDefaultStore()
		if err != nil {
			return scan.RuleInfo{}, 2, err
		}
		snapshot, _ := store.LoadActiveSnapshot(time.Now().UTC())
		advisoryID := strings.TrimPrefix(id, "IOC-PKG-")
		for _, record := range snapshot.Packages {
			if record.AdvisoryID != advisoryID {
				continue
			}
			if record.Description != "" {
				info.Description = record.Description
			}
			info.Rationale = fmt.Sprintf("The active offline intelligence snapshot attributes %s in %s to advisory %s from %s.", record.Name, record.Ecosystem, record.AdvisoryID, record.Source)
			if len(record.Affected) > 0 {
				info.LegitimateUse = "Only the sourced affected versions are confirmed; other versions still require package-identity review."
			} else {
				info.LegitimateUse = "The package name is a review signal until the resolved version and artifact are verified."
			}
			info.Remediation = "Do not install the package until the advisory and resolved artifact are reviewed: " + record.SourceURL
			break
		}
	}
	return info, 0, nil
}
