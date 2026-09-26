// Package app implements repyy's command-line orchestration and exit policy.
package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kevin-Umali/repyy/internal/buildinfo"
	"github.com/Kevin-Umali/repyy/internal/config"
	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
	"github.com/Kevin-Umali/repyy/internal/sandbox"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"github.com/Kevin-Umali/repyy/internal/source"
)

const usage = `repyy — inspect unfamiliar repositories without running them

Usage:
  repyy scan [options] <path-or-git-url>...
  repyy report [options] <report.json|->
  repyy rules validate <rules.yaml>
  repyy rules check
  repyy rules list [--format terminal|json]
  repyy rules catalog [--format terminal|json]
  repyy rules explain <rule-id> [--format terminal|json]
  repyy intel status [--format terminal|json]
  repyy intel update
  repyy intel rollback
  repyy version

Scan options:
  --file PATH              read additional targets, one per line
  --format terminal|json|sarif|html
  --output PATH            write the report to a file
  --jobs N                 concurrent repositories (default 4)
  --config PATH            trusted external config/rules/suppressions
  --include-dependencies   include dependency and cache directories
  --history N|all          remote Git history depth (default 1)
  --keep-workdir           retain remote checkouts after scanning
  --fail-on LEVEL          low|medium|high|critical (default high)
  --timeout DURATION       per-repository timeout (default 10m)
  --max-files N            maximum files per repository
  --max-file-size BYTES    maximum bytes per file
  --detail summary|review|all
  --progress auto|plain|quiet
  --color auto|always|never
  --min-severity LEVEL     display filter only
  --min-confidence LEVEL   low|medium|high display filter only
  --group-by severity|file|rule
  --sandbox host|docker       run scans in Docker (default host)

Report options:
  --format terminal|html|sarif (default html)
  --output PATH
  --detail summary|review|all
  --color auto|always|never
`

// Run executes the CLI command and returns its documented process exit code.
func Run(args []string, stdout, stderr io.Writer, version string) (int, error) {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 3, nil
	}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0, nil
	case "version", "--version":
		buildinfo.Write(stdout, version, scan.BuiltinRulesVersion)
		return 0, nil
	case "rules":
		return runRules(args[1:], stdout)
	case "report":
		return runReport(args[1:], stdout)
	case "intel":
		return runIntel(args[1:], stdout)
	case "scan":
		return runScan(args[1:], stdout, stderr, version)
	default:
		return 3, fmt.Errorf("unknown command %q; use 'repyy help'", args[0])
	}
}

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
		info, ok := scan.LookupRuleInfo(id)
		if !ok {
			return 3, fmt.Errorf("unknown rule %q", id)
		}
		if strings.HasPrefix(id, "IOC-PKG-") {
			store, err := intel.NewDefaultStore()
			if err != nil {
				return 2, err
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

const maxReportInputBytes = 64 << 20

type reportArgs struct {
	input, format, output, detail, color, minSeverity, minConfidence, groupBy string
}

func runReport(args []string, stdout io.Writer) (int, error) {
	opts := reportArgs{format: "html", detail: "review", color: "auto", minSeverity: "low", minConfidence: "low", groupBy: "severity"}
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.format, "format", opts.format, "")
	fs.StringVar(&opts.output, "output", "", "")
	fs.StringVar(&opts.detail, "detail", opts.detail, "")
	fs.StringVar(&opts.color, "color", opts.color, "")
	fs.StringVar(&opts.minSeverity, "min-severity", opts.minSeverity, "")
	fs.StringVar(&opts.minConfidence, "min-confidence", opts.minConfidence, "")
	fs.StringVar(&opts.groupBy, "group-by", opts.groupBy, "")
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if argument == "-" || !strings.HasPrefix(argument, "-") {
			if opts.input != "" {
				return 3, errors.New("repyy report accepts exactly one input")
			}
			opts.input = argument
			continue
		}
		flagArgs = append(flagArgs, argument)
		if strings.Contains(argument, "=") {
			continue
		}
		if i+1 >= len(args) {
			return 3, fmt.Errorf("missing value for %s", argument)
		}
		i++
		flagArgs = append(flagArgs, args[i])
	}
	if err := fs.Parse(flagArgs); err != nil {
		return 3, err
	}
	if opts.input == "" {
		return 3, errors.New("usage: repyy report [options] <report.json|->")
	}
	if opts.format != "terminal" && opts.format != "html" && opts.format != "sarif" {
		return 3, errors.New("--format must be terminal, html, or sarif")
	}
	if opts.detail != "summary" && opts.detail != "review" && opts.detail != "all" {
		return 3, errors.New("--detail must be summary, review, or all")
	}
	if opts.color != "auto" && opts.color != "always" && opts.color != "never" {
		return 3, errors.New("--color must be auto, always, or never")
	}
	if opts.groupBy != "severity" && opts.groupBy != "file" && opts.groupBy != "rule" {
		return 3, errors.New("--group-by must be severity, file, or rule")
	}

	var reader io.Reader
	var inputFile *os.File
	if opts.input == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(opts.input)
		if err != nil {
			return 3, err
		}
		inputFile = file
		defer inputFile.Close()
		reader = inputFile
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxReportInputBytes+1))
	if err != nil {
		return 3, err
	}
	if len(data) > maxReportInputBytes {
		return 3, fmt.Errorf("report input exceeds %d MiB", maxReportInputBytes>>20)
	}
	var report model.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return 3, fmt.Errorf("invalid report JSON: %w", err)
	}
	if err := normalizeAndValidateReport(&report); err != nil {
		return 3, err
	}

	presentation, err := presentationOptions(opts.detail, opts.minSeverity, opts.minConfidence, opts.groupBy, opts.color, stdout)
	if err != nil {
		return 3, err
	}
	if err := writeReportOutput(stdout, opts.output, opts.format, report, presentation); err != nil {
		return 3, err
	}
	return exitCodeForResults(report.Results, model.SeverityHigh), nil
}

func normalizeAndValidateReport(report *model.Report) error {
	if report.SchemaVersion != "1" {
		return fmt.Errorf("unsupported report schema %q", report.SchemaVersion)
	}
	for resultIndex := range report.Results {
		result := &report.Results[resultIndex]
		switch result.ScanMode {
		case "", model.ScanModeHost, model.ScanModeDocker:
		default:
			return fmt.Errorf("result %d has invalid scan mode %q", resultIndex, result.ScanMode)
		}
		locationsStored := 0
		locationsTruncated := false
		switch result.Verdict {
		case model.VerdictNoFindings, model.VerdictReview, model.VerdictDoNotRun, model.VerdictIncomplete:
		default:
			return fmt.Errorf("result %d has invalid verdict %q", resultIndex, result.Verdict)
		}
		for findingIndex := range result.Findings {
			finding := &result.Findings[findingIndex]
			if finding.RuleID == "" || finding.Path == "" {
				return fmt.Errorf("result %d finding %d is missing rule_id or path", resultIndex, findingIndex)
			}
			if _, err := parseSeverity(string(finding.Severity)); err != nil {
				return fmt.Errorf("result %d finding %d has invalid severity", resultIndex, findingIndex)
			}
			if _, err := parseConfidence(string(finding.Confidence)); err != nil {
				return fmt.Errorf("result %d finding %d has invalid confidence", resultIndex, findingIndex)
			}
			if finding.Disposition != "" {
				switch finding.Disposition {
				case model.DispositionBlock, model.DispositionReview, model.DispositionHarden, model.DispositionInformational:
				default:
					return fmt.Errorf("result %d finding %d has invalid disposition", resultIndex, findingIndex)
				}
			}
			if finding.Occurrences < 0 || finding.LocationsOmitted < 0 {
				return fmt.Errorf("result %d finding %d has invalid occurrence counts", resultIndex, findingIndex)
			}
			for _, location := range finding.Locations {
				if location.Path == "" || location.StartLine < 0 || location.EndLine < 0 || location.EndLine > 0 && location.EndLine < location.StartLine {
					return fmt.Errorf("result %d finding %d has an invalid location", resultIndex, findingIndex)
				}
			}
			scan.NormalizeFinding(finding)
			allowed := model.MaxLocationsPerRepo - locationsStored
			if allowed > model.MaxLocationsPerFinding {
				allowed = model.MaxLocationsPerFinding
			}
			if allowed < 0 {
				allowed = 0
			}
			if len(finding.Locations) > allowed {
				finding.LocationsOmitted += len(finding.Locations) - allowed
				finding.Locations = finding.Locations[:allowed]
				locationsTruncated = true
			}
			locationsStored += len(finding.Locations)
		}
		if locationsTruncated {
			result.Coverage.Warnings = append(result.Coverage.Warnings, "finding location detail was truncated by report limits; occurrence totals remain complete")
		}
		if result.Error != "" && result.Coverage.Complete {
			return fmt.Errorf("result %d claims complete coverage despite a scan error", resultIndex)
		}
		expectedVerdict := verdict(result.Coverage, result.Findings)
		if result.Error != "" {
			expectedVerdict = model.VerdictIncomplete
		}
		if result.Verdict != expectedVerdict {
			return fmt.Errorf("result %d verdict %q does not match its findings and coverage", resultIndex, result.Verdict)
		}
	}
	return nil
}

type scanArgs struct {
	format, output, file, config, history, failOn                string
	detail, progress, color, minSeverity, minConfidence, groupBy string
	jobs                                                         int
	includeDeps, keep                                            bool
	sandbox                                                      string
	version                                                      string
	timeout                                                      time.Duration
	limits                                                       scan.Limits
	targets                                                      []string
	intelligence                                                 *intel.Database
}

type scanProgressState struct {
	target  string
	started time.Time
	files   int
	bytes   int64
}

type scanProgress struct {
	mu      sync.Mutex
	w       io.Writer
	mode    string
	active  map[int]*scanProgressState
	stop    chan struct{}
	stopped chan struct{}
}

func newScanProgress(w io.Writer, mode string) *scanProgress {
	p := &scanProgress{w: w, mode: mode, active: map[int]*scanProgressState{}}
	if mode != "quiet" {
		p.stop = make(chan struct{})
		p.stopped = make(chan struct{})
		go p.loop()
	}
	return p
}

func (p *scanProgress) loop() {
	defer close(p.stopped)
	interval := 2 * time.Second
	if p.mode == "interactive" {
		interval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.printUpdates()
		case <-p.stop:
			return
		}
	}
}

func (p *scanProgress) start(index int, target string) {
	if p.mode == "quiet" {
		return
	}
	target = output.SanitizeSourceText(target)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active[index] = &scanProgressState{target: target, started: time.Now()}
	if p.mode == "interactive" {
		p.renderInteractive()
	} else {
		fmt.Fprintf(p.w, "repyy: scanning %s...\n", target)
	}
}

func (p *scanProgress) update(index, files int, bytes int64) {
	if p.mode == "quiet" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if state := p.active[index]; state != nil {
		state.files = files
		state.bytes = bytes
	}
}

func (p *scanProgress) finish(index int, result model.RepoResult) {
	if p.mode == "quiet" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.active[index]
	delete(p.active, index)
	if state == nil {
		return
	}
	if p.mode == "interactive" {
		fmt.Fprint(p.w, "\r\x1b[2K")
	}
	if result.Error != "" {
		fmt.Fprintf(p.w, "repyy: scan failed for %s after %s\n", state.target, formatDuration(result.Duration))
		return
	}
	fmt.Fprintf(p.w, "repyy: scanned %s (%d files, %s) in %s\n", state.target, result.Coverage.FilesScanned, formatBytes(result.Coverage.BytesScanned), formatDuration(result.Duration))
	if p.mode == "interactive" && len(p.active) > 0 {
		p.renderInteractive()
	}
}

func (p *scanProgress) printUpdates() {
	p.mu.Lock()
	defer p.mu.Unlock()
	indexes := make([]int, 0, len(p.active))
	for index := range p.active {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	if p.mode == "interactive" {
		p.renderInteractive()
		return
	}
	for _, index := range indexes {
		state := p.active[index]
		fmt.Fprintf(p.w, "repyy: scanning %s (%d files, %s, %s elapsed)\n", state.target, state.files, formatBytes(state.bytes), formatDuration(time.Since(state.started)))
	}
}

func (p *scanProgress) renderInteractive() {
	if len(p.active) == 0 {
		return
	}
	if len(p.active) == 1 {
		for _, state := range p.active {
			fmt.Fprintf(p.w, "\r\x1b[2Krepyy: scanning %s · %d files · %s · %s", state.target, state.files, formatBytes(state.bytes), formatDuration(time.Since(state.started)))
		}
		return
	}
	files, bytes := 0, int64(0)
	oldest := time.Now()
	for _, state := range p.active {
		files += state.files
		bytes += state.bytes
		if state.started.Before(oldest) {
			oldest = state.started
		}
	}
	fmt.Fprintf(p.w, "\r\x1b[2Krepyy: scanning %d repositories · %d files · %s · %s", len(p.active), files, formatBytes(bytes), formatDuration(time.Since(oldest)))
}

func (p *scanProgress) close() {
	if p.mode == "quiet" {
		return
	}
	close(p.stop)
	<-p.stopped
	if p.mode == "interactive" {
		fmt.Fprint(p.w, "\r\x1b[2K")
	}
}

func formatBytes(bytes int64) string {
	const unit = int64(1024)
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	value := float64(bytes)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, name := range units {
		value /= float64(unit)
		if value < float64(unit) || name == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", value, name)
		}
	}
	return fmt.Sprintf("%d B", bytes)
}

func formatDuration(duration time.Duration) string {
	if duration < time.Second {
		return duration.Round(time.Millisecond).String()
	}
	return duration.Round(time.Second).String()
}

func parseScanArgs(args []string) (scanArgs, error) {
	o := scanArgs{format: "terminal", jobs: 4, history: "1", failOn: "high", detail: "review", progress: "auto", color: "auto", minSeverity: "low", minConfidence: "low", groupBy: "severity", timeout: 10 * time.Minute, limits: scan.DefaultLimits()}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.file, "file", "", "")
	fs.StringVar(&o.format, "format", o.format, "")
	fs.StringVar(&o.output, "output", "", "")
	fs.IntVar(&o.jobs, "jobs", o.jobs, "")
	fs.StringVar(&o.config, "config", "", "")
	fs.BoolVar(&o.includeDeps, "include-dependencies", false, "")
	fs.StringVar(&o.history, "history", o.history, "")
	fs.BoolVar(&o.keep, "keep-workdir", false, "")
	fs.StringVar(&o.sandbox, "sandbox", "host", "")
	fs.StringVar(&o.failOn, "fail-on", o.failOn, "")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "")
	fs.IntVar(&o.limits.MaxFiles, "max-files", o.limits.MaxFiles, "")
	fs.Int64Var(&o.limits.MaxFileBytes, "max-file-size", o.limits.MaxFileBytes, "")
	fs.StringVar(&o.detail, "detail", o.detail, "")
	fs.StringVar(&o.progress, "progress", o.progress, "")
	fs.StringVar(&o.color, "color", o.color, "")
	fs.StringVar(&o.minSeverity, "min-severity", o.minSeverity, "")
	fs.StringVar(&o.minConfidence, "min-confidence", o.minConfidence, "")
	fs.StringVar(&o.groupBy, "group-by", o.groupBy, "")
	// Permit flags before or after targets by separating known value and boolean flags.
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			o.targets = append(o.targets, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		if strings.Contains(a, "=") || a == "--include-dependencies" || a == "--keep-workdir" {
			continue
		}
		if i+1 >= len(args) {
			return o, fmt.Errorf("missing value for %s", a)
		}
		i++
		flagArgs = append(flagArgs, args[i])
	}
	if err := fs.Parse(flagArgs); err != nil {
		return o, err
	}
	if o.jobs < 1 || o.jobs > 128 {
		return o, errors.New("--jobs must be between 1 and 128")
	}
	if o.sandbox != "host" && o.sandbox != "docker" {
		return o, errors.New("--sandbox must be host or docker; vm and auto are reserved for a later release")
	}
	if o.sandbox == "docker" {
		if o.keep {
			return o, errors.New("--keep-workdir is not supported with --sandbox=docker")
		}
		for _, target := range o.targets {
			if strings.HasPrefix(target, "git@") || strings.HasPrefix(target, "ssh://") {
				return o, errors.New("SSH URLs are not supported with --sandbox=docker; use an HTTPS Git URL")
			}
		}
	}
	if o.timeout <= 0 || o.limits.MaxFiles <= 0 || o.limits.MaxFileBytes <= 0 {
		return o, errors.New("resource limits must be positive")
	}
	if o.format != "terminal" && o.format != "json" && o.format != "sarif" && o.format != "html" {
		return o, errors.New("--format must be terminal, json, sarif, or html")
	}
	if o.detail != "summary" && o.detail != "review" && o.detail != "all" {
		return o, errors.New("--detail must be summary, review, or all")
	}
	if o.progress != "auto" && o.progress != "plain" && o.progress != "quiet" {
		return o, errors.New("--progress must be auto, plain, or quiet")
	}
	if o.color != "auto" && o.color != "always" && o.color != "never" {
		return o, errors.New("--color must be auto, always, or never")
	}
	if o.groupBy != "severity" && o.groupBy != "file" && o.groupBy != "rule" {
		return o, errors.New("--group-by must be severity, file, or rule")
	}
	if o.history != "all" {
		if n, err := strconv.Atoi(o.history); err != nil || n < 1 {
			return o, errors.New("--history must be a positive number or all")
		}
	}
	if _, err := parseSeverity(o.failOn); err != nil {
		return o, err
	}
	if _, err := parseDisplaySeverity(o.minSeverity); err != nil {
		return o, err
	}
	if _, err := parseConfidence(o.minConfidence); err != nil {
		return o, err
	}
	return o, nil
}

func runScan(args []string, stdout, stderr io.Writer, version string) (int, error) {
	opts, err := parseScanArgs(args)
	if err != nil {
		return 3, err
	}
	if opts.file != "" {
		targets, err := readTargets(opts.file)
		if err != nil {
			return 3, err
		}
		opts.targets = append(opts.targets, targets...)
	}
	if len(opts.targets) == 0 {
		return 3, errors.New("provide at least one target or --file")
	}
	if opts.sandbox == "docker" {
		for _, target := range opts.targets {
			if strings.HasPrefix(target, "git@") || strings.HasPrefix(target, "ssh://") {
				return 3, errors.New("SSH URLs are not supported with --sandbox=docker; use an HTTPS Git URL")
			}
		}
	}
	if opts.sandbox == "docker" {
		preflightCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := sandbox.Preflight(preflightCtx, sandbox.Options{Version: version})
		cancel()
		if err != nil {
			return 3, err
		}
		opts.version = version
		if opts.jobs > 4 {
			opts.jobs = 4
		}
	}

	rules := scan.BuiltinRules()
	suppressions := map[string]bool{}
	if opts.config != "" {
		cfg, err := config.Load(opts.config)
		if err != nil {
			return 3, err
		}
		rules = append(rules, cfg.Rules...)
		suppressions = config.ActiveSuppressions(cfg, time.Now())
		if opts.sandbox == "docker" {
			opts.config, err = filepath.Abs(opts.config)
			if err != nil {
				return 3, err
			}
		}
	}
	store, err := intel.NewDefaultStore()
	if err != nil {
		return 2, err
	}
	intelligence, intelStatus := store.LoadActive(time.Now().UTC())
	opts.intelligence = intelligence
	if opts.sandbox == "docker" {
		// The release image has no host cache mount and scans with its embedded
		// verified snapshot. Keep the host-rendered report metadata in sync.
		builtin := intel.BuiltinSnapshot()
		intelStatus.SnapshotVersion = builtin.SnapshotVersion
		intelStatus.SnapshotDate = builtin.SnapshotDate
		intelStatus.Source = "embedded"
	}
	if intelStatus.Warning != "" {
		fmt.Fprintln(stderr, "repyy:", intelStatus.Warning)
	}
	report := model.Report{
		SchemaVersion: "1",
		ToolVersion:   version,
		ToolCommit:    buildinfo.Commit,
		Limitation:    model.Limitation,
		RulesVersion:  scan.BuiltinRulesVersion,
		Intelligence: model.IntelligenceInfo{
			Version: intelStatus.SnapshotVersion,
			Date:    intelStatus.SnapshotDate,
			Source:  intelStatus.Source,
		},
		GeneratedAt: time.Now().UTC(),
		Results:     make([]model.RepoResult, len(opts.targets)),
	}
	progress := newScanProgress(stderr, resolveProgressMode(opts, stderr))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range opts.jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				target := displayTarget(opts.targets[i])
				progress.start(i, target)
				report.Results[i] = scanOne(opts.targets[i], opts, rules, suppressions, func(files int, bytes int64) {
					progress.update(i, files, bytes)
				})
				progress.finish(i, report.Results[i])
			}
		}()
	}
	for i := range opts.targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	progress.close()

	presentation, err := presentationOptions(opts.detail, opts.minSeverity, opts.minConfidence, opts.groupBy, opts.color, stdout)
	if err != nil {
		return 3, err
	}
	if err := writeReportOutput(stdout, opts.output, opts.format, report, presentation); err != nil {
		return 3, err
	}
	threshold, _ := parseSeverity(opts.failOn)
	return exitCodeForResults(report.Results, threshold), nil
}

func exitCodeForResults(results []model.RepoResult, threshold model.Severity) int {
	hasFinding, hasIncomplete := false, false
	for _, result := range results {
		if result.Error != "" || result.Verdict == model.VerdictIncomplete || !result.Coverage.Complete {
			hasIncomplete = true
		}
		for _, finding := range result.Findings {
			if finding.Severity.Rank() >= threshold.Rank() {
				hasFinding = true
			}
		}
	}
	if hasIncomplete {
		return 2
	}
	if hasFinding {
		return 1
	}
	return 0
}

func scanOne(target string, opts scanArgs, rules []scan.Rule, suppressions map[string]bool, progress func(files int, bytes int64)) (result model.RepoResult) {
	started := time.Now()
	result = model.RepoResult{Target: displayTarget(target), ScanMode: model.ScanModeHost, Findings: []model.Finding{}}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	if opts.sandbox == "docker" {
		result.ScanMode = model.ScanModeDocker
		sandboxResult, err := sandbox.Scan(ctx, target, sandbox.Options{Version: opts.version, Timeout: opts.timeout, History: opts.history, IncludeDependencies: opts.includeDeps, MaxFiles: opts.limits.MaxFiles, MaxFileBytes: opts.limits.MaxFileBytes, Config: opts.config})
		if err != nil {
			result.Error = err.Error()
			result.Verdict = model.VerdictIncomplete
			result.Coverage.Complete = false
			result.Duration = time.Since(started)
			return result
		}
		sandboxResult.Target = displayTarget(target)
		sandboxResult.Duration = time.Since(started)
		validation := model.Report{SchemaVersion: "1", Results: []model.RepoResult{sandboxResult}}
		if err := normalizeAndValidateReport(&validation); err != nil {
			result.Error = "sandbox returned invalid report: " + err.Error()
			result.Verdict = model.VerdictIncomplete
			result.Duration = time.Since(started)
			return result
		}
		sandboxResult = validation.Results[0]
		return sandboxResult
	}
	prepared, err := source.Prepare(ctx, target, source.Options{History: opts.history, Keep: opts.keep})
	if err != nil {
		result.Error = err.Error()
		result.Verdict = model.VerdictIncomplete
		result.Coverage.Complete = false
		result.Duration = time.Since(started)
		return result
	}
	defer finishCheckout(&result, prepared.Cleanup)
	if opts.keep && prepared.Remote {
		result.Resolved = prepared.Path
	}
	if prepared.Remote && prepared.RepositoryURL != "" && prepared.Revision != "" {
		result.Source = &model.SourceInfo{RepositoryURL: prepared.RepositoryURL, Revision: prepared.Revision}
	}
	scanner := scan.New(scan.Options{Rules: rules, Intelligence: opts.intelligence, IncludeDependencies: opts.includeDeps, Limits: opts.limits, Progress: progress})
	result.Coverage, result.Findings = scanner.Scan(ctx, prepared.Path)
	filtered := result.Findings[:0]
	for _, finding := range result.Findings {
		if !suppressions[finding.Fingerprint] {
			filtered = append(filtered, finding)
		}
	}
	result.Findings = filtered
	result.Verdict = verdict(result.Coverage, result.Findings)
	result.Duration = time.Since(started)
	return result
}

// finishCheckout runs before scanOne returns its named result so cleanup failures
// participate in the ordinary incomplete-scan exit policy without losing findings.
func finishCheckout(result *model.RepoResult, cleanup func() error) {
	if err := cleanup(); err != nil {
		result.Coverage.Complete = false
		result.Verdict = model.VerdictIncomplete
		result.Coverage.Warnings = append(result.Coverage.Warnings,
			"temporary checkout cleanup failed; private files may remain in the system temporary directory")
	}
}

func displayTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return target
	}
	if u.User != nil {
		u.User = url.User("[REDACTED]")
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return strings.Replace(u.String(), "%5BREDACTED%5D@", "[REDACTED]@", 1)
}

func verdict(coverage model.Coverage, findings []model.Finding) string {
	for _, f := range findings {
		if f.Severity == model.SeverityCritical && f.Confidence == model.ConfidenceHigh && (f.Context == "executable" || f.Context == "manifest-hook" || f.Context == "ci-workflow" || f.Context == "confirmed-ioc") {
			return model.VerdictDoNotRun
		}
	}
	if !coverage.Complete {
		return model.VerdictIncomplete
	}
	if len(findings) > 0 {
		return model.VerdictReview
	}
	return model.VerdictNoFindings
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, s.Err()
}

func parseSeverity(v string) (model.Severity, error) {
	s := model.Severity(strings.ToLower(v))
	switch s {
	case model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical:
		return s, nil
	}
	return "", errors.New("--fail-on must be low, medium, high, or critical")
}

func parseDisplaySeverity(v string) (model.Severity, error) {
	severity, err := parseSeverity(v)
	if err != nil {
		return "", errors.New("--min-severity must be low, medium, high, or critical")
	}
	return severity, nil
}

func parseConfidence(v string) (model.Confidence, error) {
	confidence := model.Confidence(strings.ToLower(v))
	switch confidence {
	case model.ConfidenceLow, model.ConfidenceMedium, model.ConfidenceHigh:
		return confidence, nil
	}
	return "", errors.New("--min-confidence must be low, medium, or high")
}

func presentationOptions(detail, minSeverity, minConfidence, groupBy, color string, writer io.Writer) (output.Options, error) {
	severity, err := parseDisplaySeverity(minSeverity)
	if err != nil {
		return output.Options{}, err
	}
	confidence, err := parseConfidence(minConfidence)
	if err != nil {
		return output.Options{}, err
	}
	_, noColor := os.LookupEnv("NO_COLOR")
	colorEnabled := resolveColorMode(color, isTerminalWriter(writer), noColor)
	return output.Options{Detail: detail, MinSeverity: severity, MinConfidence: confidence, GroupBy: groupBy, Color: colorEnabled}, nil
}

func resolveColorMode(mode string, terminal, noColor bool) bool {
	return mode == "always" || mode == "auto" && terminal && !noColor
}

func writeReportOutput(stdout io.Writer, path, format string, report model.Report, presentation output.Options) error {
	if path == "" {
		return output.WriteWithOptions(stdout, format, report, presentation)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".repyy-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err := restrictOutputPermissions(file.Name()); err != nil {
		file.Close()
		return err
	}
	if err := output.WriteWithOptions(file, format, report, presentation); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func resolveProgressMode(opts scanArgs, writer io.Writer) string {
	if opts.progress == "quiet" {
		return "quiet"
	}
	if opts.progress == "plain" {
		return "plain"
	}
	if isTerminalWriter(writer) && (opts.format == "terminal" || opts.output != "") {
		return "interactive"
	}
	if opts.format == "terminal" {
		return "plain"
	}
	return "quiet"
}

func isTerminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
