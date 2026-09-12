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
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kevin-Umali/repyy/internal/config"
	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"github.com/Kevin-Umali/repyy/internal/source"
)

const usage = `repyy — inspect unfamiliar repositories without running them

Usage:
  repyy scan [options] <path-or-git-url>...
  repyy rules validate <rules.yaml>
  repyy rules check
  repyy rules list [--format terminal|json]
  repyy intel status [--format terminal|json]
  repyy intel update
  repyy intel rollback
  repyy version

Scan options:
  --file PATH              read additional targets, one per line
  --format terminal|json|sarif
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
		fmt.Fprintf(stdout, "repyy %s (rules %s)\n", version, scan.BuiltinRulesVersion)
		return 0, nil
	case "rules":
		return runRules(args[1:], stdout)
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
	return 3, errors.New("usage: repyy rules validate <rules.yaml> | repyy rules check | repyy rules list [--format terminal|json]")
}

type scanArgs struct {
	format, output, file, config, history, failOn string
	jobs                                          int
	includeDeps, keep                             bool
	timeout                                       time.Duration
	limits                                        scan.Limits
	targets                                       []string
	intelligence                                  *intel.Database
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
	enabled bool
	active  map[int]*scanProgressState
	stop    chan struct{}
	stopped chan struct{}
}

func newScanProgress(w io.Writer, enabled bool) *scanProgress {
	p := &scanProgress{w: w, enabled: enabled, active: map[int]*scanProgressState{}}
	if enabled {
		p.stop = make(chan struct{})
		p.stopped = make(chan struct{})
		go p.loop()
	}
	return p
}

func (p *scanProgress) loop() {
	defer close(p.stopped)
	ticker := time.NewTicker(2 * time.Second)
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
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active[index] = &scanProgressState{target: target, started: time.Now()}
	fmt.Fprintf(p.w, "repyy: scanning %s...\n", target)
}

func (p *scanProgress) update(index, files int, bytes int64) {
	if !p.enabled {
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
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.active[index]
	delete(p.active, index)
	if state == nil {
		return
	}
	if result.Error != "" {
		fmt.Fprintf(p.w, "repyy: scan failed for %s after %s\n", state.target, formatDuration(result.Duration))
		return
	}
	fmt.Fprintf(p.w, "repyy: scanned %s (%d files, %s) in %s\n", state.target, result.Coverage.FilesScanned, formatBytes(result.Coverage.BytesScanned), formatDuration(result.Duration))
}

func (p *scanProgress) printUpdates() {
	p.mu.Lock()
	defer p.mu.Unlock()
	indexes := make([]int, 0, len(p.active))
	for index := range p.active {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	for _, index := range indexes {
		state := p.active[index]
		fmt.Fprintf(p.w, "repyy: scanning %s (%d files, %s, %s elapsed)\n", state.target, state.files, formatBytes(state.bytes), formatDuration(time.Since(state.started)))
	}
}

func (p *scanProgress) close() {
	if !p.enabled {
		return
	}
	close(p.stop)
	<-p.stopped
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
	o := scanArgs{format: "terminal", jobs: 4, history: "1", failOn: "high", timeout: 10 * time.Minute, limits: scan.DefaultLimits()}
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
	fs.StringVar(&o.failOn, "fail-on", o.failOn, "")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "")
	fs.IntVar(&o.limits.MaxFiles, "max-files", o.limits.MaxFiles, "")
	fs.Int64Var(&o.limits.MaxFileBytes, "max-file-size", o.limits.MaxFileBytes, "")
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
	if o.timeout <= 0 || o.limits.MaxFiles <= 0 || o.limits.MaxFileBytes <= 0 {
		return o, errors.New("resource limits must be positive")
	}
	if o.format != "terminal" && o.format != "json" && o.format != "sarif" {
		return o, errors.New("--format must be terminal, json, or sarif")
	}
	if o.history != "all" {
		if n, err := strconv.Atoi(o.history); err != nil || n < 1 {
			return o, errors.New("--history must be a positive number or all")
		}
	}
	if _, err := parseSeverity(o.failOn); err != nil {
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

	rules := scan.BuiltinRules()
	suppressions := map[string]bool{}
	if opts.config != "" {
		cfg, err := config.Load(opts.config)
		if err != nil {
			return 3, err
		}
		rules = append(rules, cfg.Rules...)
		suppressions = config.ActiveSuppressions(cfg, time.Now())
	}
	store, err := intel.NewDefaultStore()
	if err != nil {
		return 2, err
	}
	intelligence, intelStatus := store.LoadActive(time.Now().UTC())
	opts.intelligence = intelligence
	if intelStatus.Warning != "" {
		fmt.Fprintln(stderr, "repyy:", intelStatus.Warning)
	}
	report := model.Report{
		SchemaVersion: "1",
		ToolVersion:   version,
		RulesVersion:  scan.BuiltinRulesVersion,
		Intelligence: model.IntelligenceInfo{
			Version: intelStatus.SnapshotVersion,
			Date:    intelStatus.SnapshotDate,
			Source:  intelStatus.Source,
		},
		GeneratedAt: time.Now().UTC(),
		Results:     make([]model.RepoResult, len(opts.targets)),
	}
	progress := newScanProgress(stderr, opts.format == "terminal")
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

	w := stdout
	var file *os.File
	if opts.output != "" {
		file, err = os.OpenFile(opts.output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return 3, err
		}
		defer file.Close()
		w = file
	}
	if err := output.Write(w, opts.format, report); err != nil {
		return 3, err
	}
	threshold, _ := parseSeverity(opts.failOn)
	hasFinding, hasError := false, false
	for _, result := range report.Results {
		if result.Error != "" {
			hasError = true
		}
		for _, finding := range result.Findings {
			if finding.Severity.Rank() >= threshold.Rank() {
				hasFinding = true
			}
		}
	}
	if hasError {
		return 2, nil
	}
	if hasFinding {
		return 1, nil
	}
	return 0, nil
}

func scanOne(target string, opts scanArgs, rules []scan.Rule, suppressions map[string]bool, progress func(files int, bytes int64)) model.RepoResult {
	started := time.Now()
	result := model.RepoResult{Target: displayTarget(target), Findings: []model.Finding{}}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	prepared, err := source.Prepare(ctx, target, source.Options{History: opts.history, Keep: opts.keep})
	if err != nil {
		result.Error = err.Error()
		result.Verdict = model.VerdictIncomplete
		result.Coverage.Complete = false
		result.Duration = time.Since(started)
		return result
	}
	defer prepared.Cleanup()
	if opts.keep && prepared.Remote {
		result.Resolved = prepared.Path
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

func displayTarget(target string) string {
	if i := strings.Index(target, "://"); i >= 0 {
		rest := target[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			return target[:i+3] + "[REDACTED]@" + rest[at+1:]
		}
	}
	return target
}

func verdict(coverage model.Coverage, findings []model.Finding) string {
	for _, f := range findings {
		if f.Severity == model.SeverityCritical && f.Confidence == model.ConfidenceHigh && (f.Context == "executable" || f.Context == "manifest-hook" || f.Context == "confirmed-ioc") {
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
