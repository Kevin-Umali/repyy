package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/Kevin-Umali/repyy/internal/buildinfo"
	"github.com/Kevin-Umali/repyy/internal/config"
	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/sandbox"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"github.com/Kevin-Umali/repyy/internal/source"
	"github.com/Kevin-Umali/repyy/internal/tui"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func runScan(args []string, stdout, stderr io.Writer, version string) (int, error) {
	opts, err := parseScanArgs(args)
	if err != nil {
		return 3, err
	}
	if !opts.formatSet && !opts.outputSet && defaultInteractive(stdout) {
		opts.format = "tui"
	}
	if opts.file != "" {
		targets, err := readTargets(opts.file)
		if err != nil {
			return 3, err
		}
		opts.targets = append(opts.targets, targets...)
	}
	prompt := len(opts.targets) == 0 && !opts.fileSet && opts.format == "tui"
	if len(opts.targets) == 0 && !prompt {
		return 3, errors.New("provide at least one target or --file")
	}
	presentation, err := presentationOptions(opts.detail, opts.minSeverity, opts.minConfidence, opts.groupBy, opts.color, stdout)
	if err != nil {
		return 3, err
	}
	var report model.Report
	if opts.format == "tui" {
		terminal, err := tuiOutput(stdout, opts.output)
		if err != nil {
			return 3, err
		}
		targets := len(opts.targets)
		if prompt {
			targets = 1
		}
		report, err = tui.Run(os.Stdin, terminal, tui.Options{Presentation: presentation, Targets: targets, Timeout: opts.timeout, PromptTarget: prompt, Export: exportReport}, func(ctx context.Context, path string, onComplete func()) (model.Report, string, error) {
			selected := opts
			if prompt {
				selected.targets = []string{path}
			}
			return executeScan(ctx, selected, version, nil, onComplete)
		})
		if err != nil {
			return scanErrorCode(err), err
		}
	} else {
		progress := newScanProgress(stderr, resolveProgressMode(opts, stderr))
		report, _, err = executeScan(context.Background(), opts, version, progress, nil)
		progress.close()
		if err != nil {
			return scanErrorCode(err), err
		}
		if err := writeReportOutput(stdout, opts.output, opts.format, report, presentation); err != nil {
			return 3, err
		}
	}
	threshold, _ := parseSeverity(opts.failOn)
	return exitCodeForResults(report.Results, threshold), nil
}

type commandError struct {
	code int
	err  error
}

func (e commandError) Error() string { return e.err.Error() }

func (e commandError) Unwrap() error { return e.err }

func scanErrorCode(err error) int {
	if errors.Is(err, context.Canceled) {
		return 130
	}
	var command commandError
	if errors.As(err, &command) {
		return command.code
	}
	return 2
}

func executeScan(ctx context.Context, opts scanArgs, version string, progress *scanProgress, onComplete func()) (model.Report, string, error) {
	var err error
	if opts.sandbox == "docker" {
		for _, target := range opts.targets {
			if strings.HasPrefix(target, "git@") || strings.HasPrefix(target, "ssh://") {
				return model.Report{}, "", commandError{3, errors.New("SSH URLs are not supported with --sandbox=docker; use an HTTPS Git URL")}
			}
		}
	}
	if opts.sandbox == "docker" {
		preflightCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := sandbox.Preflight(preflightCtx, sandbox.Options{Version: version})
		cancel()
		if err != nil {
			return model.Report{}, "", commandError{3, err}
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
			return model.Report{}, "", commandError{3, err}
		}
		rules = append(rules, cfg.Rules...)
		suppressions = config.ActiveSuppressions(cfg, time.Now())
		if opts.sandbox == "docker" {
			opts.config, err = filepath.Abs(opts.config)
			if err != nil {
				return model.Report{}, "", commandError{3, err}
			}
		}
	}
	store, err := intel.NewDefaultStore()
	if err != nil {
		return model.Report{}, "", commandError{2, err}
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
	if progress != nil && intelStatus.Warning != "" {
		fmt.Fprintln(progress.w, "repyy:", intelStatus.Warning)
	}
	notice := intelStatus.Warning
	if notice == "" && intelStatus.Stale {
		notice = "Intelligence snapshot is stale; run 'repyy intel update' to refresh it."
	}
	err = scanTargets(ctx, &report, opts, rules, suppressions, progress, onComplete)
	return report, notice, err
}

func scanTargets(ctx context.Context, report *model.Report, opts scanArgs, rules []scan.Rule, suppressions map[string]bool, progress *scanProgress, onComplete func()) error {
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range opts.jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				if progress != nil {
					progress.start(i, displayTarget(opts.targets[i]))
				}
				report.Results[i] = scanOne(ctx, opts.targets[i], opts, rules, suppressions, func(files int, bytes int64) {
					if progress != nil {
						progress.update(i, files, bytes)
					}
				})
				if progress != nil {
					progress.finish(i, report.Results[i])
				}
				if onComplete != nil {
					onComplete()
				}
			}
		}()
	}
scheduling:
	for i := range opts.targets {
		select {
		case <-ctx.Done():
			break scheduling
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
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

func scanOne(parent context.Context, target string, opts scanArgs, rules []scan.Rule, suppressions map[string]bool, progress func(files int, bytes int64)) (result model.RepoResult) {
	started := time.Now()
	result = model.RepoResult{Target: displayTarget(target), ScanMode: model.ScanModeHost, Findings: []model.Finding{}}
	ctx, cancel := context.WithTimeout(parent, opts.timeout)
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
