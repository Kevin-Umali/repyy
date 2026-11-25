package app

import (
	"errors"
	"flag"
	"fmt"
	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"io"
	"strconv"
	"strings"
	"time"
)

type scanArgs struct {
	formatSet, outputSet, fileSet                                bool
	format, output, file, config, history, failOn                string
	detail, progress, color, minSeverity, minConfidence, groupBy string
	jobs                                                         int
	includeDeps, keep, registryCheck                             bool
	sandbox                                                      string
	profile                                                      scan.Profile
	version                                                      string
	timeout                                                      time.Duration
	limits                                                       scan.Limits
	targets                                                      []string
	intelligence                                                 *intel.Database
}

func parseScanArgs(args []string) (scanArgs, error) {
	o := scanArgs{format: "terminal", jobs: 4, history: "1", failOn: "high", detail: "review", progress: "auto", color: "auto", minSeverity: "low", minConfidence: "low", groupBy: "severity", profile: scan.ProfileBalanced, timeout: 10 * time.Minute, limits: scan.DefaultLimits()}
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
	fs.BoolVar(&o.registryCheck, "registry-check", false, "")
	fs.StringVar(&o.sandbox, "sandbox", "host", "")
	fs.StringVar((*string)(&o.profile), "profile", string(o.profile), "")
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
		if strings.Contains(a, "=") || a == "--include-dependencies" || a == "--keep-workdir" || a == "--registry-check" {
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
	o.formatSet = flagWasSet(fs, "format")
	o.outputSet = flagWasSet(fs, "output")
	o.fileSet = flagWasSet(fs, "file")
	if o.jobs < 1 || o.jobs > 128 {
		return o, errors.New("--jobs must be between 1 and 128")
	}
	if o.profile != scan.ProfileBalanced && o.profile != scan.ProfileComprehensive {
		return o, errors.New("--profile must be balanced or comprehensive")
	}
	if o.sandbox != "host" && o.sandbox != "docker" {
		return o, errors.New("--sandbox must be host or docker")
	}
	if o.sandbox == "docker" {
		if o.keep {
			return o, errors.New("--keep-workdir is not supported with --sandbox=docker")
		}
		if o.registryCheck {
			return o, errors.New("--registry-check is not supported with --sandbox=docker, whose scan stage has no network")
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
	if o.format != "terminal" && o.format != "json" && o.format != "sarif" && o.format != "html" && o.format != "tui" {
		return o, errors.New("--format must be terminal, json, sarif, html, or tui")
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
