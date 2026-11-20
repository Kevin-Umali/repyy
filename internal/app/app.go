// Package app implements repyy's command-line orchestration and exit policy.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/Kevin-Umali/repyy/internal/buildinfo"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"github.com/Kevin-Umali/repyy/internal/tui"
	"io"
	"os"
	"strings"
)

const usage = `repyy — inspect unfamiliar repositories without running them

Usage:
  repyy                    open interactive Home
  repyy scan [options] <path-or-git-url>...
  repyy report [options] <report.json|->
  repyy report             pick a saved report in a terminal
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
  --format terminal|json|sarif|html|tui
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
  --format terminal|html|sarif|tui (HTML outside an interactive session)
  --output PATH
  --detail summary|review|all
  --color auto|always|never
`

// Run executes the CLI command and returns its documented process exit code.
func Run(args []string, stdout, stderr io.Writer, version string) (int, error) {
	if len(args) == 0 {
		if defaultInteractive(stdout) {
			return runHome(stdout, version)
		}
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

func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func defaultInteractive(stdout io.Writer) bool {
	ci := strings.ToLower(strings.TrimSpace(os.Getenv("CI")))
	if ci != "" && ci != "false" && ci != "0" {
		return false
	}
	file, ok := stdout.(*os.File)
	return ok && tui.IsTerminal(os.Stdin) && tui.IsTerminal(file)
}

func runHome(stdout io.Writer, version string) (int, error) {
	terminal, err := tuiOutput(stdout, "")
	if err != nil {
		return 3, err
	}
	opts, err := parseScanArgs(nil)
	if err != nil {
		return 3, err
	}
	presentation, err := presentationOptions(opts.detail, opts.minSeverity, opts.minConfidence, opts.groupBy, opts.color, stdout)
	if err != nil {
		return 3, err
	}
	_, err = tui.Run(os.Stdin, terminal, tui.Options{Home: true, Targets: 1, Timeout: opts.timeout, Presentation: presentation, Export: exportReport, OpenReport: func(ctx context.Context, path string, _ func()) (model.Report, string, error) {
		if err := ctx.Err(); err != nil {
			return model.Report{}, "", err
		}
		report, err := loadTUIReport(path)
		return report, "", err
	}}, func(ctx context.Context, path string, onComplete func()) (model.Report, string, error) {
		selected := opts
		selected.targets = []string{path}
		return executeScan(ctx, selected, version, nil, onComplete)
	})
	if err != nil {
		return scanErrorCode(err), err
	}
	return 0, nil
}

func tuiOutput(stdout io.Writer, path string) (*os.File, error) {
	if path != "" {
		return nil, errors.New("--output cannot be used with --format tui; save JSON with --format json instead")
	}
	terminal, ok := stdout.(*os.File)
	if !ok || !tui.IsTerminal(terminal) || !tui.IsTerminal(os.Stdin) {
		return nil, errors.New("--format tui requires an interactive terminal on stdin and stdout; use --format terminal or json for redirected output")
	}
	return terminal, nil
}
