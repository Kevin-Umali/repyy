package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"github.com/Kevin-Umali/repyy/internal/tui"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func exportReport(report model.Report, format, path string) error {
	if path == "" {
		return errors.New("provide an export path")
	}
	switch format {
	case "json", "html", "sarif":
	default:
		return errors.New("unsupported export format")
	}
	return writeReportFile(io.Discard, path, format, report, output.Options{Detail: "all", MinSeverity: model.SeverityLow, MinConfidence: model.ConfidenceLow, GroupBy: "severity"}, true)
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
	if !flagWasSet(fs, "format") && !flagWasSet(fs, "output") && opts.input != "-" && defaultInteractive(stdout) {
		opts.format = "tui"
	}
	if opts.input == "" && opts.format != "tui" {
		return 3, errors.New("usage: repyy report [options] <report.json|->")
	}
	if opts.format != "terminal" && opts.format != "html" && opts.format != "sarif" && opts.format != "tui" {
		return 3, errors.New("--format must be terminal, html, sarif, or tui")
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

	presentation, err := presentationOptions(opts.detail, opts.minSeverity, opts.minConfidence, opts.groupBy, opts.color, stdout)
	if err != nil {
		return 3, err
	}
	if opts.format == "tui" {
		terminal, err := tuiOutput(stdout, opts.output)
		if err != nil {
			return 3, err
		}
		if opts.input == "-" {
			return 3, errors.New("--format tui cannot read a report from stdin; provide a JSON file path")
		}
		report, err := tui.Run(os.Stdin, terminal, tui.Options{Presentation: presentation, PickReport: opts.input == "", Export: exportReport}, func(ctx context.Context, selectedPath string, onComplete func()) (model.Report, string, error) {
			path := opts.input
			if path == "" {
				path = selectedPath
			}
			if err := ctx.Err(); err != nil {
				return model.Report{}, "", err
			}
			report, err := loadTUIReport(path)
			return report, "", err
		})
		if errors.Is(err, context.Canceled) {
			return 130, err
		}
		if err != nil {
			return 3, err
		}
		return exitCodeForResults(report.Results, model.SeverityHigh), nil
	}
	report, err := loadReport(opts.input)
	if err != nil {
		return 3, err
	}

	if err := writeReportOutput(stdout, opts.output, opts.format, report, presentation); err != nil {
		return 3, err
	}
	return exitCodeForResults(report.Results, model.SeverityHigh), nil
}

func loadTUIReport(path string) (model.Report, error) {
	info, err := os.Stat(path)
	if err != nil {
		return model.Report{}, err
	}
	if !info.Mode().IsRegular() {
		return model.Report{}, errors.New("TUI report input must be a regular JSON file")
	}
	return readReport(path, true)
}

func loadReport(path string) (model.Report, error) {
	return readReport(path, false)
}

func readReport(path string, regularOnly bool) (model.Report, error) {
	var reader io.Reader
	var inputFile *os.File
	if path == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return model.Report{}, err
		}
		inputFile = file
		defer inputFile.Close()
		if regularOnly {
			info, err := inputFile.Stat()
			if err != nil {
				return model.Report{}, err
			}
			if !info.Mode().IsRegular() {
				return model.Report{}, errors.New("TUI report input must be a regular JSON file")
			}
		}
		reader = inputFile
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxReportInputBytes+1))
	if err != nil {
		return model.Report{}, err
	}
	if len(data) > maxReportInputBytes {
		return model.Report{}, fmt.Errorf("report input exceeds %d MiB", maxReportInputBytes>>20)
	}
	var report model.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return model.Report{}, fmt.Errorf("invalid report JSON: %w", err)
	}
	if err := normalizeAndValidateReport(&report); err != nil {
		return model.Report{}, err
	}

	return report, nil
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

func writeReportOutput(stdout io.Writer, path, format string, report model.Report, presentation output.Options) error {
	return writeReportFile(stdout, path, format, report, presentation, false)
}

func writeReportFile(stdout io.Writer, path, format string, report model.Report, presentation output.Options, noClobber bool) error {
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
	if noClobber {
		return os.Link(file.Name(), path)
	}
	return os.Rename(file.Name(), path)
}
