// Package output renders scan reports without exposing unredacted source data.
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// Options controls human-facing rendering without changing scan policy.
type Options struct {
	Detail        string
	MinSeverity   model.Severity
	MinConfidence model.Confidence
	GroupBy       string
	Color         bool
}

// DefaultOptions returns the prioritized interactive presentation defaults.
func DefaultOptions() Options {
	return Options{Detail: "review", MinSeverity: model.SeverityLow, MinConfidence: model.ConfidenceLow, GroupBy: "severity"}
}

// Write serializes a report in terminal, JSON, or SARIF form.
func Write(w io.Writer, format string, report model.Report) error {
	return WriteWithOptions(w, format, report, DefaultOptions())
}

// WriteWithOptions serializes a report with presentation-only options.
func WriteWithOptions(w io.Writer, format string, report model.Report, opts Options) error {
	report = SanitizeReport(report)
	switch format {
	case "terminal":
		return terminal(w, report, opts)
	case "json":
		return jsonOut(w, report)
	case "sarif":
		return sarifOut(w, report)
	case "html":
		return htmlOut(w, report)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func jsonOut(w io.Writer, report model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
