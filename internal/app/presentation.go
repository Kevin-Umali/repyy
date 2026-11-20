package app

import (
	"github.com/Kevin-Umali/repyy/internal/output"
	"io"
	"os"
)

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

func isTerminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
