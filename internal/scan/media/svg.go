// Package media inspects files that carry active content in media formats.
package media

import (
	"bytes"
	"encoding/xml"
	"path/filepath"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// FindingFactory lets callers retain their finding fingerprint policy.
type FindingFactory func(id, category string, severity model.Severity, confidence model.Confidence, path string, line int, message, evidence, remediation string) model.Finding

// ScanSVG reports executable SVG content. Context callbacks keep repository
// policy in the scanner package without creating an import cycle.
func ScanSVG(path string, data []byte, classifyContext func(string) string, isContextual func(string) bool, newFinding FindingFactory, add func(model.Finding)) {
	if !strings.EqualFold(filepath.Ext(innerPath(path)), ".svg") {
		return
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	line, lastOffset := 1, int64(0)
	seenRoot := false
	for {
		start := decoder.InputOffset()
		line += bytes.Count(data[lastOffset:start], []byte{'\n'})
		lastOffset = start
		token, err := decoder.Token()
		if err != nil {
			return
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !seenRoot {
			seenRoot = true
			if !strings.EqualFold(element.Name.Local, "svg") {
				return
			}
		}
		reason := activeElement(element)
		if reason == "" {
			continue
		}
		context := classifyContext(path)
		confidence := model.ConfidenceMedium
		if isContextual(context) {
			confidence = model.ConfidenceLow
		}
		finding := newFinding("IMAGE-001", "image-active-content", model.SeverityMedium, confidence, path, line,
			"SVG contains active content", reason, "Review the SVG source and remove unneeded scripts, event handlers, or JavaScript links.")
		finding.Context = context
		finding.Disposition = model.DispositionReview
		if isContextual(context) {
			finding.Disposition = model.DispositionInformational
		}
		add(finding)
	}
}

func innerPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "!")
	return parts[len(parts)-1]
}

func activeElement(element xml.StartElement) string {
	if strings.EqualFold(element.Name.Local, "script") && executableScript(element.Attr) {
		return "SVG script element"
	}
	for _, attr := range element.Attr {
		name := strings.ToLower(attr.Name.Local)
		if len(name) > 2 && strings.HasPrefix(name, "on") && strings.TrimSpace(attr.Value) != "" {
			return "SVG " + name + " event handler"
		}
		if name == "href" {
			if reason := activeLink(attr.Value); reason != "" {
				return reason
			}
		}
	}
	return ""
}

func activeLink(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(value, "javascript:"):
		return "SVG JavaScript link"
	case strings.HasPrefix(value, "vbscript:"):
		return "SVG VBScript link"
	case strings.HasPrefix(value, "data:"):
		metadata, _, ok := strings.Cut(strings.TrimPrefix(value, "data:"), ",")
		if !ok {
			return ""
		}
		mediaType, _, _ := strings.Cut(metadata, ";")
		switch strings.TrimSpace(mediaType) {
		case "text/html", "application/xhtml+xml", "image/svg+xml", "text/javascript", "application/javascript":
			return "SVG active data link"
		}
	}
	return ""
}

func executableScript(attrs []xml.Attr) bool {
	for _, attr := range attrs {
		if !strings.EqualFold(attr.Name.Local, "type") {
			continue
		}
		kind, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(attr.Value)), ";")
		switch strings.TrimSpace(kind) {
		case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript":
			return true
		default:
			return false
		}
	}
	return true
}
