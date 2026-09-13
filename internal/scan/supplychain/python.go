package supplychain

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

var pipSourceOption = regexp.MustCompile(`(?i)^\s*(--extra-index-url|extra-index-url|--index-url|index-url|-i|--find-links|-f)\s*(?:=|\s)\s*([^\s#]+)`)

func (d Detector) scanPipSources(path string, data []byte, add func(model.Finding)) {
	base := strings.ToLower(filepath.Base(innerPath(path)))
	inPipfileSource := false
	for index, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if base == "pipfile" {
			if strings.HasPrefix(trimmed, "[") {
				inPipfileSource = strings.EqualFold(trimmed, "[[source]]")
				continue
			}
			if !inPipfileSource || !strings.HasPrefix(strings.ToLower(trimmed), "url") {
				continue
			}
			_, value, ok := strings.Cut(trimmed, "=")
			if !ok {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			if !isDefaultPyPI(value) {
				f := d.finding("PY-003", "python-package-source", model.SeverityMedium, model.ConfidenceMedium, path, index+1, "Pipfile uses an alternate package source", d.safeEvidence([]byte(line)), "Verify the package source and constrain private package names to trusted indexes.")
				f.Context = "manifest"
				add(f)
			}
			continue
		}
		matches := pipSourceOption.FindStringSubmatch(trimmed)
		if len(matches) != 3 {
			continue
		}
		option, value := strings.ToLower(matches[1]), strings.Trim(matches[2], `"'`)
		if isDefaultPyPI(value) {
			continue
		}
		if (option == "--find-links" || option == "-f") && !strings.HasPrefix(strings.ToLower(value), "http://") && !strings.HasPrefix(strings.ToLower(value), "https://") {
			continue
		}
		severity := model.SeverityMedium
		if option == "--extra-index-url" || option == "extra-index-url" || strings.HasPrefix(strings.ToLower(value), "http://") {
			severity = model.SeverityHigh
		}
		f := d.finding("PY-003", "python-package-source", severity, model.ConfidenceMedium, path, index+1, "pip configuration changes package lookup sources", d.safeEvidence([]byte(line)), "Verify the source and avoid mixing public and private indexes for the same package names.")
		f.Context = "manifest"
		add(f)
	}
}

func (d Detector) scanPythonProjectSources(path string, data []byte, add func(model.Finding)) {
	section := ""
	uvConfig := strings.EqualFold(filepath.Base(innerPath(path)), "uv.toml")
	for index, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rustStripComment(raw))
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, value, assigned := strings.Cut(line, "=")
		if !assigned {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		alternateSource := (section == "tool.uv.index" || section == "tool.poetry.source" || section == "tool.pdm.source" || section == "index") && key == "url"
		unsafeStrategy := (section == "tool.uv" || section == "tool.uv.pip" || uvConfig && (section == "" || section == "pip")) && key == "index-strategy" && (value == "unsafe-first-match" || value == "unsafe-best-match")
		if !alternateSource && !unsafeStrategy {
			continue
		}
		if alternateSource && isDefaultPyPI(value) {
			continue
		}
		severity := model.SeverityMedium
		message := "Python project defines an alternate package index"
		if unsafeStrategy {
			severity = model.SeverityHigh
			message = "Python project selects a dependency-confusion-prone index strategy"
		}
		f := d.finding("PY-003", "python-package-source", severity, model.ConfidenceMedium, path, index+1, message, d.safeEvidence([]byte(raw)), "Verify the package source and constrain private package names to trusted indexes.")
		f.Context = "manifest"
		add(f)
	}
}

func isDefaultPyPI(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && trustedSourceHost(u, "pypi.org") && (u.Path == "/simple" || u.Path == "/simple/") && u.RawQuery == "" && u.Fragment == ""
}
