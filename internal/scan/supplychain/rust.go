package supplychain

import (
	"bytes"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// scanRustSupplyChain identifies Cargo configuration that changes the source
// of dependencies. It is intentionally text-only: it does not resolve
// registries or run Cargo.
func (d Detector) scanRustSupplyChain(path string, data []byte, add func(model.Finding)) {
	path = filepath.ToSlash(innerPath(path))
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "cargo.toml":
		d.scanRustManifest(path, data, add)
	case base == "config.toml" && strings.EqualFold(filepath.Base(filepath.Dir(path)), ".cargo"):
		d.scanRustConfig(path, data, add)
	}
}

// CargoBuildInventory pairs build.rs with a package manifest during one scan.
// Keeping this state local avoids leaking paths across Scanner.Scan calls.
type CargoBuildInventory struct {
	manifestByDir    map[string]bool
	buildScriptByDir map[string]string
}

func NewCargoBuildInventory() CargoBuildInventory {
	return CargoBuildInventory{
		manifestByDir:    make(map[string]bool),
		buildScriptByDir: make(map[string]string),
	}
}

// Observe records one readable repository file. The caller screens out binary data.
func (inventory CargoBuildInventory) Observe(path string, data []byte) {
	dir := filepath.Dir(path)
	switch strings.ToLower(filepath.Base(path)) {
	case "cargo.toml":
		inventory.manifestByDir[dir] = cargoDiscoversBuildScript(data)
	case "build.rs":
		inventory.buildScriptByDir[dir] = path
	}
}

// Report emits build-script findings after all repository files are observed.
func (inventory CargoBuildInventory) Report(d Detector, add func(model.Finding)) {
	dirs := make([]string, 0, len(inventory.buildScriptByDir))
	for dir := range inventory.buildScriptByDir {
		if inventory.manifestByDir[dir] {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		path := inventory.buildScriptByDir[dir]
		finding := d.finding("RUST-002", "rust-build-script", model.SeverityMedium, model.ConfidenceHigh, path, 1,
			"Cargo automatically executes a package build.rs during build", "implicit Cargo build script",
			"Inspect build.rs and its build dependencies before compiling the package.")
		finding.Context = "manifest-hook"
		add(finding)
	}
}

func (d Detector) scanRustManifest(path string, data []byte, add func(model.Finding)) {
	lines := rustLines(data)
	seen := make(map[string]bool)
	for _, line := range lines {
		if rustUsesAlternateDependencySource(line) {
			finding := d.finding("RUST-005", "rust-dependency-source", model.SeverityHigh, model.ConfidenceMedium, path, line.number,
				"Cargo dependency uses a non-default source", "Cargo dependency git/path/registry source", "Verify the dependency source and pin remote revisions before building.")
			finding.Context = "manifest"
			finding.Disposition = model.DispositionReview
			add(finding)
		}
		section := ""
		switch {
		case line.section == "patch" || strings.HasPrefix(line.section, "patch."):
			section = "patch"
		case line.section == "replace":
			section = "replace"
		}
		if section != "" && !seen[section] {
			finding := d.finding("RUST-004", "rust-dependency-override", model.SeverityHigh, model.ConfidenceMedium, path, line.number,
				"Cargo dependency source override", "["+line.section+"]", "Verify the replacement source and pin the reviewed dependency revision.")
			finding.Context = "manifest"
			finding.Disposition = model.DispositionReview
			add(finding)
			seen[section] = true
		}
	}
}

func rustUsesAlternateDependencySource(line rustLine) bool {
	if !rustDependencySection(line.section) {
		return false
	}
	if rustInlineSource.MatchString(line.value) {
		return true
	}
	return rustDependencySubtable(line.section) && (line.key == "git" || line.key == "path" || line.key == "registry")
}

func (d Detector) scanRustConfig(path string, data []byte, add func(model.Finding)) {
	for _, line := range rustLines(data) {
		if (strings.HasPrefix(line.section, "source.") && (line.key == "replace-with" || line.key == "registry")) ||
			(strings.HasPrefix(line.section, "registries.") && line.key == "index") {
			finding := d.finding("RUST-003", "rust-registry-redirection", model.SeverityHigh, model.ConfidenceHigh, path, line.number,
				"Cargo configuration redirects dependency resolution", line.section+"."+line.key, "Verify the registry or source replacement is trusted and expected before fetching dependencies.")
			finding.Context = "manifest"
			finding.Disposition = model.DispositionReview
			add(finding)
		}
	}
}

type rustLine struct {
	number  int
	section string
	key     string
	value   string
}

var rustInlineSource = regexp.MustCompile(`(?i)\b(?:git|path|registry)\s*=`)

func rustDependencySection(section string) bool {
	return section == "dependencies" || section == "dev-dependencies" || section == "build-dependencies" || section == "workspace.dependencies" ||
		strings.HasPrefix(section, "dependencies.") || strings.HasPrefix(section, "dev-dependencies.") || strings.HasPrefix(section, "build-dependencies.") ||
		strings.Contains(section, ".dependencies") || strings.Contains(section, ".dev-dependencies") || strings.Contains(section, ".build-dependencies")
}

func rustDependencySubtable(section string) bool {
	return strings.HasPrefix(section, "dependencies.") || strings.HasPrefix(section, "dev-dependencies.") || strings.HasPrefix(section, "build-dependencies.") ||
		strings.Contains(section, ".dependencies.") || strings.Contains(section, ".dev-dependencies.") || strings.Contains(section, ".build-dependencies.")
}

// rustLines is a deliberately small TOML reader for the table headers and
// assignments relevant to Cargo supply-chain configuration. It preserves line
// numbers and ignores comments outside quoted strings.
func rustLines(data []byte) []rustLine {
	section := ""
	var out []rustLine
	for index, raw := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSpace(rustStripComment(string(raw)))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out = append(out, rustLine{number: index + 1, section: section, key: strings.ToLower(strings.TrimSpace(key)), value: strings.TrimSpace(value)})
	}
	return out
}

func rustStripComment(line string) string {
	quote := rune(0)
	escaped := false
	for index, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if quote != 0 && r == '\\' {
			escaped = true
			continue
		}
		if r == '\'' || r == '"' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			}
			continue
		}
		if r == '#' && quote == 0 {
			return line[:index]
		}
	}
	return line
}

func cargoDiscoversBuildScript(data []byte) bool {
	section := ""
	hasPackage := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rustStripComment(raw))
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.Trim(line, "[]"))
			if section == "package" {
				hasPackage = true
			}
			continue
		}
		if section == "package" {
			key, _, assigned := strings.Cut(line, "=")
			if assigned && strings.TrimSpace(key) == "build" {
				// An explicit path has its own RUST-001 finding; false disables discovery.
				return false
			}
		}
	}
	return hasPackage
}
