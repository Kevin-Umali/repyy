package supplychain

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/manifest"
	"github.com/Kevin-Umali/repyy/internal/model"
	"gopkg.in/yaml.v3"
)

type packageJSON struct {
	Scripts      map[string]string `json:"scripts"`
	Dependencies map[string]string `json:"dependencies"`
	Dev          map[string]string `json:"devDependencies"`
	Optional     map[string]string `json:"optionalDependencies"`
	Peer         map[string]string `json:"peerDependencies"`
	Bin          any               `json:"bin"`
}

func (d Detector) scanPackageJSON(path string, data []byte, add func(model.Finding)) {
	var pkg packageJSON
	if json.Unmarshal(data, &pkg) != nil {
		return
	}
	d.scanNPMScripts(path, data, pkg.Scripts, add)
	d.scanNPMDependencies(path, data, pkg, add)
	d.scanNPMBinaries(path, data, pkg.Bin, add)
}

func isNPMInstallHook(name string) bool {
	switch name {
	case "preinstall", "install", "postinstall", "prepare", "prepublish":
		return true
	}
	return false
}

func (d Detector) scanNPMScripts(path string, data []byte, scripts map[string]string, add func(model.Finding)) {
	for name, cmd := range scripts {
		if isNPMInstallHook(name) {
			severity, confidence := model.SeverityMedium, model.ConfidenceMedium
			if suspiciousCommand(cmd) {
				severity, confidence = model.SeverityCritical, model.ConfidenceHigh
			}
			f := d.finding("PKG-001", "package-lifecycle", severity, confidence, path, lineForToken(data, name), "Package lifecycle script: "+name, d.safeEvidence([]byte(cmd)), "Review this script before installing dependencies.")
			f.Context = "manifest-hook"
			add(f)
			continue
		}
		if suspiciousCommand(cmd) {
			f := d.finding("PKG-007", "package-script", model.SeverityHigh, model.ConfidenceMedium, path, lineForToken(data, name), "Non-lifecycle package script downloads and executes content: "+name, d.safeEvidence([]byte(cmd)), "Review the script before running package-manager commands such as test, dev, or start.")
			f.Context = "manifest-hook"
			add(f)
		}
	}
}

func (d Detector) scanNPMDependencies(path string, data []byte, pkg packageJSON, add func(model.Finding)) {
	dependencies := make(map[string]string)
	for _, scope := range []map[string]string{pkg.Dependencies, pkg.Dev, pkg.Optional, pkg.Peer} {
		for name, version := range scope {
			dependencies[name] = version
		}
	}
	for name, version := range dependencies {
		if target, _, alias := manifest.NPMAlias(version); alias && target != name {
			f := d.finding("PKG-009", "dependency-alias", model.SeverityMedium, model.ConfidenceMedium, path, lineForToken(data, name), "Dependency alias changes package identity: "+name, "actual package: "+d.safeEvidence([]byte(target)), "Verify the alias target, publisher, and resolved artifact before installing.")
			f.Context = "manifest"
			add(f)
		}
		if source, ok := nonRegistryNPMSource(version); ok {
			add(d.finding("PKG-002", "suspicious-dependency-source", model.SeverityHigh, model.ConfidenceMedium, path, lineForToken(data, name), "Dependency uses a non-registry source: "+name, "source type: "+source, "Verify the dependency source and pin it to an immutable trusted revision."))
		}
		if version == "0.0.0" || version == "0.0.1" {
			add(d.finding("PKG-003", "suspicious-dependency-version", model.SeverityMedium, model.ConfidenceMedium, path, lineForToken(data, name), "Dependency uses a placeholder-like version: "+name, "version: "+version, "Verify the package name and version."))
		}
		if inflatedMajorVersion(version) {
			f := d.finding("PKG-005", "dependency-confusion", model.SeverityMedium, model.ConfidenceMedium, path, lineForToken(data, name), "Dependency uses an unusually high major version: "+name, "version: "+d.safeEvidence([]byte(version)), "Verify whether a public package is shadowing an internal dependency and inspect the resolved registry and integrity hash.")
			f.Context = "manifest"
			add(f)
		}
	}
}

func (d Detector) scanNPMBinaries(path string, data []byte, bin any, add func(model.Finding)) {
	if bin == nil {
		return
	}
	add(d.finding("PKG-004", "package-binary", model.SeverityLow, model.ConfidenceMedium, path, lineForToken(data, "bin"), "Package exposes an executable command", "package.json contains a bin field", "Inspect the referenced executable before installing globally."))
	for _, target := range binTargets(bin) {
		if escapingManifestPath(target) || suspiciousBinTarget(target) {
			f := d.finding("PKG-006", "package-binary", model.SeverityHigh, model.ConfidenceHigh, path, lineForToken(data, target), "Package bin target escapes the package or embeds execution behavior", d.safeEvidence([]byte(target)), "Do not install the package until the bin target is constrained to a reviewed local file.")
			f.Context = "manifest-hook"
			add(f)
		}
	}
}

func inflatedMajorVersion(version string) bool {
	v := strings.TrimLeft(strings.TrimSpace(version), "~^<>=v ")
	majorText, _, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	major, err := strconv.Atoi(majorText)
	return err == nil && major >= 90
}

func binTargets(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case map[string]any:
		out := make([]string, 0, len(v))
		for _, target := range v {
			if s, ok := target.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func escapingManifestPath(target string) bool {
	target = filepath.ToSlash(strings.TrimSpace(target))
	clean := filepath.ToSlash(filepath.Clean(target))
	return filepath.IsAbs(target) || windowsAbsPath.MatchString(target) || clean == ".." || strings.HasPrefix(clean, "../")
}

func suspiciousBinTarget(target string) bool {
	return strings.ContainsAny(target, ";|`") || strings.Contains(target, "$(") || strings.Contains(target, "${")
}

func nonRegistryNPMSource(spec string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(spec))
	for _, prefix := range []string{"git+", "git:", "github:", "gitlab:", "bitbucket:", "http:", "https:", "file:", "link:"} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSuffix(prefix, ":"), true
		}
	}
	// npm also accepts the unqualified GitHub shorthand owner/repository.
	if parts := strings.SplitN(lower, "#", 2); len(parts[0]) > 0 && strings.Count(parts[0], "/") == 1 && !strings.ContainsAny(parts[0], " \t:@") {
		return "github shorthand", true
	}
	return "", false
}

func (d Detector) scanNPMOverrides(path string, data []byte, add func(model.Finding)) {
	var doc struct {
		Overrides   json.RawMessage `json:"overrides"`
		Resolutions json.RawMessage `json:"resolutions"`
		PNPM        struct {
			Overrides json.RawMessage `json:"overrides"`
		} `json:"pnpm"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return
	}
	for _, section := range []struct {
		name string
		raw  json.RawMessage
	}{{"overrides", doc.Overrides}, {"resolutions", doc.Resolutions}, {"pnpm.overrides", doc.PNPM.Overrides}} {
		var entries any
		if json.Unmarshal(section.raw, &entries) != nil {
			continue
		}
		walkPackageOverrides(entries, func(name, spec string) {
			if source, ok := nonRegistryNPMSource(spec); ok {
				f := d.finding("PKG-008", "dependency-override", model.SeverityHigh, model.ConfidenceMedium, path, lineForToken(data, spec), "Dependency override redirects "+name+" to a non-registry source", "source type: "+source, "Review the override and pin it to a trusted immutable artifact.")
				f.Context = "manifest"
				add(f)
			} else if target, _, alias := manifest.NPMAlias(spec); alias && target != name {
				f := d.finding("PKG-008", "dependency-override", model.SeverityHigh, model.ConfidenceMedium, path, lineForToken(data, spec), "Dependency override changes package identity: "+name, "actual package: "+d.safeEvidence([]byte(target)), "Verify the replacement package, publisher, and resolved artifact before installing.")
				f.Context = "manifest"
				add(f)
			}
		}, section.name)
	}
}

func walkPackageOverrides(value any, visit func(name, spec string), name string) {
	switch current := value.(type) {
	case string:
		visit(name, current)
	case map[string]any:
		for key, nested := range current {
			walkPackageOverrides(nested, visit, key)
		}
	}
}

func (d Detector) scanYarnRuntime(path string, data []byte, add func(model.Finding)) {
	var doc struct {
		YarnPath string `yaml:"yarnPath"`
		Plugins  []struct {
			Path string `yaml:"path"`
			Spec string `yaml:"spec"`
		} `yaml:"plugins"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return
	}
	if doc.YarnPath != "" {
		severity := model.SeverityMedium
		if escapingManifestPath(doc.YarnPath) || strings.Contains(doc.YarnPath, "://") {
			severity = model.SeverityHigh
		}
		f := d.finding("YARN-001", "package-manager-execution", severity, model.ConfidenceHigh, path, lineForToken(data, "yarnPath"), "Project selects a Yarn executable", d.safeEvidence([]byte(doc.YarnPath)), "Inspect the referenced Yarn executable before running yarn commands.")
		f.Context = "manifest-hook"
		add(f)
	}
	for _, plugin := range doc.Plugins {
		if plugin.Path == "" {
			continue
		}
		severity := model.SeverityMedium
		if escapingManifestPath(plugin.Path) || strings.Contains(plugin.Path, "://") {
			severity = model.SeverityHigh
		}
		f := d.finding("YARN-002", "package-manager-plugin", severity, model.ConfidenceHigh, path, lineForToken(data, plugin.Path), "Project loads a Yarn plugin", d.safeEvidence([]byte(plugin.Path)), "Inspect the plugin source and provenance before running yarn commands.")
		f.Context = "manifest-hook"
		add(f)
	}
}
