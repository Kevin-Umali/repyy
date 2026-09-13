package supplychain

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// ScanFile inspects one readable file for supply-chain risks.
func (d Detector) ScanFile(path string, data []byte, add func(model.Finding)) {
	if strings.EqualFold(filepath.Base(innerPath(path)), "package.json") {
		d.scanPackageJSON(path, data, add)
	}
	d.scanPackageSourceRisks(path, data, add)
	d.scanRustSupplyChain(path, data, add)
	d.scanJVMWrapper(path, data, add)
}

func (d Detector) scanPackageSourceRisks(path string, data []byte, add func(model.Finding)) {
	base := strings.ToLower(filepath.Base(innerPath(path)))
	switch {
	case base == "package.json":
		d.scanNPMOverrides(path, data, add)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"), base == "pip.conf", base == "pip.ini", base == "pipfile":
		d.scanPipSources(path, data, add)
	case base == "pyproject.toml" || base == "uv.toml":
		d.scanPythonProjectSources(path, data, add)
	case base == ".yarnrc.yml":
		d.scanYarnRuntime(path, data, add)
	case base == "gemfile" || strings.HasSuffix("/"+filepath.ToSlash(strings.ToLower(innerPath(path))), "/.bundle/config"):
		d.scanRubySources(path, data, add)
	case base == "composer.json":
		d.scanComposerSources(path, data, add)
	case base == "nuget.config":
		d.scanNuGetSources(path, data, add)
	case base == "go.mod" || base == "go.work":
		d.scanGoReplacementBlock(path, data, add)
	case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") || strings.HasSuffix(base, ".vbproj") || strings.HasSuffix(base, ".props") || strings.HasSuffix(base, ".targets"):
		d.scanMSBuildCommands(path, data, add)
	}
}

func trustedSourceHost(u *url.URL, host string) bool {
	return u.Scheme == "https" && u.User == nil && strings.EqualFold(u.Hostname(), host) && (u.Port() == "" || u.Port() == "443")
}
