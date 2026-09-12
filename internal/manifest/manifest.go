// Package manifest extracts dependency declarations without executing package managers.
package manifest

import (
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Dependency is a dependency declaration found in a repository manifest.
type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

var (
	quotedAssignment = regexp.MustCompile(`^\s*["']?([^"'\s=]+)["']?\s*=\s*["']([^"']+)["']`)
	inlineVersion    = regexp.MustCompile(`^\s*["']?([^"'\s=]+)["']?\s*=\s*\{[^}]*version\s*=\s*["']([^"']+)["']`)
	gemCall          = regexp.MustCompile(`(?m)^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?`)
	requirement      = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^;#\s]+)?`)
	pep621List       = regexp.MustCompile(`(?s)dependencies\s*=\s*\[(.*?)\]`)
	quotedValue      = regexp.MustCompile(`["']([^"']+)["']`)
)

// Parse recognizes common dependency manifests. The bool reports whether the path is supported.
func Parse(path string, data []byte) ([]Dependency, bool) {
	base := filepath.Base(path)
	switch {
	case base == "package.json":
		return parseJSONMaps("npm", data, "dependencies", "devDependencies", "optionalDependencies", "peerDependencies"), true
	case base == "composer.json":
		return parseJSONMaps("composer", data, "require", "require-dev"), true
	case base == "pom.xml":
		return parseMaven(data), true
	case base == "packages.config" || strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") || strings.HasSuffix(base, ".vbproj"):
		return parseXMLPackages(data), true
	case base == "go.mod":
		return parseGoMod(data), true
	case base == "Cargo.toml":
		return parseTOMLSections("rust", data, "dependencies", "dev-dependencies", "build-dependencies"), true
	case base == "Gemfile":
		return parseGemfile(data), true
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return parseRequirements(data), true
	case base == "pyproject.toml":
		return parsePyProject(data), true
	default:
		return nil, false
	}
}

func parseJSONMaps(ecosystem string, data []byte, keys ...string) []Dependency {
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []Dependency
	for _, key := range keys {
		var deps map[string]string
		if json.Unmarshal(doc[key], &deps) != nil {
			continue
		}
		for name, version := range deps {
			out = append(out, Dependency{ecosystem, name, version, key})
		}
	}
	return sorted(out)
}

func parseGoMod(data []byte) []Dependency {
	var out []Dependency
	inBlock := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "//", 2)[0])
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inBlock {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out = append(out, Dependency{"go", fields[0], fields[1], "require"})
		}
	}
	return sorted(out)
}

func parseTOMLSections(ecosystem string, data []byte, allowed ...string) []Dependency {
	allow := map[string]bool{}
	for _, s := range allowed {
		allow[s] = true
	}
	section := ""
	var out []Dependency
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		if !allow[section] {
			continue
		}
		m := quotedAssignment.FindStringSubmatch(line)
		if len(m) != 3 {
			m = inlineVersion.FindStringSubmatch(line)
		}
		if len(m) == 3 {
			out = append(out, Dependency{ecosystem, m[1], m[2], section})
		}
	}
	return sorted(out)
}

func parseRequirements(data []byte) []Dependency {
	var out []Dependency
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := requirement.FindStringSubmatch(line)
		if len(m) > 1 && m[1] != "" {
			out = append(out, Dependency{"pip", m[1], m[2] + m[3], "requirement"})
		}
	}
	return sorted(out)
}

func parsePyProject(data []byte) []Dependency {
	out := parseTOMLSections("pip", data, "tool.poetry.dependencies", "tool.poetry.dev-dependencies", "tool.pdm.dependencies")
	for _, list := range pep621List.FindAllSubmatch(data, -1) {
		for _, quoted := range quotedValue.FindAllSubmatch(list[1], -1) {
			if deps := parseRequirements(quoted[1]); len(deps) == 1 {
				deps[0].Scope = "project.dependencies"
				out = append(out, deps[0])
			}
		}
	}
	return sorted(out)
}

func parseGemfile(data []byte) []Dependency {
	var out []Dependency
	for _, m := range gemCall.FindAllStringSubmatch(string(data), -1) {
		out = append(out, Dependency{"rubygems", m[1], m[2], "gem"})
	}
	return sorted(out)
}

func parseXMLPackages(data []byte) []Dependency {
	type node struct {
		ID       string `xml:"id,attr"`
		Include  string `xml:"Include,attr"`
		Version  string `xml:"version,attr"`
		Version2 string `xml:"Version,attr"`
	}
	var root struct {
		Packages   []node `xml:"package"`
		References []node `xml:"ItemGroup>PackageReference"`
	}
	if xml.Unmarshal(data, &root) != nil {
		return nil
	}
	var out []Dependency
	for _, n := range append(root.Packages, root.References...) {
		name := n.ID
		if name == "" {
			name = n.Include
		}
		version := n.Version
		if version == "" {
			version = n.Version2
		}
		if name != "" {
			out = append(out, Dependency{"nuget", name, version, "package"})
		}
	}
	return sorted(out)
}

func parseMaven(data []byte) []Dependency {
	type dependency struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
	}
	var project struct {
		Dependencies []dependency `xml:"dependencies>dependency"`
	}
	if xml.Unmarshal(data, &project) != nil {
		return nil
	}
	var out []Dependency
	for _, d := range project.Dependencies {
		if d.GroupID != "" && d.ArtifactID != "" {
			out = append(out, Dependency{"maven", d.GroupID + ":" + d.ArtifactID, d.Version, d.Scope})
		}
	}
	return sorted(out)
}

func sorted(in []Dependency) []Dependency {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Ecosystem != in[j].Ecosystem {
			return in[i].Ecosystem < in[j].Ecosystem
		}
		return strings.ToLower(in[i].Name) < strings.ToLower(in[j].Name)
	})
	return in
}
