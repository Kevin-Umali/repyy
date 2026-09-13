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
	Alias     string `json:"alias,omitempty"`
	Line      int    `json:"line,omitempty"`
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
	if separator := strings.LastIndex(path, "!"); separator >= 0 {
		path = path[separator+1:]
	}
	base := filepath.Base(path)
	var dependencies []Dependency
	var supported bool
	switch {
	case base == "package.json":
		dependencies, supported = parseJSONMaps("npm", data, "dependencies", "devDependencies", "optionalDependencies", "peerDependencies"), true
	case base == "composer.json":
		dependencies, supported = parseJSONMaps("composer", data, "require", "require-dev"), true
	case base == "pom.xml":
		dependencies, supported = parseMaven(data), true
	case base == "packages.config" || base == "Directory.Packages.props" || strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") || strings.HasSuffix(base, ".vbproj"):
		dependencies, supported = parseXMLPackages(data), true
	case base == "go.mod":
		dependencies, supported = parseGoMod(data), true
	case base == "Cargo.toml":
		dependencies, supported = parseTOMLSections("rust", data, "dependencies", "dev-dependencies", "build-dependencies"), true
	case base == "Gemfile":
		dependencies, supported = parseGemfile(data), true
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		dependencies, supported = parseRequirements(data), true
	case base == "pyproject.toml":
		dependencies, supported = parsePyProject(data), true
	default:
		return nil, false
	}
	attachLines(data, dependencies)
	return dependencies, supported
}

func attachLines(data []byte, dependencies []Dependency) {
	for i := range dependencies {
		needles := []string{dependencies[i].Name}
		if dependencies[i].Alias != "" {
			needles = append([]string{dependencies[i].Alias}, needles...)
		}
		if separator := strings.LastIndex(dependencies[i].Name, ":"); separator >= 0 {
			needles = append(needles, dependencies[i].Name[separator+1:])
		}
		for _, needle := range needles {
			if dependencies[i].Line = DeclarationLine(data, needle); dependencies[i].Line > 0 {
				break
			}
		}
	}
}

// DeclarationLine returns the first line containing token as a complete
// manifest identifier or quoted value, avoiding package-name substrings.
func DeclarationLine(data []byte, token string) int {
	if token == "" {
		return 0
	}
	for lineIndex, line := range strings.Split(string(data), "\n") {
		for offset := 0; ; {
			found := strings.Index(line[offset:], token)
			if found < 0 {
				break
			}
			found += offset
			leftOK := found == 0 || !manifestTokenByte(line[found-1])
			right := found + len(token)
			rightOK := right == len(line) || !manifestTokenByte(line[right])
			if leftOK && rightOK {
				return lineIndex + 1
			}
			offset = found + 1
		}
	}
	return 0
}

func manifestTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("_.@/-:", rune(value))
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
			out = append(out, Dependency{Ecosystem: ecosystem, Name: name, Version: version, Scope: key})
			if ecosystem == "npm" {
				if target, targetVersion, alias := NPMAlias(version); alias && target != name {
					out = append(out, Dependency{Ecosystem: ecosystem, Name: target, Version: targetVersion, Scope: key + ":alias-target", Alias: name})
				}
			}
		}
	}
	return sorted(out)
}

// NPMAlias extracts the actual registry package from an npm: alias specifier.
func NPMAlias(spec string) (name, version string, ok bool) {
	if !strings.HasPrefix(spec, "npm:") {
		return "", "", false
	}
	value := strings.TrimPrefix(spec, "npm:")
	if value == "" {
		return "", "", false
	}
	lastAt := strings.LastIndex(value, "@")
	if lastAt > 0 {
		name, version = value[:lastAt], value[lastAt+1:]
	} else {
		name = value
	}
	if name == "" || strings.ContainsAny(name, " \t\r\n") {
		return "", "", false
	}
	return name, version, true
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
			out = append(out, Dependency{Ecosystem: "go", Name: fields[0], Version: fields[1], Scope: "require"})
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
			out = append(out, Dependency{Ecosystem: ecosystem, Name: m[1], Version: m[2], Scope: section})
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
			out = append(out, Dependency{Ecosystem: "pip", Name: m[1], Version: m[2] + m[3], Scope: "requirement"})
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
		out = append(out, Dependency{Ecosystem: "rubygems", Name: m[1], Version: m[2], Scope: "gem"})
	}
	return sorted(out)
}

func parseXMLPackages(data []byte) []Dependency {
	type node struct {
		ID       string `xml:"id,attr"`
		Include  string `xml:"Include,attr"`
		Update   string `xml:"Update,attr"`
		Version  string `xml:"version,attr"`
		Version2 string `xml:"Version,attr"`
	}
	var root struct {
		Packages   []node `xml:"package"`
		References []node `xml:"ItemGroup>PackageReference"`
		Versions   []node `xml:"ItemGroup>PackageVersion"`
	}
	if xml.Unmarshal(data, &root) != nil {
		return nil
	}
	var out []Dependency
	for _, n := range append(append(root.Packages, root.References...), root.Versions...) {
		name := n.ID
		if name == "" {
			name = n.Include
		}
		if name == "" {
			name = n.Update
		}
		version := n.Version
		if version == "" {
			version = n.Version2
		}
		if name != "" {
			out = append(out, Dependency{Ecosystem: "nuget", Name: name, Version: version, Scope: "package"})
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
			out = append(out, Dependency{Ecosystem: "maven", Name: d.GroupID + ":" + d.ArtifactID, Version: d.Version, Scope: d.Scope})
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
