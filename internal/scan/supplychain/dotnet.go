package supplychain

import (
	"encoding/xml"
	"io"
	"net/url"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func (d Detector) scanMSBuildCommands(path string, data []byte, add func(model.Finding)) {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	rootSeen := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			return
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !rootSeen {
			rootSeen = true
			if !strings.EqualFold(start.Name.Local, "Project") {
				return
			}
		}
		if !strings.EqualFold(start.Name.Local, "Exec") {
			continue
		}
		for _, attribute := range start.Attr {
			if !strings.EqualFold(attribute.Name.Local, "Command") || strings.TrimSpace(attribute.Value) == "" {
				continue
			}
			line := lineForToken(data, attribute.Value)
			if line == 0 {
				line = lineForToken(data, "Exec")
			}
			f := d.finding("DOTNET-001", "dotnet-build-execution", model.SeverityHigh, model.ConfidenceMedium, path, line, "MSBuild project or imported file runs a command", d.safeEvidence([]byte(attribute.Value)), "Inspect the Exec command and its conditions before building or restoring the project.")
			f.Context = "manifest-hook"
			add(f)
		}
	}
}

func (d Detector) scanNuGetSources(path string, data []byte, add func(model.Finding)) {
	var sources []struct{ key, value string }
	wildcard := map[string]bool{}
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	var stack []string
	mappingSource := ""
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
		switch node := token.(type) {
		case xml.StartElement:
			name := strings.ToLower(node.Name.Local)
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			} else if name != "configuration" {
				return
			}
			if parent == "packagesources" && name == "add" {
				sources = append(sources, struct{ key, value string }{xmlAttribute(node.Attr, "key"), xmlAttribute(node.Attr, "value")})
			}
			if parent == "packagesourcemapping" && name == "packagesource" {
				mappingSource = xmlAttribute(node.Attr, "key")
			}
			if parent == "packagesource" && name == "package" && xmlAttribute(node.Attr, "pattern") == "*" {
				wildcard[strings.ToLower(mappingSource)] = true
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	for _, source := range sources {
		if source.value == "" || isDefaultNuGet(source.value) {
			continue
		}
		severity := model.SeverityMedium
		if wildcard[strings.ToLower(source.key)] || strings.HasPrefix(strings.ToLower(source.value), "http://") {
			severity = model.SeverityHigh
		}
		line := lineForToken(data, source.value)
		if line == 0 {
			line = lineForToken(data, source.key)
		}
		f := d.finding("NUGET-001", "nuget-package-source", severity, model.ConfidenceMedium, path, line, "NuGet package source can supply dependencies: "+source.key, d.safeEvidence([]byte(source.value)), "Verify the feed and constrain package source mapping to intended package names.")
		f.Context = "manifest"
		add(f)
	}
}

func xmlAttribute(attributes []xml.Attr, name string) string {
	for _, attribute := range attributes {
		if strings.EqualFold(attribute.Name.Local, name) {
			return attribute.Value
		}
	}
	return ""
}

func isDefaultNuGet(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && trustedSourceHost(u, "api.nuget.org") && u.Path == "/v3/index.json" && u.RawQuery == "" && u.Fragment == ""
}
