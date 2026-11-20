package output

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/Kevin-Umali/repyy/internal/model"
)

type sarif struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifLocation   `json:"locations"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}
type sarifInvocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	Properties          map[string]any `json:"properties,omitempty"`
}

func sarifOut(w io.Writer, report model.Report) error {
	rules := map[string]sarifRule{}
	results := []sarifResult{}
	success := true
	for _, repo := range report.Results {
		if repo.Error != "" || !repo.Coverage.Complete {
			success = false
		}
		for _, f := range repo.Findings {
			rules[f.RuleID] = sarifRule{ID: f.RuleID, ShortDescription: sarifMessage{Text: f.Message}, Properties: map[string]string{"category": f.Category, "severity": string(f.Severity), "confidence": string(f.Confidence), "context": f.Context, "disposition": string(f.Disposition)}}
			level := "warning"
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
				level = "error"
			} else if f.Severity == model.SeverityLow {
				level = "note"
			}
			findingLocations := f.Locations
			if len(findingLocations) == 0 {
				findingLocations = []model.Location{{Path: f.Path, StartLine: f.Line}}
			}
			locations := make([]sarifLocation, 0, len(findingLocations))
			for _, findingLocation := range findingLocations {
				loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: findingLocation.Path}}
				if findingLocation.StartLine > 0 {
					loc.Region = &sarifRegion{StartLine: findingLocation.StartLine, EndLine: findingLocation.EndLine}
				}
				locations = append(locations, sarifLocation{PhysicalLocation: loc})
			}
			message := f.Message
			if f.Evidence != "" {
				message += "; evidence: " + f.Evidence
			}
			results = append(results, sarifResult{RuleID: f.RuleID, Level: level, Message: sarifMessage{Text: message}, Locations: locations, Fingerprints: map[string]string{"repyy/v1": f.Fingerprint}})
		}
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	properties := map[string]any{
		"rulesVersion": report.RulesVersion,
		"toolCommit":   report.ToolCommit,
		"limitation":   model.Limitation,
		"intelligence": report.Intelligence,
	}
	doc := sarif{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "repyy", Version: report.ToolVersion, InformationURI: "https://github.com/Kevin-Umali/repyy", Rules: ruleList}}, Results: results, Invocations: []sarifInvocation{{ExecutionSuccessful: success, Properties: properties}}}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
