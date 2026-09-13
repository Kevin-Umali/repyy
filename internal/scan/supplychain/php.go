package supplychain

import (
	"encoding/json"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func (d Detector) scanComposerSources(path string, data []byte, add func(model.Finding)) {
	var doc struct {
		Repositories json.RawMessage `json:"repositories"`
		Config       struct {
			AllowPlugins json.RawMessage `json:"allow-plugins"`
		} `json:"config"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return
	}
	var repositories any
	if json.Unmarshal(doc.Repositories, &repositories) == nil && nonemptyJSONCollection(repositories) {
		f := d.finding("PHP-002", "composer-package-source", model.SeverityMedium, model.ConfidenceMedium, path, lineForToken(data, "repositories"), "Composer defines alternate package repositories", "composer.json repositories setting", "Review repository precedence and the resolved composer.lock before installing.")
		f.Context = "manifest"
		add(f)
	}
	if !composerAllowsAllPlugins(doc.Config.AllowPlugins) {
		return
	}
	f := d.finding("PHP-003", "composer-plugin-execution", model.SeverityHigh, model.ConfidenceHigh, path, lineForToken(data, "allow-plugins"), "Composer permits every dependency plugin to execute", "allow-plugins wildcard", "Replace the wildcard with explicit reviewed plugin names or disable plugins.")
	f.Context = "manifest-hook"
	add(f)
}

func composerAllowsAllPlugins(raw json.RawMessage) bool {
	var allowAll bool
	if json.Unmarshal(raw, &allowAll) == nil {
		return allowAll
	}
	var allowed map[string]bool
	return json.Unmarshal(raw, &allowed) == nil && allowed["*"]
}

func nonemptyJSONCollection(value any) bool {
	switch collection := value.(type) {
	case []any:
		return len(collection) > 0
	case map[string]any:
		return len(collection) > 0
	default:
		return false
	}
}
