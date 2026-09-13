package supplychain

import (
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func (d Detector) scanGoReplacementBlock(path string, data []byte, add func(model.Finding)) {
	inReplace := false
	for index, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "//", 2)[0])
		if line == "replace (" {
			inReplace = true
			continue
		}
		if inReplace && line == ")" {
			inReplace = false
			continue
		}
		if !inReplace || !strings.Contains(line, "=>") {
			continue
		}
		f := d.finding("GO-002", "go-module-replacement", model.SeverityMedium, model.ConfidenceMedium, path, index+1, "Go workspace or module replaces a dependency source", d.safeEvidence([]byte(raw)), "Review the replacement target before resolving modules.")
		f.Context = "manifest"
		add(f)
	}
}
