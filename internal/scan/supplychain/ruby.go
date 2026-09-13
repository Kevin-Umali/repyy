package supplychain

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

var rubySourceLine = regexp.MustCompile(`(?i)^\s*source\s+["']([^"']+)["']`)

func (d Detector) scanRubySources(path string, data []byte, add func(model.Finding)) {
	base := strings.ToLower(filepath.Base(innerPath(path)))
	for index, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if base == "gemfile" {
			m := rubySourceLine.FindStringSubmatch(line)
			if len(m) != 2 || isDefaultRubyGems(m[1]) {
				continue
			}
		} else if !strings.HasPrefix(strings.ToUpper(trimmed), "BUNDLE_MIRROR__") {
			continue
		}
		f := d.finding("RUBY-002", "ruby-package-source", model.SeverityMedium, model.ConfidenceMedium, path, index+1, "Bundler package source is redirected", d.safeEvidence([]byte(line)), "Verify the gem source or mirror and review the resolved Gemfile.lock.")
		f.Context = "manifest"
		add(f)
	}
}

func isDefaultRubyGems(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && trustedSourceHost(u, "rubygems.org") && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
}
