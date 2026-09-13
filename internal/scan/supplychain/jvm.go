package supplychain

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

const (
	jvmWrapperSourceRule     = "JVMWRAP-001"
	jvmWrapperMissingSHARule = "JVMWRAP-002"
	jvmWrapperInvalidSHARule = "JVMWRAP-003"
)

var jvmWrapperSHA256 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// scanJVMWrapper inspects the two wrapper property files that download a JVM
// build distribution before the build itself can run. It deliberately treats
// organization mirrors as reviewable rather than malicious: they are common,
// but change the source that repository users execute.
func (d Detector) scanJVMWrapper(path string, data []byte, add func(model.Finding)) {
	kind, ok := jvmWrapperKind(path)
	if !ok {
		return
	}
	properties := parseJVMWrapperProperties(data)
	distributionURL, hasDistributionURL := properties.values["distributionUrl"]
	if !hasDistributionURL || !trustedJVMWrapperDistribution(kind, distributionURL) {
		line := properties.lines["distributionUrl"]
		evidence := "distributionUrl is missing"
		if hasDistributionURL {
			evidence = d.safeEvidence([]byte(distributionURL))
		}
		finding := d.finding(jvmWrapperSourceRule, "jvm-wrapper-source", model.SeverityHigh, model.ConfidenceHigh, path, line,
			"JVM wrapper distribution URL is missing or redirects from the official source", evidence,
			"Use the official HTTPS distribution endpoint, or review and pin the approved organization mirror before running the wrapper.")
		finding.Context = "manifest"
		finding.Disposition = model.DispositionReview
		add(finding)
	}

	checksum, hasChecksum := properties.values["distributionSha256Sum"]
	if !hasChecksum || strings.TrimSpace(checksum) == "" {
		finding := d.finding(jvmWrapperMissingSHARule, "jvm-wrapper-integrity", model.SeverityMedium, model.ConfidenceHigh, path, properties.lines["distributionUrl"],
			"JVM wrapper distribution has no expected SHA-256", "distributionSha256Sum is missing",
			"Record the reviewed distribution SHA-256 in distributionSha256Sum so the wrapper can verify the downloaded archive.")
		finding.Context = "manifest"
		finding.Disposition = model.DispositionHarden
		add(finding)
		return
	}
	if !jvmWrapperSHA256.MatchString(strings.TrimSpace(checksum)) {
		finding := d.finding(jvmWrapperInvalidSHARule, "jvm-wrapper-integrity", model.SeverityHigh, model.ConfidenceHigh, path, properties.lines["distributionSha256Sum"],
			"JVM wrapper distribution SHA-256 is malformed", d.safeEvidence([]byte(checksum)),
			"Replace distributionSha256Sum with the reviewed 64-character hexadecimal SHA-256 for the configured distribution.")
		finding.Context = "manifest"
		finding.Disposition = model.DispositionReview
		add(finding)
	}
}

func jvmWrapperKind(path string) (string, bool) {
	path = strings.ToLower(filepath.ToSlash(innerPath(path)))
	switch {
	case strings.HasSuffix(path, "/gradle/wrapper/gradle-wrapper.properties") || path == "gradle/wrapper/gradle-wrapper.properties":
		return "gradle", true
	case strings.HasSuffix(path, "/.mvn/wrapper/maven-wrapper.properties") || path == ".mvn/wrapper/maven-wrapper.properties":
		return "maven", true
	default:
		return "", false
	}
}

// IsJVMWrapper reports whether a path is a known JVM wrapper configuration.
func IsJVMWrapper(path string) bool {
	_, ok := jvmWrapperKind(path)
	return ok
}

type jvmWrapperProperties struct {
	values map[string]string
	lines  map[string]int
}

func parseJVMWrapperProperties(data []byte) jvmWrapperProperties {
	result := jvmWrapperProperties{values: map[string]string{}, lines: map[string]int{}}
	lines := strings.Split(string(data), "\n")
	for index := 0; index < len(lines); index++ {
		line, startLine := lines[index], index+1
		for propertyLineContinues(line) && index+1 < len(lines) {
			line = strings.TrimSuffix(line, "\\") + strings.TrimLeft(lines[index+1], " \t\f")
			index++
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		separator := strings.IndexAny(trimmed, "=:")
		if separator < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:separator])
		if key != "distributionUrl" && key != "distributionSha256Sum" {
			continue
		}
		result.values[key] = unescapeJVMWrapperValue(strings.TrimSpace(trimmed[separator+1:]))
		result.lines[key] = startLine
	}
	return result
}

func propertyLineContinues(line string) bool {
	line = strings.TrimRight(line, " \t\r\f")
	backslashes := 0
	for index := len(line) - 1; index >= 0 && line[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func unescapeJVMWrapperValue(value string) string {
	value = strings.ReplaceAll(value, `\:`, `:`)
	value = strings.ReplaceAll(value, `\=`, `=`)
	return strings.ReplaceAll(value, `\\`, `\`)
}

func trustedJVMWrapperDistribution(kind, rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != "" && parsed.Port() != "443" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	path := parsed.EscapedPath()
	switch kind {
	case "gradle":
		return (host == "services.gradle.org" || host == "downloads.gradle.org") && strings.HasPrefix(path, "/distributions/")
	case "maven":
		return host == "repo.maven.apache.org" && strings.HasPrefix(path, "/maven2/") ||
			host == "repository.apache.org" && strings.HasPrefix(path, "/content/repositories/")
	default:
		return false
	}
}
