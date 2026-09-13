package scan

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/manifest"
	"github.com/Kevin-Umali/repyy/internal/model"
	"gopkg.in/yaml.v3"
)

const (
	maxLocationsPerFinding = model.MaxLocationsPerFinding
	maxLocationsPerRepo    = model.MaxLocationsPerRepo
)

// Limits bounds repository and archive work performed on untrusted input.
type Limits struct {
	MaxFiles        int
	MaxFileBytes    int64
	MaxArchiveFiles int
	MaxArchiveBytes int64
	MaxArchiveDepth int
}

// DefaultLimits returns conservative bounds suitable for interactive scans.
func DefaultLimits() Limits {
	return Limits{MaxFiles: 100_000, MaxFileBytes: 50 << 20, MaxArchiveFiles: 10_000, MaxArchiveBytes: 1 << 30, MaxArchiveDepth: 3}
}

// Options configures scanner rules, intelligence, dependency traversal, and limits.
type Options struct {
	Rules               []Rule
	Intelligence        *intel.Database
	IncludeDependencies bool
	Limits              Limits
	Progress            func(files int, bytes int64)
}

// Scanner performs deterministic, read-only static inspection.
type Scanner struct {
	opts Options
}

// New constructs a scanner and supplies safe defaults for omitted options.
func New(opts Options) *Scanner {
	if len(opts.Rules) == 0 {
		opts.Rules = BuiltinRules()
	}
	if opts.Intelligence == nil {
		opts.Intelligence = intel.Builtin()
	}
	if opts.Limits.MaxFiles == 0 {
		opts.Limits = DefaultLimits()
	}
	return &Scanner{opts: opts}
}

var dependencyDirs = map[string]bool{
	"node_modules": true, ".venv": true, "venv": true, ".tox": true,
	"vendor": true, "target": true, ".gradle": true, ".m2": true,
	"__pycache__": true, ".bundle": true, ".convex": true, ".expo": true,
	".next": true, ".turbo": true, "Pods": true, "DerivedData": true,
}

// Scan inspects one local repository root without executing its contents.
func (s *Scanner) Scan(ctx context.Context, root string) (model.Coverage, []model.Finding) {
	coverage := model.Coverage{Complete: true}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, "cannot resolve repository root: "+err.Error())
		return coverage, nil
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, "repository root is not a readable directory")
		return coverage, nil
	}
	root = resolved
	confined, err := os.OpenRoot(root)
	if err != nil {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, "cannot confine repository root")
		return coverage, nil
	}
	defer confined.Close()
	findings := make([]model.Finding, 0)
	seen := map[string]int{}
	locationTotal := 0
	locationDetailTruncated := false

	add := func(f model.Finding) {
		NormalizeFinding(&f)
		key := f.RuleID + "\x00" + f.Path + "\x00" + f.Message + "\x00" + f.Context + "\x00" + string(f.Severity) + "\x00" + string(f.Confidence)
		if index, ok := seen[key]; ok {
			increment := f.Occurrences
			if increment < 1 {
				increment = 1
			}
			findings[index].Occurrences += increment
			for _, location := range f.Locations {
				if hasLocation(findings[index].Locations, location) {
					continue
				}
				if len(findings[index].Locations) >= maxLocationsPerFinding || locationTotal >= maxLocationsPerRepo {
					findings[index].LocationsOmitted++
					locationDetailTruncated = true
					continue
				}
				findings[index].Locations = append(findings[index].Locations, location)
				locationTotal++
			}
			return
		}
		if f.Occurrences == 0 {
			f.Occurrences = 1
		}
		seen[key] = len(findings)
		if len(f.Locations) > maxLocationsPerFinding || locationTotal+len(f.Locations) > maxLocationsPerRepo {
			allowed := maxLocationsPerRepo - locationTotal
			if allowed > maxLocationsPerFinding {
				allowed = maxLocationsPerFinding
			}
			if allowed < 0 {
				allowed = 0
			}
			f.LocationsOmitted += len(f.Locations) - allowed
			f.Locations = f.Locations[:allowed]
			locationDetailTruncated = true
		}
		locationTotal += len(f.Locations)
		findings = append(findings, f)
	}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if walkErr != nil {
			coverage.Complete = false
			coverage.Warnings = append(coverage.Warnings, rel+": "+walkErr.Error())
			return nil
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				s.scanGitMetadata(ctx, root, rel, add, &coverage)
				s.reportProgress(coverage)
				return filepath.SkipDir
			}
			if !s.opts.IncludeDependencies && dependencyDirs[d.Name()] {
				coverage.Skipped = append(coverage.Skipped, rel+" (dependency/cache tree)")
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			coverage.Complete = false
			coverage.Warnings = append(coverage.Warnings, rel+": "+err.Error())
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			s.scanSymlink(root, path, rel, add)
			if d.Name() == ".git" {
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, rel+" (linked Git metadata directory)")
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, rel+" (non-regular file)")
			return nil
		}
		if coverage.FilesScanned >= s.opts.Limits.MaxFiles {
			coverage.Complete = false
			return fmt.Errorf("file-count limit reached")
		}
		coverage.FilesScanned++
		if info.Size() > s.opts.Limits.MaxFileBytes {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, rel+" (file-size limit)")
			s.reportProgress(coverage)
			return nil
		}
		file, err := openConfinedNonblocking(confined, rel)
		if err != nil {
			coverage.Complete = false
			coverage.Warnings = append(coverage.Warnings, rel+": cannot open confined file")
			return nil
		}
		openedInfo, err := file.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			file.Close()
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, rel+" (file changed while scanning)")
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(file, s.opts.Limits.MaxFileBytes+1))
		file.Close()
		if err != nil || int64(len(data)) > s.opts.Limits.MaxFileBytes || ctx.Err() != nil {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, rel+" (file read or size limit)")
			return nil
		}
		coverage.BytesScanned += int64(len(data))
		s.scanContent(rel, data, info.Mode(), add, &coverage)
		if isArchive(rel, data) {
			s.scanArchive(ctx, rel, data, 1, add, &coverage)
		}
		s.reportProgress(coverage)
		return nil
	})
	if err != nil {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, err.Error())
	}
	if ctx.Err() != nil {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, "scan timed out or was cancelled")
	}
	s.scanRepositoryHygiene(root, add)
	correlate(findings, add)
	if locationDetailTruncated {
		coverage.Warnings = append(coverage.Warnings, "finding location detail was truncated by report limits; occurrence totals remain complete")
	}
	// correlate may have appended via add; findings is updated by the closure.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Disposition.Rank() != findings[j].Disposition.Rank() {
			return findings[i].Disposition.Rank() > findings[j].Disposition.Rank()
		}
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		if findings[i].Confidence.Rank() != findings[j].Confidence.Rank() {
			return findings[i].Confidence.Rank() > findings[j].Confidence.Rank()
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].Message != findings[j].Message {
			return findings[i].Message < findings[j].Message
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return coverage, findings
}

func hasLocation(locations []model.Location, candidate model.Location) bool {
	for _, location := range locations {
		if location.Path == candidate.Path && location.StartLine == candidate.StartLine && location.EndLine == candidate.EndLine {
			return true
		}
	}
	return false
}

func (s *Scanner) reportProgress(coverage model.Coverage) {
	if s.opts.Progress != nil {
		s.opts.Progress(coverage.FilesScanned, coverage.BytesScanned)
	}
}

func correlate(findings []model.Finding, add func(model.Finding)) {
	type signalSet struct {
		rules     map[string]bool
		locations []model.Location
	}
	type signals struct {
		network, fingerprint, environment, execution, evasion signalSet
	}
	byPath := map[string]*signals{}
	for _, f := range findings {
		if f.Confidence == model.ConfidenceLow || f.Context != "executable" || f.Disposition == model.DispositionInformational {
			continue
		}
		sig := byPath[f.Path]
		if sig == nil {
			sig = &signals{
				network: signalSet{rules: map[string]bool{}}, fingerprint: signalSet{rules: map[string]bool{}},
				environment: signalSet{rules: map[string]bool{}}, execution: signalSet{rules: map[string]bool{}},
				evasion: signalSet{rules: map[string]bool{}},
			}
			byPath[f.Path] = sig
		}
		addSignal := func(set *signalSet) {
			set.rules[f.RuleID] = true
			locations := f.Locations
			if len(locations) == 0 {
				locations = []model.Location{{Path: f.Path, StartLine: f.Line, Evidence: f.Evidence}}
			}
			for _, location := range locations {
				if !hasLocation(set.locations, location) {
					set.locations = append(set.locations, location)
				}
			}
		}
		switch f.Category {
		case "remote-fetch", "exfiltration":
			addSignal(&sig.network)
		case "host-fingerprinting":
			addSignal(&sig.fingerprint)
		case "credential-harvesting", "environment-access", "secret":
			addSignal(&sig.environment)
		case "dynamic-execution", "process-execution":
			addSignal(&sig.execution)
		case "sandbox-evasion":
			addSignal(&sig.evasion)
		}
	}
	for path, sig := range byPath {
		if len(sig.network.rules) > 0 && (len(sig.fingerprint.rules) > 0 || len(sig.environment.rules) > 0) {
			h := sha256.Sum256([]byte("COMBO-001\x00" + path))
			add(correlatedFinding("COMBO-001", "collection-and-exfiltration", path, "Host or credential collection appears alongside network transfer", "Do not run until the data flow and destination are verified.", h, sig.network, sig.fingerprint, sig.environment))
		}
		if len(sig.network.rules) > 0 && len(sig.execution.rules) > 0 {
			h := sha256.Sum256([]byte("COMBO-002\x00" + path))
			finding := correlatedFinding("COMBO-002", "fetch-and-execute", path, "Network retrieval appears alongside command or code execution", "Do not run the repository; verify the fetched content and execution path.", h, sig.network, sig.execution)
			finding.Severity = model.SeverityCritical
			add(finding)
		}
		if len(sig.evasion.rules) > 0 && len(sig.execution.rules) > 0 {
			h := sha256.Sum256([]byte("COMBO-003\x00" + path))
			add(correlatedFinding("COMBO-003", "evasion-and-execution", path, "CI or sandbox evasion appears alongside dynamic execution", "Do not run until the environment checks and execution path are verified.", h, sig.evasion, sig.execution))
		}
	}
}

func correlatedFinding(id, category, path, message, remediation string, hash [32]byte, sets ...struct {
	rules     map[string]bool
	locations []model.Location
}) model.Finding {
	rules := map[string]bool{}
	locations := make([]model.Location, 0)
	for _, set := range sets {
		for ruleID := range set.rules {
			rules[ruleID] = true
		}
		for _, location := range set.locations {
			if !hasLocation(locations, location) {
				locations = append(locations, location)
			}
		}
	}
	contributors := make([]string, 0, len(rules))
	for ruleID := range rules {
		contributors = append(contributors, ruleID)
	}
	sort.Strings(contributors)
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].Path != locations[j].Path {
			return locations[i].Path < locations[j].Path
		}
		return locations[i].StartLine < locations[j].StartLine
	})
	line := 0
	if len(locations) > 0 {
		line = locations[0].StartLine
	}
	return model.Finding{
		RuleID: id, Category: category, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh,
		Context: "executable", Path: path, Line: line, Occurrences: 1, Message: message,
		Evidence: "correlated behaviors in the same file", Remediation: remediation,
		Fingerprint: "sha256:" + hex.EncodeToString(hash[:]), Locations: locations,
		ContributingRuleIDs: contributors,
	}
}

func (s *Scanner) scanContent(path string, data []byte, mode os.FileMode, add func(model.Finding), coverage *model.Coverage) {
	if executableMagic(data) {
		add(s.finding("BINARY-001", "compiled-binary", model.SeverityHigh, model.ConfidenceHigh, path, 0, "Compiled executable content is present", "executable file signature", "Verify the binary's provenance and hash before use."))
	} else if mode&0o111 != 0 {
		add(s.finding("EXECBIT-001", "executable-file", model.SeverityLow, model.ConfidenceMedium, path, 0, "File has executable permissions", "executable permission bit", "Review whether this file needs to be executable."))
	}
	if known, ok := s.opts.Intelligence.MatchHash(data); ok {
		finding := s.finding("IOC-HASH-SHA256", "known-malicious-file", model.SeverityCritical, model.ConfidenceHigh, path, 0, "File SHA-256 matches a confirmed "+known.Family+" indicator", "sha256:"+known.SHA256, "Do not execute or distribute this file. Isolate the system and follow incident-response procedures. Source: "+known.Source)
		finding.Context = "confirmed-ioc"
		add(finding)
	}
	if !looksText(data) {
		if scanRelevantText(path, data, mode) {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (undecodable source or configuration)")
		}
		return
	}
	if dependencies, supported := manifest.Parse(path, data); supported {
		for _, dependency := range dependencies {
			confirmed := false
			for _, match := range s.opts.Intelligence.MatchPackage(dependency.Ecosystem, dependency.Name, dependency.Version) {
				confirmed = true
				severity, confidence, context := model.SeverityHigh, model.ConfidenceHigh, "manifest-review"
				message := "Package name appears in confirmed malware advisory " + match.Indicator.AdvisoryID
				if match.VersionMatched {
					severity, context = model.SeverityCritical, "confirmed-ioc"
					message = "Declared package version matches confirmed malware advisory " + match.Indicator.AdvisoryID
				}
				f := s.finding("IOC-PKG-"+match.Indicator.AdvisoryID, "known-malicious-package", severity, confidence, path, dependency.Line, message, dependency.Name+" "+safeEvidence([]byte(dependency.Version)), "Do not install dependencies. Review the source advisory and resolved lockfile before proceeding: "+match.Indicator.SourceURL)
				f.Context = context
				add(f)
			}
			if !confirmed {
				if expected, ok := knownTyposquat(dependency.Ecosystem, dependency.Name); ok {
					f := s.finding("TYPOSQUAT-001", "typosquatting", model.SeverityHigh, model.ConfidenceMedium, path, dependency.Line, "Dependency resembles "+expected+": "+dependency.Name, dependency.Name+" "+safeEvidence([]byte(dependency.Version)), "Verify the dependency spelling, registry owner, publication history, and resolved artifact before installing.")
					f.Context = "manifest-review"
					add(f)
				}
			}
		}
	}

	lines := splitLines(data)
	codeData := codeProjection(path, data)
	codeLines := splitLines(codeData)
	for _, rule := range s.opts.Rules {
		if !rule.Applies(path) {
			continue
		}
		if rule.MatchScope == "structured" {
			continue
		}
		matchLines := lines
		matchData := data
		if rule.MatchScope == "code" {
			matchLines = codeLines
			matchData = codeData
		}
		matched := false
		for i, line := range matchLines {
			matches := rule.re.FindAllIndex(line, -1)
			if len(matches) == 0 {
				continue
			}
			matched = true
			originalLine := lines[i]
			if rule.ID == "GITHOOK-001" && disabledHooksPath(originalLine) {
				continue
			}
			matches = qualifyingLineMatches(rule.ID, originalLine, matches)
			if len(matches) == 0 {
				continue
			}
			severity, confidence := rule.Severity, rule.Confidence
			if rule.ID == "EXFIL-001" && lexicallySegmented(path) && !rule.re.Match(codeLines[i]) {
				confidence = model.ConfidenceLow
			}
			findingContext := matchContext(rule, path, originalLine)
			if skipContextualRule(rule.ID, findingContext) {
				continue
			}
			severity, confidence = contextualize(rule, findingContext, severity, confidence)
			finding := s.finding(rule.ID, rule.Category, severity, confidence, path, i+1, rule.Description, safeEvidence(originalLine), rule.Remediation)
			finding.Occurrences = len(matches)
			finding.Context = findingContext
			finding.Disposition = rule.Disposition
			if isContextualContext(findingContext) {
				finding.Disposition = model.DispositionInformational
			}
			add(finding)
		}
		if !matched {
			for _, loc := range rule.re.FindAllIndex(matchData, -1) {
				line := 1 + bytes.Count(matchData[:loc[0]], []byte{'\n'})
				endLine := line + bytes.Count(matchData[loc[0]:loc[1]], []byte{'\n'})
				severity, confidence := rule.Severity, rule.Confidence
				findingContext := classifyContext(path, nil)
				if skipContextualRule(rule.ID, findingContext) {
					continue
				}
				severity, confidence = contextualize(rule, findingContext, severity, confidence)
				evidence := safeEvidence(data[loc[0]:loc[1]])
				finding := s.findingRange(rule.ID, rule.Category, severity, confidence, path, line, endLine, rule.Description, evidence, rule.Remediation)
				finding.Context = findingContext
				finding.Disposition = rule.Disposition
				if isContextualContext(findingContext) {
					finding.Disposition = model.DispositionInformational
				}
				add(finding)
			}
		}
	}

	dangerousLines := make([]bool, len(lines))
	for index, line := range lines {
		dangerousLines[index] = dangerousContext(line)
	}
	for i, line := range lines {
		if skipGeneratedLineHeuristics(path) || classifyContext(path, line) == "generated" {
			break
		}
		if len(line) > 600 {
			finding := s.finding("OBFS-004", "minified-or-obfuscated", model.SeverityLow, model.ConfidenceLow, path, i+1, "Very long single line", fmt.Sprintf("line length: %d bytes", len(line)), "Review generated or minified content and its provenance.")
			finding.Context = classifyContext(path, line)
			add(finding)
		}
		lineEntropy := 0.0
		if len(line) >= 80 {
			lineEntropy = entropy(line)
		}
		if lineEntropy >= 4.8 {
			if !nearbyDangerousLine(dangerousLines, i, 3) {
				continue
			}
			severity, confidence := model.SeverityMedium, model.ConfidenceMedium
			findingContext := classifyContext(path, line)
			if findingContext != "executable" {
				confidence = model.ConfidenceLow
			}
			finding := s.finding("OBFS-005", "high-entropy-code", severity, confidence, path, i+1, "High-entropy content beside an execution primitive", fmt.Sprintf("entropy: %.2f; length: %d", lineEntropy, len(line)), "Decode and inspect the content in an isolated analysis environment.")
			finding.Context = findingContext
			add(finding)
		}
	}
	s.scanStructured(path, data, add)
}

func qualifyingLineMatches(ruleID string, original []byte, matches [][]int) [][]int {
	qualified := matches[:0]
	for _, match := range matches {
		if match[0] < 0 || match[1] > len(original) || match[0] >= match[1] {
			continue
		}
		value := original[match[0]:match[1]]
		if (ruleID == "NPMRC-002" || ruleID == "LOCK-001") && onlyTrustedRegistry(value) {
			continue
		}
		if ruleID == "IPURL-001" && !containsPublicIPURL(value) {
			continue
		}
		if ruleID == "IMPORT-001" && literalImportCall.Match(value) {
			continue
		}
		qualified = append(qualified, match)
	}
	return qualified
}

var literalImportCall = regexp.MustCompile(`(?i)^\s*(?:import|require|__import__|Class\.forName)\s*\(\s*["']`)

func nearbyDangerousLine(lines []bool, index, distance int) bool {
	start, end := index-distance, index+distance
	if start < 0 {
		start = 0
	}
	if end >= len(lines) {
		end = len(lines) - 1
	}
	for i := start; i <= end; i++ {
		if lines[i] {
			return true
		}
	}
	return false
}

func (s *Scanner) scanStructured(path string, data []byte, add func(model.Finding)) {
	if isGitHubWorkflow(path) {
		s.scanWorkflowActions(path, data, add)
	}
	if filepath.Base(innerPath(path)) != "package.json" {
		return
	}
	var pkg struct {
		Scripts      map[string]string `json:"scripts"`
		Dependencies map[string]string `json:"dependencies"`
		Dev          map[string]string `json:"devDependencies"`
		Bin          any               `json:"bin"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return
	}
	for _, name := range []string{"preinstall", "install", "postinstall", "prepare", "prepublish"} {
		cmd, ok := pkg.Scripts[name]
		if !ok {
			continue
		}
		sev, conf := model.SeverityMedium, model.ConfidenceMedium
		if suspiciousCommand(cmd) {
			sev, conf = model.SeverityCritical, model.ConfidenceHigh
		}
		finding := s.finding("PKG-001", "package-lifecycle", sev, conf, path, lineForToken(data, name), "Package lifecycle script: "+name, safeEvidence([]byte(cmd)), "Review this script before installing dependencies.")
		finding.Context = "manifest-hook"
		add(finding)
	}
	for name, cmd := range pkg.Scripts {
		if name == "preinstall" || name == "install" || name == "postinstall" || name == "prepare" || name == "prepublish" || !suspiciousCommand(cmd) {
			continue
		}
		f := s.finding("PKG-007", "package-script", model.SeverityHigh, model.ConfidenceMedium, path, lineForToken(data, name), "Non-lifecycle package script downloads and executes content: "+name, safeEvidence([]byte(cmd)), "Review the script before running package-manager commands such as test, dev, or start.")
		f.Context = "manifest-hook"
		add(f)
	}
	all := make(map[string]string, len(pkg.Dependencies)+len(pkg.Dev))
	for k, v := range pkg.Dependencies {
		all[k] = v
	}
	for k, v := range pkg.Dev {
		all[k] = v
	}
	for name, version := range all {
		lower := strings.ToLower(version)
		if strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:") || strings.HasPrefix(lower, "git+") || strings.HasPrefix(lower, "file:") {
			add(s.finding("PKG-002", "suspicious-dependency-source", model.SeverityHigh, model.ConfidenceMedium, path, lineForToken(data, name), "Dependency uses a non-registry source: "+name, "source type: "+strings.SplitN(lower, ":", 2)[0], "Verify the dependency source and pin it to an immutable trusted revision."))
		}
		if version == "0.0.0" || version == "0.0.1" {
			add(s.finding("PKG-003", "suspicious-dependency-version", model.SeverityMedium, model.ConfidenceMedium, path, lineForToken(data, name), "Dependency uses a placeholder-like version: "+name, "version: "+version, "Verify the package name and version."))
		}
		if inflatedMajorVersion(version) {
			finding := s.finding("PKG-005", "dependency-confusion", model.SeverityMedium, model.ConfidenceMedium, path, lineForToken(data, name), "Dependency uses an unusually high major version: "+name, "version: "+safeEvidence([]byte(version)), "Verify whether a public package is shadowing an internal dependency and inspect the resolved registry and integrity hash.")
			finding.Context = "manifest"
			add(finding)
		}
	}
	if pkg.Bin != nil {
		add(s.finding("PKG-004", "package-binary", model.SeverityLow, model.ConfidenceMedium, path, lineForToken(data, "bin"), "Package exposes an executable command", "package.json contains a bin field", "Inspect the referenced executable before installing globally."))
		for _, target := range binTargets(pkg.Bin) {
			if escapingManifestPath(target) || suspiciousBinTarget(target) {
				f := s.finding("PKG-006", "package-binary", model.SeverityHigh, model.ConfidenceHigh, path, lineForToken(data, target), "Package bin target escapes the package or embeds execution behavior", safeEvidence([]byte(target)), "Do not install the package until the bin target is constrained to a reviewed local file.")
				f.Context = "manifest-hook"
				add(f)
			}
		}
	}
}

func (s *Scanner) scanWorkflowActions(path string, data []byte, add func(model.Finding)) {
	var document yaml.Node
	if yaml.Unmarshal(data, &document) != nil {
		return
	}
	var visit func(*yaml.Node)
	visit = func(node *yaml.Node) {
		if node.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, value := node.Content[i], node.Content[i+1]
				if key.Value == "uses" && value.Kind == yaml.ScalarNode {
					ref := strings.TrimSpace(value.Value)
					if !strings.HasPrefix(ref, "./") && strings.Contains(ref, "@") && !pinnedAction([]byte("uses: "+ref)) {
						finding := s.finding("CICD-003", "ci-workflow-integrity", model.SeverityHigh, model.ConfidenceHigh, path, value.Line, "GitHub Action is referenced by a mutable tag or branch", safeEvidence([]byte("uses: "+ref)), "Pin third-party actions to a reviewed full commit SHA.")
						finding.Context = "ci-workflow"
						finding.Disposition = model.DispositionHarden
						add(finding)
					}
				}
				visit(value)
			}
			return
		}
		for _, child := range node.Content {
			visit(child)
		}
	}
	visit(&document)
}

func lineForToken(data []byte, token string) int {
	return manifest.DeclarationLine(data, token)
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

func (s *Scanner) scanRepositoryHygiene(root string, add func(model.Finding)) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	hasREADME, hasLicense := false, false
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		hasREADME = hasREADME || name == "readme" || strings.HasPrefix(name, "readme.")
		hasLicense = hasLicense || name == "license" || strings.HasPrefix(name, "license.") || name == "copying"
	}
	if !hasREADME {
		f := s.finding("REPO-001", "repository-hygiene", model.SeverityLow, model.ConfidenceHigh, ".", 0, "Repository has no top-level README", "README not found", "Ask the repository owner for setup, provenance, and execution instructions.")
		f.Context = "metadata"
		add(f)
	}
	if !hasLicense {
		f := s.finding("REPO-002", "repository-hygiene", model.SeverityLow, model.ConfidenceHigh, ".", 0, "Repository has no top-level license", "license file not found", "Clarify the code's origin and permitted use before redistributing it.")
		f.Context = "metadata"
		add(f)
	}
}

func (s *Scanner) scanSymlink(root, path, rel string, add func(model.Finding)) {
	target, err := os.Readlink(path)
	if err != nil {
		return
	}
	resolved := target
	if !filepath.IsAbs(target) {
		resolved = filepath.Join(filepath.Dir(path), target)
	}
	resolved, err = filepath.Abs(resolved)
	rootAbs, _ := filepath.Abs(root)
	if err != nil || resolved != rootAbs && !strings.HasPrefix(resolved, rootAbs+string(os.PathSeparator)) {
		add(s.finding("SYMLINK-001", "escaping-symlink", model.SeverityHigh, model.ConfidenceHigh, rel, 0, "Symbolic link escapes the repository", "target redacted", "Remove or replace the escaping symbolic link."))
		return
	}
	if _, err := os.Stat(resolved); err != nil {
		add(s.finding("SYMLINK-002", "broken-symlink", model.SeverityMedium, model.ConfidenceMedium, rel, 0, "Broken symbolic link", "target unavailable", "Review the link target and repository packaging."))
	}
}

func (s *Scanner) scanGitMetadata(ctx context.Context, root, gitRel string, add func(model.Finding), coverage *model.Coverage) {
	confined, err := os.OpenRoot(root)
	if err != nil {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, gitRel+": cannot confine Git metadata")
		return
	}
	defer confined.Close()
	read := func(rel string, hook bool) {
		path := filepath.ToSlash(filepath.Join(gitRel, rel))
		if ctx.Err() != nil {
			coverage.Complete = false
			return
		}
		info, err := confined.Lstat(path)
		if os.IsNotExist(err) {
			return
		}
		if err != nil || !info.Mode().IsRegular() {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (unreadable or non-regular Git metadata)")
			return
		}
		if coverage.FilesScanned >= s.opts.Limits.MaxFiles {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (file-count limit)")
			return
		}
		coverage.FilesScanned++
		if info.Size() > s.opts.Limits.MaxFileBytes {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (file-size limit)")
			return
		}
		file, err := openConfinedNonblocking(confined, path)
		if err != nil {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (cannot open Git metadata)")
			return
		}
		defer file.Close()
		openedInfo, err := file.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (Git metadata changed while scanning)")
			return
		}
		data, err := io.ReadAll(io.LimitReader(file, s.opts.Limits.MaxFileBytes+1))
		if err != nil || int64(len(data)) > s.opts.Limits.MaxFileBytes || ctx.Err() != nil {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (Git metadata read or size limit)")
			return
		}
		coverage.BytesScanned += int64(len(data))
		mode := os.FileMode(0)
		if hook {
			mode = 0o700
			if suspiciousHook(data) {
				f := s.finding("GITHOOK-002", "git-hook", model.SeverityCritical, model.ConfidenceHigh, path, 0, "Active Git hook contains execution or remote-fetch behavior", "suspicious behavior in active hook", "Disable the hook and review its complete data flow before running Git commands.")
				f.Context = "git-hook"
				add(f)
			}
		}
		s.scanContent(path, data, mode, add, coverage)
	}
	for _, rel := range []string{"config", "config.worktree", filepath.Join("info", "attributes")} {
		read(rel, false)
	}
	hooksPath := filepath.ToSlash(filepath.Join(gitRel, "hooks"))
	info, err := confined.Lstat(hooksPath)
	if os.IsNotExist(err) {
		return
	}
	if err != nil || !info.IsDir() {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, hooksPath+" (unreadable or non-directory hooks)")
		return
	}
	hooksDir, err := confined.Open(hooksPath)
	if err != nil {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, hooksPath+" (cannot open hooks)")
		return
	}
	defer hooksDir.Close()
	hooks, err := hooksDir.ReadDir(-1)
	if err != nil {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, hooksPath+" (cannot list hooks)")
		return
	}
	for _, hook := range hooks {
		if strings.HasSuffix(strings.ToLower(hook.Name()), ".sample") {
			continue
		}
		read(filepath.Join("hooks", hook.Name()), true)
	}
}

func suspiciousHook(data []byte) bool {
	l := strings.ToLower(string(data))
	for _, needle := range []string{"curl ", "wget ", "eval ", "node -e", "python -c", "bash -c", "powershell", "/dev/tcp/", "base64 -d"} {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}

func (s *Scanner) finding(id, category string, severity model.Severity, confidence model.Confidence, path string, line int, message, evidence, remediation string) model.Finding {
	return s.findingRange(id, category, severity, confidence, path, line, line, message, evidence, remediation)
}

func (s *Scanner) findingRange(id, category string, severity model.Severity, confidence model.Confidence, path string, startLine, endLine int, message, evidence, remediation string) model.Finding {
	h := sha256.Sum256([]byte(id + "\x00" + path + "\x00" + fmt.Sprint(startLine) + "\x00" + message))
	path = filepath.ToSlash(path)
	finding := model.Finding{RuleID: id, Category: category, Severity: severity, Confidence: confidence, Context: "executable", Path: path, Line: startLine, Occurrences: 1, Message: message, Evidence: evidence, Remediation: remediation, Fingerprint: "sha256:" + hex.EncodeToString(h[:])}
	location := model.Location{Path: path, StartLine: startLine, Evidence: evidence}
	if endLine > startLine {
		location.EndLine = endLine
	}
	finding.Locations = []model.Location{location}
	return finding
}

func looksText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	limit := len(data)
	if limit > 8192 {
		limit = 8192
	}
	sample := data[:limit]
	if !utf8.Valid(sample) {
		return false
	}
	for _, b := range sample {
		if b == 0 {
			return false
		}
	}
	return true
}

// Undecodable source and configuration cannot be silently treated as clean.
// Ordinary binary assets remain outside the text-rule coverage claim.
func scanRelevantText(path string, data []byte, mode os.FileMode) bool {
	if mode&0o111 != 0 || bytes.HasPrefix(data, []byte("#!")) {
		return true
	}
	if i := strings.LastIndex(path, "!"); i >= 0 {
		path = path[i+1:]
	}
	base := strings.ToLower(filepath.Base(path))
	if strings.Contains(filepath.ToSlash(path), "/.git/") || strings.HasPrefix(filepath.ToSlash(path), ".git/") {
		return true
	}
	if _, supported := manifest.Parse(path, nil); supported {
		return true
	}
	switch base {
	case "dockerfile", "makefile", "gemfile", ".npmrc", ".yarnrc", ".yarnrc.yml", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "go.sum", "pipfile.lock", "poetry.lock", "requirements.txt":
		return true
	}
	switch strings.ToLower(filepath.Ext(base)) {
	case ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".cs", ".php", ".c", ".h", ".cc", ".cpp", ".html", ".htm", ".css", ".sql", ".yml", ".yaml", ".toml", ".json", ".jsonc", ".ipynb", ".xml", ".ini", ".cfg", ".conf":
		return true
	}
	return false
}

func splitLines(data []byte) [][]byte {
	s := bufio.NewScanner(strings.NewReader(string(data)))
	s.Buffer(make([]byte, 64*1024), 64*1024*1024)
	var lines [][]byte
	for s.Scan() {
		lines = append(lines, append([]byte(nil), s.Bytes()...))
	}
	return lines
}

// codeProjection preserves byte offsets while replacing definite comments and
// string contents with spaces. Unsupported or ambiguous inputs are returned
// unchanged so precision improvements never silently create a coverage gap.
func codeProjection(path string, data []byte) []byte {
	ext := strings.ToLower(filepath.Ext(innerPath(path)))
	cLike := map[string]bool{
		".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".h": true, ".hpp": true,
		".cs": true, ".go": true, ".java": true, ".js": true, ".jsx": true,
		".kt": true, ".kts": true, ".mjs": true, ".cjs": true, ".rs": true,
		".swift": true, ".ts": true, ".tsx": true,
	}
	hashComments := map[string]bool{
		".py": true, ".pyw": true, ".rb": true, ".sh": true, ".bash": true,
		".zsh": true, ".ps1": true, ".toml": true, ".yaml": true, ".yml": true,
	}
	if !cLike[ext] && !hashComments[ext] {
		return data
	}
	out := append([]byte(nil), data...)
	const (
		stateCode = iota
		stateLineComment
		stateBlockComment
		stateSingle
		stateDouble
		stateBacktick
		stateTripleSingle
		stateTripleDouble
	)
	state := stateCode
	templateDepth := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			if state == stateLineComment || state == stateSingle || state == stateDouble {
				state = stateCode
			}
			continue
		}
		switch state {
		case stateLineComment:
			out[i] = ' '
		case stateBlockComment:
			out[i] = ' '
			if i+1 < len(data) && data[i] == '*' && data[i+1] == '/' {
				out[i+1] = ' '
				i++
				state = stateCode
			}
		case stateSingle, stateDouble, stateBacktick:
			out[i] = ' '
			quote := byte('\'')
			if state == stateDouble {
				quote = '"'
			} else if state == stateBacktick {
				quote = '`'
			}
			if state == stateBacktick && data[i] == '$' && i+1 < len(data) && data[i+1] == '{' {
				out[i+1] = ' '
				i++
				templateDepth = 1
				state = stateCode
			} else if data[i] == '\\' && i+1 < len(data) {
				out[i+1] = ' '
				i++
			} else if data[i] == quote {
				state = stateCode
			}
		case stateTripleSingle, stateTripleDouble:
			out[i] = ' '
			quote := byte('\'')
			if state == stateTripleDouble {
				quote = '"'
			}
			if i+2 < len(data) && data[i] == quote && data[i+1] == quote && data[i+2] == quote {
				out[i+1], out[i+2] = ' ', ' '
				i += 2
				state = stateCode
			}
		case stateCode:
			if templateDepth > 0 {
				if data[i] == '{' {
					templateDepth++
				} else if data[i] == '}' {
					templateDepth--
					if templateDepth == 0 {
						out[i] = ' '
						state = stateBacktick
						continue
					}
				}
			}
			if cLike[ext] && i+1 < len(data) && data[i] == '/' && data[i+1] == '/' {
				out[i], out[i+1] = ' ', ' '
				i++
				state = stateLineComment
				continue
			}
			if cLike[ext] && i+1 < len(data) && data[i] == '/' && data[i+1] == '*' {
				out[i], out[i+1] = ' ', ' '
				i++
				state = stateBlockComment
				continue
			}
			if hashComments[ext] && data[i] == '#' {
				out[i] = ' '
				state = stateLineComment
				continue
			}
			if (ext == ".py" || ext == ".pyw") && i+2 < len(data) && (data[i] == '\'' || data[i] == '"') && data[i+1] == data[i] && data[i+2] == data[i] {
				out[i], out[i+1], out[i+2] = ' ', ' ', ' '
				if data[i] == '\'' {
					state = stateTripleSingle
				} else {
					state = stateTripleDouble
				}
				i += 2
				continue
			}
			switch data[i] {
			case '\'':
				out[i] = ' '
				state = stateSingle
			case '"':
				out[i] = ' '
				state = stateDouble
			case '`':
				if cLike[ext] {
					out[i] = ' '
					state = stateBacktick
				}
			}
		}
	}
	return out
}

func lexicallySegmented(path string) bool {
	ext := strings.ToLower(filepath.Ext(innerPath(path)))
	switch ext {
	case ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs", ".go", ".java", ".js", ".jsx", ".kt", ".kts", ".mjs", ".cjs", ".rs", ".swift", ".ts", ".tsx", ".py", ".pyw", ".rb", ".sh", ".bash", ".zsh", ".ps1", ".toml", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var out float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(data))
		out -= p * math.Log2(p)
	}
	return out
}

func dangerousContext(data []byte) bool {
	l := strings.ToLower(string(data))
	for _, needle := range []string{"eval(", "exec(", "execsync(", "spawn(", "b64decode", "fromcharcode", "runinnewcontext"} {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}

func suspiciousCommand(v string) bool {
	l := strings.ToLower(v)
	hasFetch := strings.Contains(l, "curl ") || strings.Contains(l, "wget ") || strings.Contains(l, "http://") || strings.Contains(l, "https://")
	hasExec := strings.Contains(l, "| sh") || strings.Contains(l, "| bash") || strings.Contains(l, "eval") || strings.Contains(l, "node -e") || strings.Contains(l, "python -c") || strings.Contains(l, "powershell")
	return hasFetch && hasExec || strings.Contains(l, "base64") && hasExec
}

func looksLikeSignatureDefinition(line []byte) bool {
	l := strings.TrimSpace(string(line))
	if strings.HasPrefix(l, "#") || strings.Contains(l, `\s`) || strings.Contains(l, `\(`) || strings.Contains(l, `[^\n]`) || strings.Contains(l, "Pattern:") {
		return true
	}
	if strings.Contains(l, "needle := range []string{") || strings.Contains(l, "regexp.MustCompile(") || strings.Contains(l, ".finding(") {
		return true
	}
	if strings.Contains(l, "string(data[:") && (strings.Contains(l, `\x7fELF`) || strings.Contains(l, `\xcf\xfa\xed\xfe`)) {
		return true
	}
	if strings.Count(l, "|") >= 4 && (strings.Contains(l, "curl") || strings.Contains(l, "eval")) {
		return true
	}
	return strings.HasPrefix(l, "{") && strings.Contains(l, "ID:") && strings.Contains(l, "Category:")
}

func classifyContext(path string, line []byte) string {
	plainPath := strings.ToLower(innerPath(path))
	slashed := "/" + strings.TrimPrefix(plainPath, "/")
	ext := filepath.Ext(plainPath)
	base := filepath.Base(plainPath)
	if strings.Contains(slashed, "/.local-evidence/") || strings.Contains(slashed, "/evidence/") {
		return "evidence"
	}
	if strings.Contains(slashed, "/testdata/") || strings.Contains(slashed, "/fixtures/") || strings.Contains(slashed, "/fixture/") || strings.Contains(slashed, "/__tests__/") || strings.Contains(slashed, "/snapshots/") || strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") {
		return "test-fixture"
	}
	if strings.Contains(slashed, "/_generated/") || strings.Contains(slashed, "/generated/") || strings.Contains(slashed, "/build/generated/") || strings.Contains(slashed, "/autolinking/") || ext == ".pbxproj" || strings.Contains(base, ".generated.") || strings.Contains(base, "_generated.") || strings.HasSuffix(base, ".gen.go") || strings.HasSuffix(base, ".g.cs") {
		return "generated"
	}
	if strings.Contains(slashed, "/dist/") || strings.Contains(slashed, "/build/") || strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".bundle.js") || strings.HasSuffix(base, ".min.css") || base == "sw.js" && strings.Contains(slashed, "/public/") && len(line) > 600 {
		return "generated"
	}
	if strings.Contains(slashed, "/node_modules/") || strings.Contains(slashed, "/vendor/") || strings.Contains(slashed, "/pods/") || strings.Contains(slashed, "/.venv/") {
		return "dependency"
	}
	if strings.Contains(slashed, "/examples/") || strings.Contains(slashed, "/example/") || strings.Contains(slashed, "/samples/") {
		return "example"
	}
	if strings.Contains(slashed, "/.github/workflows/") {
		return "ci-workflow"
	}
	if strings.Contains(slashed, "/.git/hooks/") {
		return "git-hook"
	}
	if ext == ".md" || ext == ".rst" || ext == ".adoc" || ext == ".txt" {
		return "documentation"
	}
	if base == "package.json" || base == "pyproject.toml" || base == "setup.py" || base == "composer.json" || base == "cargo.toml" || base == "pom.xml" || strings.HasPrefix(base, "build.gradle") {
		return "manifest"
	}
	if looksLikeSignatureDefinition(line) || strings.Contains(base, "signature") || strings.Contains(base, "indicator") || strings.Contains(base, "rules") {
		return "detection-definition"
	}
	return "executable"
}

func matchContext(rule Rule, path string, line []byte) string {
	context := classifyContext(path, line)
	if !definiteCommentLine(path, line) {
		return context
	}
	switch rule.Category {
	case "secret", "known-malicious-file", "known-malicious-package", "social-engineering", "agent-execution", "prompt-injection":
		return context
	default:
		return "example"
	}
}

func definiteCommentLine(path string, line []byte) bool {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return false
	}
	ext := strings.ToLower(filepath.Ext(innerPath(path)))
	switch ext {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".kts", ".rs", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs":
		return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*")
	case ".py", ".pyw", ".rb", ".sh", ".bash", ".zsh", ".ps1", ".yaml", ".yml", ".toml":
		return strings.HasPrefix(trimmed, "#")
	default:
		return false
	}
}

func innerPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "!")
	return parts[len(parts)-1]
}

func isContextualContext(context string) bool {
	switch context {
	case "documentation", "example", "test-fixture", "evidence", "generated", "dependency", "detection-definition", "metadata":
		return true
	default:
		return false
	}
}

func contextualize(rule Rule, context string, severity model.Severity, confidence model.Confidence) (model.Severity, model.Confidence) {
	allow := true
	if rule.AllowContextDowngrade != nil {
		allow = *rule.AllowContextDowngrade
	}
	if !allow || !isContextualContext(context) {
		return severity, confidence
	}
	if severity.Rank() > model.SeverityMedium.Rank() {
		severity = model.SeverityMedium
	}
	return severity, model.ConfidenceLow
}

func skipContextualRule(ruleID, context string) bool {
	if context != "generated" && context != "dependency" {
		return false
	}
	switch ruleID {
	case "ENV-001", "EXEC-004", "OBFS-004", "OBFS-005":
		return true
	default:
		return false
	}
}

func safeEvidence(line []byte) string {
	input := strings.ReplaceAll(string(line), "\r\n", "\n")
	redacted := make([]string, 0)
	for _, sourceLine := range strings.Split(input, "\n") {
		v := strings.TrimSpace(sourceLine)
		v = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return '�'
			}
			return r
		}, v)
		v = secretAssignmentRedactor.ReplaceAllString(v, "$1=[REDACTED]")
		for _, re := range evidenceRedactors {
			v = re.ReplaceAllString(v, "[REDACTED]")
		}
		words := strings.Fields(v)
		for i, word := range words {
			lower := strings.ToLower(word)
			if !strings.Contains(word, "[REDACTED]") && (len([]rune(word)) > 40 || strings.Contains(lower, "token=") || strings.Contains(lower, "password=")) {
				words[i] = "[REDACTED]"
			}
		}
		v = strings.Join(words, " ")
		runes := []rune(v)
		if len(runes) > 160 {
			v = string(runes[:160]) + "…"
		}
		if v != "" {
			redacted = append(redacted, v)
		}
	}
	return strings.Join(redacted, "\n")
}

var secretAssignmentRedactor = regexp.MustCompile(`(?i)\b(token|password|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[=:]\s*(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,;]+)`)

var evidenceRedactors = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`sk_live_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{16,}`),
	regexp.MustCompile(`(?i)https://[^/@\s]+:[^/@\s]+@`),
}

func onlyTrustedRegistry(line []byte) bool {
	value := string(line)
	start := strings.Index(strings.ToLower(value), "http://")
	secureStart := strings.Index(strings.ToLower(value), "https://")
	if secureStart < 0 || start >= 0 && start < secureStart {
		return false
	}
	value = strings.TrimRight(value[secureStart:], ",;)")
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.Port() != "" && u.Port() != "443" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "registry.npmjs.org", "registry.yarnpkg.com", "files.pythonhosted.org", "repo1.maven.org", "repo.maven.apache.org":
		return true
	}
	return false
}

var actionRef = regexp.MustCompile(`(?i)uses:\s*[^\s@]+@([0-9a-z._/-]+)`)

func pinnedAction(line []byte) bool {
	m := actionRef.FindSubmatch(line)
	if len(m) != 2 || len(m[1]) != 40 {
		return false
	}
	for _, b := range m[1] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(b)) {
			return false
		}
	}
	return true
}

var ipURL = regexp.MustCompile(`(?i)https?://([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:[/:]|$)`)

func containsPublicIPURL(line []byte) bool {
	for _, match := range ipURL.FindAllSubmatch(line, -1) {
		ip := net.ParseIP(string(match[1]))
		if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() {
			return true
		}
	}
	return false
}

func skipGeneratedLineHeuristics(path string) bool {
	base := strings.ToLower(filepath.Base(innerPath(path)))
	return strings.HasSuffix(base, ".map") || strings.HasSuffix(base, ".lock") || base == "package-lock.json" || base == "npm-shrinkwrap.json" || base == "pnpm-lock.yaml" || base == "yarn.lock"
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

var windowsAbsPath = regexp.MustCompile(`(?i)^[a-z]:[\\/]`)

func suspiciousBinTarget(target string) bool {
	return strings.ContainsAny(target, ";|`") || strings.Contains(target, "$(") || strings.Contains(target, "${")
}

func isGitHubWorkflow(path string) bool {
	path = "/" + strings.ToLower(innerPath(path))
	return strings.Contains(path, "/.github/workflows/")
}

var typoTargets = map[string]string{
	"lodahs": "lodash", "loadsh": "lodash", "lodsh": "lodash", "lodashs": "lodash",
	"crossenv": "cross-env", "cross-env.js": "cross-env", "cross-environment": "cross-env",
	"expres": "express", "expresss": "express", "express-js": "express",
	"axois": "axios", "axioss": "axios", "axios-js": "axios",
	"web-pack": "webpack", "webpackk": "webpack", "webpck": "webpack",
	"babeljs": "@babel/core", "babel-coree": "@babel/core",
	"type-script": "typescript", "typescriptt": "typescript",
	"momnet": "moment", "momentjs": "moment",
	"chalkk": "chalk", "chalk-js": "chalk",
	"comander": "commander", "commanderr": "commander",
	"es-lint": "eslint", "eslintt": "eslint",
	"eventstream": "event-stream", "event-stream-js": "event-stream",
	"colour": "colors", "colorss": "colors",
	"faker-js": "faker", "facker": "faker",
	"reqeust": "request", "requset": "request", "requsets": "request", "requesrs": "requests",
	"reactt": "react", "react-js": "react", "djago": "django", "flaskk": "flask",
}

func knownTyposquat(ecosystem, name string) (string, bool) {
	if ecosystem != "npm" && ecosystem != "pip" {
		return "", false
	}
	target, ok := typoTargets[strings.ToLower(name)]
	return target, ok
}

func disabledHooksPath(line []byte) bool {
	l := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(line)), " ", ""))
	return l == "hookspath=/dev/null" || l == "core.hookspath=/dev/null" || l == "hookspath=nul" || l == "core.hookspath=nul"
}

func executableMagic(data []byte) bool {
	return len(data) >= 4 && (string(data[:4]) == "\x7fELF" || string(data[:2]) == "MZ" || string(data[:4]) == "\xcf\xfa\xed\xfe" || string(data[:4]) == "\xfe\xed\xfa\xcf" || string(data[:4]) == "\xca\xfe\xba\xbe")
}

func isArchive(path string, data []byte) bool {
	l := strings.ToLower(path)
	return len(data) >= 4 && (string(data[:4]) == "PK\x03\x04" || strings.HasSuffix(l, ".tar") || strings.HasSuffix(l, ".tar.gz") || strings.HasSuffix(l, ".tgz"))
}

func (s *Scanner) scanArchive(ctx context.Context, parent string, data []byte, depth int, add func(model.Finding), coverage *model.Coverage) {
	if depth > s.opts.Limits.MaxArchiveDepth {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, parent+" (archive-depth limit)")
		return
	}
	count, total := 0, int64(0)
	links := map[string]string{}
	flagUnsafe := func(name, reason string) {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, parent+"!"+name+" (unsafe archive entry)")
		add(s.finding("ARCHIVE-001", "archive-traversal", model.SeverityCritical, model.ConfidenceHigh, parent+"!"+name, 0, "Archive entry escapes its extraction root", reason, "Do not extract this archive."))
	}
	inspectNonFile := func(name string) bool {
		count++
		if count > s.opts.Limits.MaxArchiveFiles {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, parent+" (archive entry-count limit)")
			return false
		}
		if unsafeArchivePath(name) {
			flagUnsafe(name, "unsafe archive path")
		}
		return true
	}
	inspectLink := func(name, target string, hardlink bool) bool {
		if !inspectNonFile(name) {
			return false
		}
		name = strings.ReplaceAll(name, "\\", "/")
		target = strings.ReplaceAll(target, "\\", "/")
		if unsafeArchivePath(name) {
			return true
		}
		if strings.HasPrefix(target, "/") || windowsAbsPath.MatchString(target) {
			flagUnsafe(name, "unsafe archive link target")
			return true
		}
		resolved := target
		if !hardlink {
			resolved = pathpkg.Join(pathpkg.Dir(name), target)
		}
		if unsafeArchivePath(resolved) {
			flagUnsafe(name, "archive link escapes extraction root")
			return true
		}
		links[pathpkg.Clean(name)] = pathpkg.Clean(resolved)
		return true
	}
	consume := func(name string, size int64, r io.Reader) bool {
		if ctx.Err() != nil {
			return false
		}
		count++
		total += size
		if count > s.opts.Limits.MaxArchiveFiles || total > s.opts.Limits.MaxArchiveBytes || size > s.opts.Limits.MaxFileBytes {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, parent+" (archive resource limit)")
			return false
		}
		if unsafeArchivePath(name) {
			flagUnsafe(name, "unsafe archive path")
			return true
		}
		portableName := pathpkg.Clean(strings.ReplaceAll(name, "\\", "/"))
		for ancestor := pathpkg.Dir(portableName); ancestor != "." && ancestor != "/"; ancestor = pathpkg.Dir(ancestor) {
			if _, linked := links[ancestor]; linked {
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, parent+"!"+name+" (entry traverses archive link)")
				return true
			}
		}
		entry, err := io.ReadAll(io.LimitReader(r, s.opts.Limits.MaxFileBytes+1))
		if err != nil || int64(len(entry)) > s.opts.Limits.MaxFileBytes {
			coverage.Complete = false
			return true
		}
		virtual := parent + "!" + filepath.ToSlash(name)
		s.scanContent(virtual, entry, 0, add, coverage)
		if isArchive(name, entry) {
			s.scanArchive(ctx, virtual, entry, depth+1, add, coverage)
		}
		return true
	}

	if len(data) >= 4 && string(data[:4]) == "PK\x03\x04" {
		zr, err := zip.NewReader(strings.NewReader(string(data)), int64(len(data)))
		if err != nil {
			coverage.Complete = false
			coverage.Warnings = append(coverage.Warnings, parent+": invalid or encrypted zip")
			return
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				if !inspectNonFile(f.Name) {
					return
				}
				continue
			}
			if f.Mode()&os.ModeSymlink != 0 {
				r, err := f.Open()
				if err != nil {
					coverage.Complete = false
					continue
				}
				target, err := io.ReadAll(io.LimitReader(r, 4097))
				r.Close()
				if err != nil || len(target) > 4096 {
					coverage.Complete = false
					coverage.Skipped = append(coverage.Skipped, parent+"!"+f.Name+" (unreadable archive link)")
					continue
				}
				if !inspectLink(f.Name, string(target), false) {
					return
				}
				continue
			}
			if !f.Mode().IsRegular() {
				if !inspectNonFile(f.Name) {
					return
				}
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, parent+"!"+f.Name+" (unsupported archive entry type)")
				continue
			}
			r, err := f.Open()
			if err != nil {
				coverage.Complete = false
				continue
			}
			ok := consume(f.Name, int64(f.UncompressedSize64), r)
			r.Close()
			if !ok {
				return
			}
		}
		return
	}
	var tr *tar.Reader
	if strings.HasSuffix(strings.ToLower(parent), ".gz") || strings.HasSuffix(strings.ToLower(parent), ".tgz") {
		gz, err := gzip.NewReader(strings.NewReader(string(data)))
		if err != nil {
			coverage.Complete = false
			return
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	} else {
		tr = tar.NewReader(strings.NewReader(string(data)))
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			coverage.Complete = false
			break
		}
		if h.FileInfo().IsDir() {
			if !inspectNonFile(h.Name) {
				return
			}
			continue
		}
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
			if !inspectLink(h.Name, h.Linkname, h.Typeflag == tar.TypeLink) {
				return
			}
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			if !inspectNonFile(h.Name) {
				return
			}
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, parent+"!"+h.Name+" (unsupported archive entry type)")
			continue
		}
		if !consume(h.Name, h.Size, tr) {
			return
		}
	}
}

func unsafeArchivePath(name string) bool {
	portable := strings.ReplaceAll(name, "\\", "/")
	clean := pathpkg.Clean(portable)
	return clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(portable, "/") || windowsAbsPath.MatchString(name)
}
