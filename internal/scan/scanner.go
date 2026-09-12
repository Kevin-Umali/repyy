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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/manifest"
	"github.com/Kevin-Umali/repyy/internal/model"
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
	findings := make([]model.Finding, 0)
	seen := map[string]int{}

	add := func(f model.Finding) {
		key := f.RuleID + "\x00" + f.Path + "\x00" + f.Message + "\x00" + f.Context + "\x00" + string(f.Severity) + "\x00" + string(f.Confidence)
		if index, ok := seen[key]; ok {
			findings[index].Occurrences++
			return
		}
		if f.Occurrences == 0 {
			f.Occurrences = 1
		}
		seen[key] = len(findings)
		findings = append(findings, f)
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
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
				s.scanGitMetadata(root, add, &coverage)
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
			return nil
		}
		if !info.Mode().IsRegular() {
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
		data, err := os.ReadFile(path)
		if err != nil {
			coverage.Complete = false
			coverage.Warnings = append(coverage.Warnings, rel+": "+err.Error())
			return nil
		}
		coverage.BytesScanned += int64(len(data))
		s.scanContent(rel, data, info.Mode(), add)
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
	// correlate may have appended via add; findings is updated by the closure.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	return coverage, findings
}

func (s *Scanner) reportProgress(coverage model.Coverage) {
	if s.opts.Progress != nil {
		s.opts.Progress(coverage.FilesScanned, coverage.BytesScanned)
	}
}

func correlate(findings []model.Finding, add func(model.Finding)) {
	type signals struct{ network, fingerprint, environment, execution, evasion bool }
	byPath := map[string]*signals{}
	for _, f := range findings {
		if f.Confidence == model.ConfidenceLow || f.Context != "executable" {
			continue
		}
		sig := byPath[f.Path]
		if sig == nil {
			sig = &signals{}
			byPath[f.Path] = sig
		}
		switch f.Category {
		case "remote-fetch", "hardcoded-network", "exfiltration":
			sig.network = true
		case "host-fingerprinting":
			sig.fingerprint = true
		case "credential-harvesting", "environment-access", "secret":
			sig.environment = true
		case "dynamic-execution", "process-execution":
			sig.execution = true
		case "sandbox-evasion":
			sig.fingerprint = true
			sig.evasion = true
		}
	}
	for path, sig := range byPath {
		if sig.network && (sig.fingerprint || sig.environment) {
			h := sha256.Sum256([]byte("COMBO-001\x00" + path))
			add(model.Finding{RuleID: "COMBO-001", Category: "collection-and-exfiltration", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Context: "executable", Path: path, Occurrences: 1, Message: "Host or credential collection appears alongside network transfer", Evidence: "correlated behaviors in the same file", Remediation: "Do not run until the data flow and destination are verified.", Fingerprint: "sha256:" + hex.EncodeToString(h[:])})
		}
		if sig.network && sig.execution {
			h := sha256.Sum256([]byte("COMBO-002\x00" + path))
			add(model.Finding{RuleID: "COMBO-002", Category: "fetch-and-execute", Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Context: "executable", Path: path, Occurrences: 1, Message: "Network retrieval appears alongside command or code execution", Evidence: "correlated behaviors in the same file", Remediation: "Do not run the repository; verify the fetched content and execution path.", Fingerprint: "sha256:" + hex.EncodeToString(h[:])})
		}
		if sig.evasion && sig.execution {
			h := sha256.Sum256([]byte("COMBO-003\x00" + path))
			add(model.Finding{RuleID: "COMBO-003", Category: "evasion-and-execution", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Context: "executable", Path: path, Occurrences: 1, Message: "CI or sandbox evasion appears alongside dynamic execution", Evidence: "correlated behaviors in the same file", Remediation: "Do not run until the environment checks and execution path are verified.", Fingerprint: "sha256:" + hex.EncodeToString(h[:])})
		}
	}
}

func (s *Scanner) scanContent(path string, data []byte, mode os.FileMode, add func(model.Finding)) {
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
				f := s.finding("IOC-PKG-"+match.Indicator.AdvisoryID, "known-malicious-package", severity, confidence, path, 0, message, dependency.Name+" "+safeEvidence([]byte(dependency.Version)), "Do not install dependencies. Review the source advisory and resolved lockfile before proceeding: "+match.Indicator.SourceURL)
				f.Context = context
				add(f)
			}
			if !confirmed {
				if expected, ok := knownTyposquat(dependency.Ecosystem, dependency.Name); ok {
					f := s.finding("TYPOSQUAT-001", "typosquatting", model.SeverityHigh, model.ConfidenceMedium, path, 0, "Dependency resembles "+expected+": "+dependency.Name, dependency.Name+" "+safeEvidence([]byte(dependency.Version)), "Verify the dependency spelling, registry owner, publication history, and resolved artifact before installing.")
					f.Context = "manifest-review"
					add(f)
				}
			}
		}
	}

	lines := splitLines(data)
	for _, rule := range s.opts.Rules {
		if !rule.Applies(path) {
			continue
		}
		matched := false
		for i, line := range lines {
			if !rule.re.Match(line) {
				continue
			}
			matched = true
			if (rule.ID == "NPMRC-002" || rule.ID == "LOCK-001") && onlyTrustedRegistry(line) {
				continue
			}
			if rule.ID == "GITHOOK-001" && disabledHooksPath(line) {
				continue
			}
			if rule.ID == "CICD-003" && (!isGitHubWorkflow(path) || pinnedAction(line)) {
				continue
			}
			if rule.ID == "IPURL-001" && !containsPublicIPURL(line) {
				continue
			}
			severity, confidence := rule.Severity, rule.Confidence
			findingContext := classifyContext(path, line)
			if findingContext != "executable" && rule.Category != "known-malicious-package" {
				severity, confidence = model.SeverityMedium, model.ConfidenceLow
			}
			finding := s.finding(rule.ID, rule.Category, severity, confidence, path, i+1, rule.Description, safeEvidence(line), rule.Remediation)
			finding.Context = findingContext
			add(finding)
		}
		if !matched {
			if loc := rule.re.FindIndex(data); loc != nil {
				line := 1 + bytes.Count(data[:loc[0]], []byte{'\n'})
				severity, confidence := rule.Severity, rule.Confidence
				findingContext := classifyContext(path, nil)
				if findingContext != "executable" && rule.Category != "known-malicious-package" {
					severity, confidence = model.SeverityMedium, model.ConfidenceLow
				}
				finding := s.finding(rule.ID, rule.Category, severity, confidence, path, line, rule.Description, "multi-line behavior matched", rule.Remediation)
				finding.Context = findingContext
				add(finding)
			}
		}
	}

	dangerousChecked, dangerous := false, false
	for i, line := range lines {
		if skipGeneratedLineHeuristics(path) {
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
			if !dangerousChecked {
				dangerous = dangerousContext(data)
				dangerousChecked = true
			}
			if !dangerous {
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

func (s *Scanner) scanStructured(path string, data []byte, add func(model.Finding)) {
	if filepath.Base(path) != "package.json" {
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
		finding := s.finding("PKG-001", "package-lifecycle", sev, conf, path, 0, "Package lifecycle script: "+name, safeEvidence([]byte(cmd)), "Review this script before installing dependencies.")
		finding.Context = "manifest-hook"
		add(finding)
	}
	for name, cmd := range pkg.Scripts {
		if name == "preinstall" || name == "install" || name == "postinstall" || name == "prepare" || name == "prepublish" || !suspiciousCommand(cmd) {
			continue
		}
		f := s.finding("PKG-007", "package-script", model.SeverityHigh, model.ConfidenceMedium, path, 0, "Non-lifecycle package script downloads and executes content: "+name, safeEvidence([]byte(cmd)), "Review the script before running package-manager commands such as test, dev, or start.")
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
			add(s.finding("PKG-002", "suspicious-dependency-source", model.SeverityHigh, model.ConfidenceMedium, path, 0, "Dependency uses a non-registry source: "+name, "source type: "+strings.SplitN(lower, ":", 2)[0], "Verify the dependency source and pin it to an immutable trusted revision."))
		}
		if version == "0.0.0" || version == "0.0.1" {
			add(s.finding("PKG-003", "suspicious-dependency-version", model.SeverityMedium, model.ConfidenceMedium, path, 0, "Dependency uses a placeholder-like version: "+name, "version: "+version, "Verify the package name and version."))
		}
		if inflatedMajorVersion(version) {
			finding := s.finding("PKG-005", "dependency-confusion", model.SeverityMedium, model.ConfidenceMedium, path, 0, "Dependency uses an unusually high major version: "+name, "version: "+safeEvidence([]byte(version)), "Verify whether a public package is shadowing an internal dependency and inspect the resolved registry and integrity hash.")
			finding.Context = "manifest"
			add(finding)
		}
	}
	if pkg.Bin != nil {
		add(s.finding("PKG-004", "package-binary", model.SeverityLow, model.ConfidenceMedium, path, 0, "Package exposes an executable command", "package.json contains a bin field", "Inspect the referenced executable before installing globally."))
		for _, target := range binTargets(pkg.Bin) {
			if escapingManifestPath(target) || suspiciousBinTarget(target) {
				f := s.finding("PKG-006", "package-binary", model.SeverityHigh, model.ConfidenceHigh, path, 0, "Package bin target escapes the package or embeds execution behavior", safeEvidence([]byte(target)), "Do not install the package until the bin target is constrained to a reviewed local file.")
				f.Context = "manifest-hook"
				add(f)
			}
		}
	}
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

func (s *Scanner) scanGitMetadata(root string, add func(model.Finding), coverage *model.Coverage) {
	paths := []string{"config", "config.worktree", filepath.Join("info", "attributes")}
	for _, rel := range paths {
		path := filepath.Join(root, ".git", rel)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		coverage.FilesScanned++
		coverage.BytesScanned += int64(len(data))
		s.scanContent(filepath.ToSlash(filepath.Join(".git", rel)), data, 0, add)
	}
	hooksDir := filepath.Join(root, ".git", "hooks")
	hooks, err := os.ReadDir(hooksDir)
	if err != nil {
		return
	}
	for _, hook := range hooks {
		if hook.IsDir() || strings.HasSuffix(strings.ToLower(hook.Name()), ".sample") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(hooksDir, hook.Name()))
		if err != nil {
			coverage.Complete = false
			continue
		}
		coverage.FilesScanned++
		coverage.BytesScanned += int64(len(data))
		hookPath := filepath.ToSlash(filepath.Join(".git", "hooks", hook.Name()))
		if suspiciousHook(data) {
			f := s.finding("GITHOOK-002", "git-hook", model.SeverityCritical, model.ConfidenceHigh, hookPath, 0, "Active Git hook contains execution or remote-fetch behavior", "suspicious behavior in active hook", "Disable the hook and review its complete data flow before running Git commands.")
			f.Context = "git-hook"
			add(f)
		}
		s.scanContent(hookPath, data, 0o700, add)
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
	h := sha256.Sum256([]byte(id + "\x00" + path + "\x00" + fmt.Sprint(line) + "\x00" + message))
	return model.Finding{RuleID: id, Category: category, Severity: severity, Confidence: confidence, Context: "executable", Path: filepath.ToSlash(path), Line: line, Occurrences: 1, Message: message, Evidence: evidence, Remediation: remediation, Fingerprint: "sha256:" + hex.EncodeToString(h[:])}
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

func splitLines(data []byte) [][]byte {
	s := bufio.NewScanner(strings.NewReader(string(data)))
	s.Buffer(make([]byte, 64*1024), 64*1024*1024)
	var lines [][]byte
	for s.Scan() {
		lines = append(lines, append([]byte(nil), s.Bytes()...))
	}
	return lines
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
	plainPath := strings.ToLower(strings.SplitN(filepath.ToSlash(path), "!", 2)[0])
	ext := filepath.Ext(plainPath)
	base := filepath.Base(plainPath)
	if ext == ".md" || ext == ".rst" || ext == ".adoc" || ext == ".txt" {
		return "documentation"
	}
	if strings.Contains(plainPath, "/testdata/") || strings.Contains(plainPath, "/fixtures/") || strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") {
		return "test-fixture"
	}
	if base == "package.json" || base == "pyproject.toml" || base == "setup.py" || base == "composer.json" || base == "cargo.toml" || base == "pom.xml" || strings.HasPrefix(base, "build.gradle") {
		return "manifest"
	}
	if looksLikeSignatureDefinition(line) || strings.Contains(base, "signature") || strings.Contains(base, "indicator") || strings.Contains(base, "rules") {
		return "detection-definition"
	}
	return "executable"
}

func documentationOnlyMatch(path, category string) bool {
	ext := strings.ToLower(filepath.Ext(strings.SplitN(path, "!", 2)[0]))
	if ext != ".md" && ext != ".rst" && ext != ".adoc" {
		return false
	}
	switch category {
	case "dynamic-execution", "process-execution", "remote-fetch", "download-execute", "decode-execute", "remote-import", "reverse-shell", "cryptomining", "hardcoded-network", "unsafe-deserialization", "path-traversal":
		return true
	default:
		return false
	}
}

func safeEvidence(line []byte) string {
	v := strings.TrimSpace(string(line))
	for _, re := range evidenceRedactors {
		v = re.ReplaceAllString(v, "[REDACTED]")
	}
	if len(v) > 160 {
		v = v[:160] + "…"
	}
	// Do not echo likely credentials or long encoded payloads into reports.
	words := strings.Fields(v)
	for i, word := range words {
		if len(word) > 40 || strings.Contains(strings.ToLower(word), "token=") || strings.Contains(strings.ToLower(word), "password=") {
			words[i] = "[REDACTED]"
		}
	}
	return strings.Join(words, " ")
}

var evidenceRedactors = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`sk_live_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{16,}`),
	regexp.MustCompile(`(?i)(token|password|secret|api[_-]?key)\s*[=:]\s*[^\s,;]+`),
	regexp.MustCompile(`(?i)https://[^/@\s]+:[^/@\s]+@`),
}

func onlyTrustedRegistry(line []byte) bool {
	l := strings.ToLower(string(line))
	trusted := []string{"registry.npmjs.org", "registry.yarnpkg.com", "files.pythonhosted.org", "repo1.maven.org", "repo.maven.apache.org"}
	for _, host := range trusted {
		if strings.Contains(l, host) {
			return true
		}
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
	base := strings.ToLower(filepath.Base(strings.SplitN(path, "!", 2)[0]))
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
	path = "/" + strings.ToLower(filepath.ToSlash(strings.SplitN(path, "!", 2)[0]))
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
		if strings.HasPrefix(filepath.Clean(name), "..") || filepath.IsAbs(name) {
			add(s.finding("ARCHIVE-001", "archive-traversal", model.SeverityCritical, model.ConfidenceHigh, parent+"!"+name, 0, "Archive entry escapes its extraction root", "unsafe archive path", "Do not extract this archive."))
			return true
		}
		entry, err := io.ReadAll(io.LimitReader(r, s.opts.Limits.MaxFileBytes+1))
		if err != nil || int64(len(entry)) > s.opts.Limits.MaxFileBytes {
			coverage.Complete = false
			return true
		}
		virtual := parent + "!" + filepath.ToSlash(name)
		s.scanContent(virtual, entry, 0, add)
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
			continue
		}
		if !consume(h.Name, h.Size, tr) {
			return
		}
	}
}
