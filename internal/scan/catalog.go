package scan

import (
	"sort"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// RuleInfo is the review-facing metadata shared by terminal and HTML reports.
type RuleInfo struct {
	ID                    string            `json:"id"`
	Category              string            `json:"category"`
	Severity              model.Severity    `json:"severity"`
	Confidence            model.Confidence  `json:"confidence"`
	Disposition           model.Disposition `json:"disposition"`
	Description           string            `json:"description"`
	Rationale             string            `json:"rationale"`
	LegitimateUse         string            `json:"legitimate_use"`
	Remediation           string            `json:"remediation"`
	MatchScope            string            `json:"match_scope"`
	ApplicablePaths       []string          `json:"applicable_paths"`
	AllowContextDowngrade bool              `json:"allow_context_downgrade"`
}

func applyRuleDefaults(rule *Rule) {
	if rule.MatchScope == "" && codeScopedRule(rule.ID) {
		rule.MatchScope = "code"
	}
	if rule.MatchScope == "" {
		rule.MatchScope = "raw"
	}
	if rule.Rationale == "" {
		rule.Rationale = categoryRationale(rule.Category)
	}
	if rule.LegitimateUse == "" {
		rule.LegitimateUse = categoryLegitimateUse(rule.Category)
	}
	if rule.Disposition == "" {
		rule.Disposition = defaultRuleDisposition(rule.ID, rule.Category, rule.Severity, rule.Confidence)
	}
	if rule.AllowContextDowngrade == nil {
		value := !strings.HasPrefix(rule.ID, "IOC-") && !strings.HasPrefix(rule.ID, "SECRET-")
		rule.AllowContextDowngrade = &value
	}
}

func codeScopedRule(id string) bool {
	switch id {
	case "EXEC-001", "EXEC-002", "BACKDOOR-001", "IMPORT-001", "IMPORT-003", "PROTO-001", "ENV-001", "FINGERPRINT-001", "UNSERIALIZE-001", "PATH-001":
		return true
	default:
		return false
	}
}

func defaultRuleDisposition(id, category string, severity model.Severity, confidence model.Confidence) model.Disposition {
	if id == "CICD-003" || id == "JVMWRAP-002" || strings.HasPrefix(id, "REPO-") || category == "repository-hygiene" {
		return model.DispositionHarden
	}
	if severity == model.SeverityLow || confidence == model.ConfidenceLow || category == "process-capability" {
		return model.DispositionInformational
	}
	if severity == model.SeverityCritical && confidence == model.ConfidenceHigh {
		return model.DispositionBlock
	}
	return model.DispositionReview
}

func categoryRationale(category string) string {
	return "This rule identifies " + strings.ReplaceAll(category, "-", " ") + " behavior that can affect repository trust or execution safety."
}

func categoryLegitimateUse(category string) string {
	switch category {
	case "process-execution", "process-capability":
		return "Build, test, and development tooling often starts reviewed local processes."
	case "environment-access":
		return "Applications commonly read explicitly named configuration variables."
	case "ci-workflow-integrity":
		return "Version tags are common and convenient, but they are not immutable."
	case "repository-hygiene":
		return "Private or early-stage repositories may intentionally omit public documentation."
	case "remote-fetch":
		return "Installers and update tools may retrieve content from reviewed, pinned sources."
	case "dynamic-execution":
		return "Frameworks and developer tools sometimes evaluate generated or sandboxed code."
	case "image-active-content":
		return "Interactive SVG assets may intentionally contain script or event handlers."
	case "editor-extension-recommendation":
		return "Teams commonly recommend reviewed editor extensions for a workspace."
	case "editor-extension-installation":
		return "Development containers and setup scripts often provision reviewed editor extensions."
	case "editor-command":
		return "Workspace tasks and debugger configurations commonly invoke reviewed project tools."
	case "devcontainer-feature-installation":
		return "Development containers commonly install reusable, reviewed tooling features."
	case "directory-auto-execution", "development-shell-execution":
		return "Development environment tools run reviewed setup commands when a trusted environment is entered."
	case "system-installation":
		return "Bootstrap scripts commonly install reviewed packages and developer tools."
	case "font-installation":
		return "Applications and design projects may install bundled, licensed fonts for consistent rendering."
	default:
		return "The behavior may be legitimate when its inputs, destination, and execution context are understood."
	}
}

// BuiltinRuleCatalog returns complete metadata for behavioral and structured
// rule families. Dynamic package-advisory IDs use the IOC-PKG-* fallback.
func BuiltinRuleCatalog() []RuleInfo {
	items := make([]RuleInfo, 0)
	seen := map[string]bool{}
	for _, rule := range BuiltinRules() {
		items = append(items, infoFromRule(rule))
		seen[rule.ID] = true
	}
	for _, item := range structuredRuleCatalog() {
		if !seen[item.ID] {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func infoFromRule(rule Rule) RuleInfo {
	allow := true
	if rule.AllowContextDowngrade != nil {
		allow = *rule.AllowContextDowngrade
	}
	paths := append([]string(nil), rule.Globs...)
	if len(paths) == 0 {
		paths = []string{"**"}
	}
	return RuleInfo{
		ID: rule.ID, Category: rule.Category, Severity: rule.Severity,
		Confidence: rule.Confidence, Disposition: rule.Disposition,
		Description: rule.Description, Rationale: rule.Rationale,
		LegitimateUse: rule.LegitimateUse, Remediation: rule.Remediation,
		MatchScope: rule.MatchScope, ApplicablePaths: paths, AllowContextDowngrade: allow,
	}
}

func structuredRuleCatalog() []RuleInfo {
	type entry struct {
		id, category, description, remediation string
		severity                               model.Severity
		confidence                             model.Confidence
	}
	entries := []entry{
		{"ARCHIVE-001", "archive-traversal", "Archive entry escapes its extraction root", "Do not extract the archive.", model.SeverityCritical, model.ConfidenceHigh},
		{"BINARY-001", "compiled-binary", "Compiled executable content is present", "Verify the binary provenance and hash before use.", model.SeverityHigh, model.ConfidenceHigh},
		{"CHAIN-004", "staged-download-execute", "Downloaded file is executed later in the same script", "Do not run until the downloaded content, destination, and execution path are verified.", model.SeverityCritical, model.ConfidenceHigh},
		{"COMBO-001", "collection-and-exfiltration", "Collection appears alongside network transfer", "Verify the collected data and destination before running the repository.", model.SeverityHigh, model.ConfidenceHigh},
		{"COMBO-002", "fetch-and-execute", "Network retrieval appears alongside execution", "Do not run until the fetched content and execution path are verified.", model.SeverityCritical, model.ConfidenceHigh},
		{"COMBO-003", "evasion-and-execution", "Environment evasion appears alongside execution", "Verify the environment checks and execution path.", model.SeverityHigh, model.ConfidenceHigh},
		{"CICD-006", "ci-artifact-trust", "Privileged workflow_run job executes after downloading an artifact", "Treat upstream artifacts as untrusted data; validate them and avoid executing downloaded content in this privileged job.", model.SeverityHigh, model.ConfidenceMedium},
		{"CICD-007", "ci-cache-integrity", "Low-trust workflow explicitly allows cache writes", "Keep low-trust jobs read-only for cache access, or verify that they cannot process untrusted input before saving a cache.", model.SeverityHigh, model.ConfidenceMedium},
		{"CICD-008", "ci-runner-trust", "Pull-request workflow runs on a self-hosted runner", "Verify repository visibility, fork approval, runner isolation, and what untrusted pull-request code can access.", model.SeverityHigh, model.ConfidenceMedium},
		{"DOTNET-001", "dotnet-build-execution", "MSBuild project or imported file runs a command", "Inspect the Exec command and its conditions before building or restoring the project.", model.SeverityHigh, model.ConfidenceMedium},
		{"DOC-001", "document-active-content", "PDF declares active or embedded content", "Review or remove PDF actions and embedded files before opening it.", model.SeverityHigh, model.ConfidenceMedium},
		{"DOC-002", "office-macro", "Office package contains a VBA macro project", "Inspect or remove the macro project before opening the document.", model.SeverityHigh, model.ConfidenceHigh},
		{"DOC-003", "office-external-relationship", "Office package references external content", "Review and remove unneeded external relationships.", model.SeverityMedium, model.ConfidenceHigh},
		{"DOC-004", "office-dynamic-data-exchange", "Office document contains a Dynamic Data Exchange field", "Remove the DDE field or inspect its command and data source.", model.SeverityHigh, model.ConfidenceMedium},
		{"EXECBIT-001", "executable-file", "File has executable permissions", "Review whether this file needs to be executable.", model.SeverityLow, model.ConfidenceMedium},
		{"FONT-002", "binary-font", "Binary font file requires provenance review", "Verify the font source, license, hash, and signature before installing or previewing it.", model.SeverityMedium, model.ConfidenceHigh},
		{"FONT-003", "font-container-integrity", "Font container is malformed or contains an executable payload", "Do not install or preview the font; replace it with a trusted copy.", model.SeverityHigh, model.ConfidenceHigh},
		{"FONT-004", "font-active-content", "OpenType SVG glyph contains active content", "Remove active SVG content or replace the font with a trusted copy.", model.SeverityMedium, model.ConfidenceMedium},
		{"FONT-005", "font-program", "Font contains TrueType instructions", "Verify provenance before passing the instruction stream to a font engine.", model.SeverityLow, model.ConfidenceHigh},
		{"GITHOOK-002", "git-hook", "Active Git hook contains execution or remote-fetch behavior", "Disable the hook and review it before running Git commands.", model.SeverityCritical, model.ConfidenceHigh},
		{"IMAGE-001", "image-active-content", "SVG contains active content", "Review the SVG source and remove unneeded scripts, event handlers, or JavaScript links.", model.SeverityMedium, model.ConfidenceMedium},
		{"IDE-007", "editor-extension-package", "Packaged VSIX editor extension is present", "Verify the extension publisher, signature, package contents, and hash before installing it.", model.SeverityMedium, model.ConfidenceHigh},
		{"IDE-008", "editor-extension-capability", "VSIX extension declares activation or execution capabilities", "Review activation events and contributed execution surfaces before installation.", model.SeverityMedium, model.ConfidenceHigh},
		{"IDE-009", "editor-extension-install-script", "VSIX extension package declares an installation lifecycle script", "Inspect the lifecycle command and bundled files before installation.", model.SeverityHigh, model.ConfidenceHigh},
		{"JVMWRAP-001", "jvm-wrapper-source", "JVM wrapper distribution URL is missing or redirects from the official source", "Verify the wrapper distribution before running it.", model.SeverityHigh, model.ConfidenceHigh},
		{"JVMWRAP-002", "jvm-wrapper-integrity", "JVM wrapper distribution has no expected SHA-256", "Pin the reviewed distribution SHA-256 in the wrapper properties.", model.SeverityMedium, model.ConfidenceHigh},
		{"JVMWRAP-003", "jvm-wrapper-integrity", "JVM wrapper distribution SHA-256 is malformed", "Replace the checksum with the reviewed 64-character SHA-256.", model.SeverityHigh, model.ConfidenceHigh},
		{"IOC-HASH-SHA256", "known-malicious-file", "File hash matches confirmed intelligence", "Isolate the file and follow incident-response procedures.", model.SeverityCritical, model.ConfidenceHigh},
		{"IOC-PKG-*", "known-malicious-package", "Package declaration matches confirmed intelligence", "Review the advisory and resolved package before installation.", model.SeverityCritical, model.ConfidenceHigh},
		{"OBFS-004", "minified-or-obfuscated", "Very long single line", "Review generated or minified content and its provenance.", model.SeverityLow, model.ConfidenceLow},
		{"OBFS-005", "high-entropy-code", "High-entropy content appears beside execution", "Decode and inspect the content in an isolated environment.", model.SeverityMedium, model.ConfidenceMedium},
		{"NUGET-001", "nuget-package-source", "NuGet configuration uses an alternate package source", "Verify the feed and constrain package source mapping.", model.SeverityMedium, model.ConfidenceMedium},
		{"PKG-001", "package-lifecycle", "Package lifecycle script is present", "Review the script before installing dependencies.", model.SeverityMedium, model.ConfidenceMedium},
		{"PKG-002", "suspicious-dependency-source", "Dependency uses a non-registry source", "Verify and pin the dependency source.", model.SeverityHigh, model.ConfidenceMedium},
		{"PKG-003", "suspicious-dependency-version", "Dependency uses a placeholder-like version", "Verify the package name and version.", model.SeverityMedium, model.ConfidenceMedium},
		{"PKG-004", "package-binary", "Package exposes an executable command", "Inspect the executable before installing globally.", model.SeverityLow, model.ConfidenceMedium},
		{"PKG-005", "dependency-confusion", "Dependency uses an unusually high major version", "Verify registry ownership and the resolved artifact.", model.SeverityMedium, model.ConfidenceMedium},
		{"PKG-006", "package-binary", "Package binary target escapes the package or embeds execution", "Constrain the target to a reviewed local file.", model.SeverityHigh, model.ConfidenceHigh},
		{"PKG-007", "package-script", "Package script downloads and executes content", "Review the script before running package-manager commands.", model.SeverityHigh, model.ConfidenceMedium},
		{"PKG-008", "dependency-override", "Dependency override changes package source or identity", "Review the override and pin it to a trusted immutable artifact.", model.SeverityHigh, model.ConfidenceMedium},
		{"PKG-009", "package-alias", "Dependency name resolves to a different registry package", "Verify the alias target, publisher, and resolved artifact.", model.SeverityMedium, model.ConfidenceMedium},
		{"PHP-002", "composer-package-source", "Composer defines alternate package repositories", "Review repository precedence and the resolved composer.lock.", model.SeverityMedium, model.ConfidenceMedium},
		{"PHP-003", "composer-plugin-execution", "Composer permits every dependency plugin to execute", "Replace wildcard permission with explicit reviewed plugin names.", model.SeverityHigh, model.ConfidenceHigh},
		{"PY-003", "python-package-source", "pip configuration changes package lookup sources", "Verify the source and avoid mixing public and private indexes for the same package names.", model.SeverityMedium, model.ConfidenceMedium},
		{"RUBY-002", "ruby-package-source", "Bundler package source is redirected", "Verify the gem source or mirror and review Gemfile.lock.", model.SeverityMedium, model.ConfidenceMedium},
		{"RUST-002", "rust-build-script", "Cargo automatically executes a package build.rs", "Inspect build.rs and its build dependencies before compiling.", model.SeverityMedium, model.ConfidenceHigh},
		{"RUST-003", "rust-registry-redirection", "Cargo configuration redirects dependency resolution", "Verify the registry or source replacement before fetching dependencies.", model.SeverityHigh, model.ConfidenceHigh},
		{"RUST-004", "rust-dependency-override", "Cargo dependency source override", "Verify and pin the replacement dependency source.", model.SeverityHigh, model.ConfidenceMedium},
		{"RUST-005", "rust-dependency-source", "Cargo dependency uses a non-default source", "Verify the dependency source and pin remote revisions.", model.SeverityHigh, model.ConfidenceMedium},
		{"REPO-001", "repository-hygiene", "Repository has no top-level README", "Ask the owner for setup and provenance documentation.", model.SeverityLow, model.ConfidenceHigh},
		{"REPO-002", "repository-hygiene", "Repository has no top-level license", "Clarify the code origin and permitted use.", model.SeverityLow, model.ConfidenceHigh},
		{"SYMLINK-001", "escaping-symlink", "Symbolic link escapes the repository", "Remove or replace the escaping link.", model.SeverityHigh, model.ConfidenceHigh},
		{"SYMLINK-002", "broken-symlink", "Symbolic link target is unavailable", "Review the link target and packaging.", model.SeverityMedium, model.ConfidenceMedium},
		{"YARN-001", "package-manager-execution", "Project selects a local Yarn executable", "Inspect the referenced Yarn executable before running yarn commands.", model.SeverityMedium, model.ConfidenceHigh},
		{"YARN-002", "package-manager-plugin", "Project loads a Yarn plugin", "Inspect the plugin source before running yarn commands.", model.SeverityMedium, model.ConfidenceHigh},
	}
	items := make([]RuleInfo, 0, len(entries))
	for _, value := range entries {
		items = append(items, RuleInfo{
			ID: value.id, Category: value.category, Severity: value.severity, Confidence: value.confidence,
			Disposition: defaultRuleDisposition(value.id, value.category, value.severity, value.confidence),
			Description: value.description, Rationale: categoryRationale(value.category),
			LegitimateUse: categoryLegitimateUse(value.category), Remediation: value.remediation,
			MatchScope: "structured", ApplicablePaths: structuredApplicablePaths(value.id), AllowContextDowngrade: !strings.HasPrefix(value.id, "IOC-"),
		})
	}
	return items
}

func structuredApplicablePaths(id string) []string {
	switch {
	case strings.HasPrefix(id, "PKG-"), id == "IOC-PKG-*":
		return []string{"package.json and supported dependency manifests"}
	case strings.HasPrefix(id, "REPO-"):
		return []string{"repository root"}
	case strings.HasPrefix(id, "COMBO-"):
		return []string{"executable source files"}
	case id == "ARCHIVE-001":
		return []string{"archive entries"}
	case id == "GITHOOK-002":
		return []string{".git/hooks/*"}
	case id == "CICD-006" || id == "CICD-007" || id == "CICD-008":
		return []string{".github/workflows/*.yml", ".github/workflows/*.yaml"}
	case id == "IMAGE-001":
		return []string{"*.svg"}
	case strings.HasPrefix(id, "DOC-"):
		return []string{"*.pdf", "Office Open XML package entries"}
	case id == "IDE-007":
		return []string{"*.vsix"}
	case id == "IDE-008" || id == "IDE-009":
		return []string{"*.vsix package entries"}
	case id == "FONT-002" || id == "FONT-003":
		return []string{"*.ttf", "*.otf", "*.ttc", "*.woff", "*.woff2"}
	case id == "FONT-004" || id == "FONT-005":
		return []string{"*.ttf", "*.otf", "*.ttc", "*.woff", "*.woff2"}
	default:
		return []string{"**"}
	}
}

// LookupRuleInfo resolves a concrete rule ID, including dynamic package IOCs.
func LookupRuleInfo(id string) (RuleInfo, bool) {
	lookup := id
	if strings.HasPrefix(id, "IOC-PKG-") {
		lookup = "IOC-PKG-*"
	}
	for _, item := range BuiltinRuleCatalog() {
		if item.ID == lookup {
			if lookup != id {
				item.ID = id
			}
			return item, true
		}
	}
	return RuleInfo{}, false
}

// NormalizeFinding fills additive review fields when reading a legacy report.
func NormalizeFinding(f *model.Finding) {
	if len(f.Locations) == 0 && f.Path != "" {
		f.Locations = []model.Location{{Path: f.Path, StartLine: f.Line, Evidence: f.Evidence}}
	}
	if f.Occurrences == 0 {
		f.Occurrences = len(f.Locations)
		if f.Occurrences == 0 {
			f.Occurrences = 1
		}
	}
	if detailed := len(f.Locations) + f.LocationsOmitted; f.Occurrences < detailed {
		f.Occurrences = detailed
	}
	if len(f.Locations) > 0 {
		f.Path = f.Locations[0].Path
		f.Line = f.Locations[0].StartLine
		f.Evidence = f.Locations[0].Evidence
	}
	if f.Disposition == "" {
		f.Disposition = dispositionForFinding(*f)
	}
}

// SanitizeEvidence applies the same redaction and UTF-8-safe truncation used
// while scanning. Report conversion calls it again so legacy inputs cannot
// bypass current presentation safeguards.
func SanitizeEvidence(value string) string {
	return safeEvidence([]byte(value))
}

func dispositionForFinding(f model.Finding) model.Disposition {
	if f.Severity == model.SeverityCritical && f.Confidence == model.ConfidenceHigh && (f.Context == "executable" || f.Context == "manifest-hook" || f.Context == "ci-workflow" || f.Context == "confirmed-ioc") {
		return model.DispositionBlock
	}
	if f.RuleID == "CICD-003" || strings.HasPrefix(f.RuleID, "REPO-") || f.Category == "repository-hygiene" {
		return model.DispositionHarden
	}
	switch f.Context {
	case "documentation", "example", "test-fixture", "evidence", "generated", "dependency", "detection-definition", "metadata":
		return model.DispositionInformational
	}
	if f.Severity == model.SeverityLow || f.Confidence == model.ConfidenceLow || f.Category == "process-capability" {
		return model.DispositionInformational
	}
	return model.DispositionReview
}
