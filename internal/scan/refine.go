package scan

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

// ruleMatch is one reported match of a content rule. line is the original line, or the
// matched span for a multi-line match, and spans holds each match's offsets in line.
// Code-scoped rules match a projection that keeps offsets, so spans index line too.
type ruleMatch struct {
	path  string
	line  []byte
	spans [][]int
	file  []byte
}

// routineMatch reports whether a match is a routine fixed form of the capability its
// rule exists for.
type routineMatch func(ruleMatch) bool

var routineMatches = map[string]routineMatch{
	"AGENT-001": func(m ruleMatch) bool { return pinnedMCPServersOnly(m.file) },
	"IDE-001":   containerSideDevcontainerCommand,
	"EXEC-002":  fixedProgramLaunch,
}

// refineSeverity lowers a high or critical match to medium when the rule's routine
// check recognizes it. It never raises severity.
func refineSeverity(ruleID string, m ruleMatch, severity model.Severity) model.Severity {
	routine, ok := routineMatches[ruleID]
	if ok && severity.Rank() >= model.SeverityHigh.Rank() && routine(m) {
		return model.SeverityMedium
	}
	return severity
}

var agentAutoExecKey = regexp.MustCompile(`(?i)["']?(?:hooks?|auto[-_ ]?run|allow[-_ ]?commands?|dangerously[-_ ]?skip|bypass[-_ ]?permissions?)["']?\s*[:=]`)

// packageRunners maps a package-runner command to the subcommand that must precede the
// package argument.
var packageRunners = map[string]string{
	"npx": "", "uvx": "", "bunx": "", "pnpx": "", "pipx": "run", "pnpm": "dlx", "yarn": "dlx",
}

var versionedPackage = regexp.MustCompile(`^@?[^@=\s]+(?:@|==)\d`)

type mcpServer struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// pinnedMCPServersOnly reports whether a JSON agent configuration only declares MCP
// servers that a package runner starts from a pinned version. Hooks, auto-run keys,
// and anything that does not parse stay high.
func pinnedMCPServersOnly(file []byte) bool {
	if agentAutoExecKey.Match(file) {
		return false
	}
	var config struct {
		MCPServers map[string]mcpServer `json:"mcpServers"`
	}
	if json.Unmarshal(file, &config) != nil || len(config.MCPServers) == 0 {
		return false
	}
	for _, server := range config.MCPServers {
		if server.Command != "" && !pinnedRunnerLaunch(server) {
			return false
		}
	}
	return true
}

func pinnedRunnerLaunch(server mcpServer) bool {
	command := strings.ToLower(filepath.Base(server.Command))
	command = strings.TrimSuffix(strings.TrimSuffix(command, ".cmd"), ".exe")
	subcommand, ok := packageRunners[command]
	if !ok {
		return false
	}
	args := server.Args
	if subcommand != "" {
		if len(args) == 0 || args[0] != subcommand {
			return false
		}
		args = args[1:]
	}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return versionedPackage.MatchString(arg)
		}
	}
	return false
}

var (
	hostSideDevcontainerKey = regexp.MustCompile(`(?i)initializeCommand`)
	networkOrShellPayload   = regexp.MustCompile(`(?i)\b(?:curl|wget|iwr|invoke-webrequest|base64|eval)\b|https?://|\|\s*(?:ba|z)?sh\b`)
)

// containerSideDevcontainerCommand reports whether a devcontainer lifecycle command runs
// inside the container in a file that carries no network or shell payload.
// initializeCommand runs on the host, so it never qualifies.
func containerSideDevcontainerCommand(m ruleMatch) bool {
	base := strings.ToLower(filepath.Base(innerPath(m.path)))
	if base != "devcontainer.json" && base != ".devcontainer.json" {
		return false
	}
	return !hostSideDevcontainerKey.Match(m.line) && !networkOrShellPayload.Match(m.file)
}

var (
	fixedProgramCall = regexp.MustCompile(`^(?:(?:child_process\.)?(?:execFileSync|execFile|spawnSync|spawn)\s*\(\s*["']([\w.+-]+)["']\s*[,)]|subprocess\.(?:run|Popen|call)\s*\(\s*\[\s*["']([\w.+-]+)["'])`)
	shellOption      = regexp.MustCompile(`shell\s*[:=]\s*(?:true|True)`)
)

// fixedPrograms are build, version-control, and formatting tools whose launch with a
// literal name is routine. Anything else, interpreters included, stays high.
var fixedPrograms = map[string]bool{
	"git": true, "gh": true, "go": true, "cargo": true, "rustc": true, "make": true, "cmake": true,
	"gcc": true, "g++": true, "cc": true, "clang": true, "tsc": true, "prettier": true, "eslint": true,
	"black": true, "ruff": true, "isort": true, "gofmt": true, "rustfmt": true, "clang-format": true,
	"ls": true, "cat": true, "echo": true, "which": true, "open": true, "xdg-open": true, "code": true,
}

// fixedProgramLaunch reports whether every match on the line launches a known fixed
// program by literal name without a shell. Each match is read at its own offset, so a
// lookalike in a comment or string cannot vouch for a different call.
func fixedProgramLaunch(m ruleMatch) bool {
	if len(m.spans) == 0 || shellOption.Match(m.line) {
		return false
	}
	for _, span := range m.spans {
		call := fixedProgramCall.FindSubmatch(m.line[span[0]:])
		if call == nil {
			return false
		}
		if !fixedPrograms[strings.ToLower(string(call[1])+string(call[2]))] {
			return false
		}
	}
	return true
}

// capabilityRules report what code can do, not what it intends. Ordinary programs use
// these capabilities, so alone they are reviewed at medium.
var capabilityRules = map[string]bool{
	"EXEC-001": true, "EXEC-002": true, "IMPORT-001": true, "UNSERIALIZE-001": true, "EXFIL-001": true, "EXFIL-002": true,
	"PROTO-001": true, "OBFS-002": true, "FINGERPRINT-001": true,
}

// threatCategories are signals of intent: hiding, staging, or sending something. One in
// a file keeps that file's capability findings high. The value records whether the
// signal runs code, which decides whether it keeps its severity inside test code.
var threatCategories = map[string]bool{
	"download-execute": true, "decode-execute": true, "staged-download-execute": true, "fetch-and-execute": true,
	"evasion-and-execution": true, "remote-response-execution": true, "loader-injection": true,
	"encoded-execution": true, "proxy-execution": true, "reverse-shell": true, "backdoor": true,
	"known-malicious-file":        true,
	"collection-and-exfiltration": false, "encoded-payload": false, "string-obfuscation": false,
	"prototype-evasion": false, "global-access": false, "credential-harvesting": false, "exfiltration": false,
	"suspicious-network": false, "cryptomining": false, "sandbox-evasion": false, "host-fingerprinting": false,
	"hardcoded-network": false, "remote-import": false, "unicode-obfuscation": false,
	"contagious-interview": false, "decoded-indicator": false, "high-entropy-code": false,
}

// executionCapabilities run code they are handed. Decoding beside one of them in the
// same file is the classic way to hide a payload, so decoding vouches for them even
// though decoding alone is routine.
var executionCapabilities = map[string]bool{"EXEC-001": true, "EXEC-002": true, "IMPORT-001": true}

const decodingRule = "OBFS-002"

// autorunContexts are contexts whose files run without an explicit command.
var autorunContexts = map[string]bool{
	"manifest": true, "manifest-hook": true, "ci-workflow": true, "git-hook": true, "agent-instruction": true,
}

// autorunFile matches files that tools load on their own: install and build scripts,
// test bootstraps, and JavaScript tool configuration.
var autorunFile = regexp.MustCompile(`^(?:setup\.py|build\.rs|conftest\.py|[^/]+\.config\.[cm]?[jt]s|\.eslintrc\.c?js|gulpfile\.[cm]?[jt]s|gruntfile\.[cm]?[jt]s)$`)

// corroborateCapabilities lowers high capability findings to medium unless their file
// carries a threat signal or runs automatically. findings must hold every finding of
// each file it covers.
func corroborateCapabilities(findings []model.Finding) {
	threatened, decoded := map[string]bool{}, map[string]bool{}
	for _, f := range findings {
		threatened[f.Path] = threatened[f.Path] || isThreatSignal(f.RuleID, f.Category, f.Confidence)
		decoded[f.Path] = decoded[f.Path] || f.RuleID == decodingRule && f.Confidence != model.ConfidenceLow
	}
	for i := range findings {
		f := &findings[i]
		if !capabilityRules[f.RuleID] || f.Severity.Rank() < model.SeverityHigh.Rank() || threatened[f.Path] {
			continue
		}
		if decoded[f.Path] && executionCapabilities[f.RuleID] {
			continue
		}
		if autorunContexts[f.Context] || autorunFile.MatchString(strings.ToLower(filepath.Base(innerPath(f.Path)))) {
			continue
		}
		f.Severity = model.SeverityMedium
	}
}

// isThreatSignal reports whether a finding shows intent. Capabilities and
// low-confidence findings never do.
func isThreatSignal(ruleID, category string, confidence model.Confidence) bool {
	if strings.HasPrefix(ruleID, "IOC-") {
		return true
	}
	_, threat := threatCategories[category]
	return threat && !capabilityRules[ruleID] && confidence != model.ConfidenceLow
}

// downgradeAllowed reports whether a context may lower a rule's severity. Test code
// runs on a routine command, so a threat that runs code keeps its severity there.
func downgradeAllowed(ruleAllows bool, ruleID, category, context string) bool {
	executes := threatCategories[category] && !capabilityRules[ruleID] || strings.HasPrefix(ruleID, "IOC-")
	return ruleAllows && !(context == "test-fixture" && executes)
}
