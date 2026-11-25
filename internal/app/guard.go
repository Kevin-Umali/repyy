package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	guardInputLimit = 1 << 20
	// guardDefaultTimeout bounds the whole guard scan, clone included. Hook
	// runners treat a killed hook as a non-blocking error, so this must stay
	// well below the hook timeout the docs recommend (180 seconds).
	guardDefaultTimeout = 2 * time.Minute
)

// guardDecision is the JSON written by `repyy guard --format json`.
type guardDecision struct {
	Decision string        `json:"decision"`
	Reason   string        `json:"reason,omitempty"`
	Targets  []guardResult `json:"targets"`
}

type guardResult struct {
	gateTarget
	Blocking bool         `json:"blocking"`
	Scan     *scanSummary `json:"scan,omitempty"`
}

// hookPayload covers the pre-tool hook shapes that carry a shell command:
// tool_input.command (Claude Code, Codex, Gemini CLI) or a top-level command.
type hookPayload struct {
	ToolName  string          `json:"tool_name"`
	Command   json.RawMessage `json:"command"`
	CWD       string          `json:"cwd"`
	ToolInput json.RawMessage `json:"tool_input"`
}

var shellTools = map[string]bool{"bash": true, "shell": true, "local_shell": true, "exec_command": true, "run_shell_command": true, "run_terminal_cmd": true}

type guardArgs struct {
	command         string
	commandSet      bool
	cwd             string
	format          string
	allowIncomplete bool
	scan            scanArgs
}

var errGuardMisconfigured = errors.New("repyy guard misconfigured")

func parseGuardArgs(args []string) (guardArgs, error) {
	g := guardArgs{format: "text"}
	scanFlags := []string{"--timeout=" + guardDefaultTimeout.String()}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			g.command, g.commandSet = shellJoin(args[i+1:]), true
			break
		}
		name, value, inline := strings.Cut(a, "=")
		switch name {
		case "--command", "--cwd", "--format":
			if !inline {
				if i+1 >= len(args) {
					return g, fmt.Errorf("missing value for %s", name)
				}
				i++
				value = args[i]
			}
			switch name {
			case "--command":
				g.command, g.commandSet = value, true
			case "--cwd":
				g.cwd = value
			default:
				g.format = value
			}
		case "--allow-incomplete":
			g.allowIncomplete = true
			if inline {
				allow, err := strconv.ParseBool(value)
				if err != nil {
					return g, errors.New("--allow-incomplete must be true or false")
				}
				g.allowIncomplete = allow
			}
		case "--output", "--file":
			return g, fmt.Errorf("%s is not supported by repyy guard", name)
		default:
			scanFlags = append(scanFlags, a)
		}
	}
	if g.format != "text" && g.format != "json" {
		return g, errors.New("--format must be text or json")
	}
	var err error
	if g.scan, err = parseScanArgs(scanFlags); err != nil {
		return g, err
	}
	if len(g.scan.targets) > 0 {
		return g, fmt.Errorf("unexpected argument %q; pass the command with --command or after --", g.scan.targets[0])
	}
	return g, nil
}

// runGuard is a pre-command gate for agent hooks. It exits 0 to allow the
// command and 2 to block it, writing the reason to stderr. Hook runners such as
// Claude Code only block on exit 2, so every failure, a misconfigured guard
// included, blocks.
func runGuard(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) (int, error) {
	g, err := parseGuardArgs(args)
	if err != nil {
		err = fmt.Errorf("%w: %w", errGuardMisconfigured, err)
	}
	decision := guardDecision{Decision: "allow", Targets: []guardResult{}}
	if err == nil {
		err = guard(&decision, g, stdin, version)
	}
	if err != nil {
		decision.Decision = "block"
		decision.Reason = failClosedReason(err)
	}
	if g.format == "json" {
		if _, err := encodeJSON(stdout, decision); err != nil {
			fmt.Fprintln(stderr, "repyy guard could not write its decision:", err)
			return 2, nil
		}
	}
	if decision.Decision == "block" {
		fmt.Fprintln(stderr, decision.Reason)
		return 2, nil
	}
	return 0, nil
}

func failClosedReason(err error) string {
	if errors.Is(err, errGuardMisconfigured) {
		return err.Error() + "\nFix the repyy guard hook configuration; it blocks every command it cannot check."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "repyy guard blocked this command: the scan did not finish within --timeout. Review the target with `repyy scan` and ask the user before running this command."
	}
	return "repyy guard blocked this command because it could not check it: " + err.Error()
}

func guard(decision *guardDecision, g guardArgs, stdin io.Reader, version string) error {
	if !g.commandSet {
		payload, err := readHookPayload(stdin)
		if err != nil {
			return err
		}
		if g.command, err = payload.command(); err != nil {
			return err
		}
		if g.cwd == "" {
			g.cwd = payload.CWD
		}
	}
	if g.cwd == "" {
		var err error
		if g.cwd, err = os.Getwd(); err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
	}
	targets := gateTargets(g.command, g.cwd)
	if len(targets) == 0 {
		return nil
	}
	return evaluateGuard(decision, targets, g, version)
}

func evaluateGuard(decision *guardDecision, targets []gateTarget, g guardArgs, version string) error {
	opts := g.scan
	opts.targets = nil
	for _, t := range targets {
		if t.Unverifiable == "" {
			opts.targets = append(opts.targets, t.Target)
		}
	}
	var results []scanSummary
	if len(opts.targets) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
		defer cancel()
		report, _, err := executeScan(ctx, opts, version, nil, nil)
		var command commandError
		if errors.As(err, &command) && command.code == 3 {
			return fmt.Errorf("%w: %w", errGuardMisconfigured, err)
		}
		if err != nil {
			return err
		}
		threshold, _ := parseSeverity(opts.failOn)
		for _, result := range report.Results {
			results = append(results, summarizeResult(result, threshold, 3))
		}
	}
	var reasons []string
	for _, target := range targets {
		result := guardResult{gateTarget: target}
		if target.Unverifiable != "" {
			result.Blocking = !g.allowIncomplete
		} else {
			summary := results[0]
			results = results[1:]
			result.Scan = &summary
			result.Blocking = summary.ExceedsFailOn || (summary.incomplete() && !g.allowIncomplete)
		}
		if result.Blocking {
			reasons = append(reasons, guardReason(result))
		}
		decision.Targets = append(decision.Targets, result)
	}
	if len(reasons) > 0 {
		decision.Decision = "block"
		decision.Reason = "repyy guard blocked this command before it ran.\n" + strings.Join(reasons, "\n") +
			"\nReview the full report with `repyy scan <target>` and ask the user before running this command."
	}
	return nil
}

func guardReason(r guardResult) string {
	line := fmt.Sprintf("- %s %s: ", r.Trigger, displayTarget(r.Target))
	if r.Unverifiable != "" {
		return line + "cannot verify (" + r.Unverifiable + ")"
	}
	s := *r.Scan
	line += s.Verdict
	if s.incomplete() {
		detail := s.Error
		if detail == "" && len(s.Warnings) > 0 {
			detail = s.Warnings[0]
		}
		if detail != "" {
			line += " (" + detail + ")"
		}
		return line
	}
	line += fmt.Sprintf(", %d of %d findings at or above %s", s.AtOrAboveFailOn, s.Counts.Total, s.FailOn)
	for _, f := range s.TopFindings {
		if f.Severity.Rank() >= s.FailOn.Rank() {
			line += fmt.Sprintf("\n    %s %s %s:%d %s", f.RuleID, f.Severity, f.Path, f.Line, f.Message)
		}
	}
	return line
}

func readHookPayload(stdin io.Reader) (hookPayload, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, guardInputLimit+1))
	if err != nil {
		return hookPayload{}, fmt.Errorf("read hook input: %w", err)
	}
	if len(data) > guardInputLimit {
		return hookPayload{}, errors.New("hook input exceeds 1 MiB")
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return hookPayload{}, fmt.Errorf("%w: no command; pass --command, a command after --, or hook JSON on stdin", errGuardMisconfigured)
	}
	var payload hookPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return hookPayload{}, fmt.Errorf("hook input is not a JSON object: %w", err)
	}
	return payload, nil
}

// command returns the shell command the hooked tool would run, or "" for a
// tool that runs no shell command.
func (p hookPayload) command() (string, error) {
	var input struct {
		Command json.RawMessage `json:"command"`
	}
	if len(p.ToolInput) > 0 && string(p.ToolInput) != "null" {
		if err := json.Unmarshal(p.ToolInput, &input); err != nil {
			return "", errors.New("hook tool_input is not a JSON object")
		}
	}
	for _, raw := range []json.RawMessage{input.Command, p.Command} {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) == nil {
			return text, nil
		}
		var argv []string
		if json.Unmarshal(raw, &argv) == nil {
			return shellJoin(argv), nil
		}
		return "", errors.New("hook command must be a string or an array of strings")
	}
	if p.ToolName == "" || shellTools[strings.ToLower(p.ToolName)] {
		return "", errors.New("hook input has no command to check")
	}
	return "", nil
}

// shellJoin quotes argv so the shell lexer reads the same words back.
func shellJoin(words []string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		if w != "" && !strings.ContainsAny(w, " \t\n'\"\\$`;&|()<>#*?~") {
			quoted[i] = w
			continue
		}
		quoted[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}
