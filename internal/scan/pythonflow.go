package scan

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

const pythonFlowMaxSource = 1 << 20

var (
	pythonFlowScope  = regexp.MustCompile(`^(?:async[ \t]+)?(?:def|class)[ \t]+[A-Za-z_][A-Za-z0-9_]*\b`)
	pythonFlowBranch = regexp.MustCompile(`^(?:if|elif|else|for|while|try|except|finally|with|match|case)\b`)
	pythonFlowAssign = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:[ \t]*:[^=]+)?[ \t]*(=|\+=|-=|\*=|/=)[ \t]*(.*)$`)
	pythonFlowDelete = regexp.MustCompile(`^del[ \t]+([A-Za-z_][A-Za-z0-9_]*)\s*$`)
	pythonFlowSource = regexp.MustCompile(`^(?:(?:requests|httpx)\.(?:get|post|request|put|patch|delete|head)|(?:urllib\.request\.)?urlopen)\s*\([^()]*\)(?:\s*\.\s*(?:text|content|read\s*\(\s*\)|decode\s*\([^()]*\)))*\s*$`)
	pythonFlowValue  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:\s*\.\s*(?:text|content|read\s*\(\s*\)|decode\s*\([^()]*\)))*\s*$`)
	pythonFlowSink   = regexp.MustCompile(`\b(exec|eval|compile)\s*\(\s*(?:compile\s*\(\s*)?([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*(?:text|content|read\s*\(\s*\)|decode\s*\([^()]*\)))*)\s*(?:[,)]|$)`)
	pythonFlowInline = regexp.MustCompile(`\b(exec|eval|compile)\s*\(\s*(?:(?:requests|httpx)\.(?:get|post|request|put|patch|delete|head)|(?:urllib\.request\.)?urlopen)\s*\([^()]*\)\s*\.\s*(?:text|content|read\s*\(\s*\))\s*(?:[,)]|$)`)
)

type pythonFlowScopeState struct {
	indent   int
	values   map[string]int
	branches []int
}

// scanPythonRemoteFlow tracks only simple, straight-line assignments. It does
// not infer control flow, interprocedural flows, or execution through files.
func (s *Scanner) scanPythonRemoteFlow(path string, data []byte, add func(model.Finding), coverage *model.Coverage) {
	if !bytes.Contains(data, []byte("requests")) && !bytes.Contains(data, []byte("httpx")) && !bytes.Contains(data, []byte("urlopen")) {
		return
	}
	if len(data) > pythonFlowMaxSource {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, path+" (Python flow source-byte limit)")
		return
	}
	codeLines := splitLines(codeProjection(path, data))
	originalLines := splitLines(data)
	stack := []pythonFlowScopeState{{indent: -1, values: make(map[string]int)}}
	found := 0
	for i, codeLine := range codeLines {
		line := strings.TrimLeft(string(codeLine), " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(codeLine) - len(line)
		for len(stack) > 1 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		if pythonFlowScope.MatchString(line) {
			if len(stack) >= 128 {
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, path+" (Python flow scope limit)")
				return
			}
			stack = append(stack, pythonFlowScopeState{indent: indent, values: make(map[string]int)})
			continue
		}
		state := &stack[len(stack)-1]
		values := state.values
		for len(state.branches) > 0 && indent <= state.branches[len(state.branches)-1] {
			state.branches = state.branches[:len(state.branches)-1]
			clear(values)
		}
		if pythonFlowBranch.MatchString(line) {
			clear(values)
			state.branches = append(state.branches, indent)
			continue
		}
		if deleted := pythonFlowDelete.FindStringSubmatch(line); deleted != nil {
			delete(values, deleted[1])
			continue
		}
		bareCalls := func(pattern *regexp.Regexp) [][]string {
			matches := pattern.FindAllStringSubmatchIndex(line, -1)
			var result [][]string
			for _, match := range matches {
				prefix := strings.TrimRight(line[:match[0]], " \t")
				if strings.HasSuffix(prefix, ".") {
					continue
				}
				parts := make([]string, len(match)/2)
				for j := range parts {
					if match[2*j] >= 0 {
						parts[j] = line[match[2*j]:match[2*j+1]]
					}
				}
				result = append(result, parts)
			}
			return result
		}
		sinks := bareCalls(pythonFlowSink)
		for _, inline := range bareCalls(pythonFlowInline) {
			sinks = append(sinks, []string{inline[0], inline[1], ""})
		}
		for _, sink := range sinks {
			value := pythonFlowValue.FindStringSubmatch(sink[2])
			sourceLine := i + 1
			if sink[2] != "" {
				if value == nil || values[value[1]] == 0 {
					continue
				}
				sourceLine = values[value[1]]
			}
			sinkLine := i + 1
			severity, confidence, disposition := model.SeverityHigh, model.ConfidenceMedium, model.DispositionReview
			context := classifyContext(path, nil)
			if isContextualContext(context) {
				confidence, disposition = model.ConfidenceLow, model.DispositionInformational
			}
			f := s.finding("FLOW-002", "remote-response-execution", severity, confidence, path, sinkLine, fmt.Sprintf("Python remote response from line %d may reach %s at line %d", sourceLine, sink[1], sinkLine), fmt.Sprintf("remote response line %d; dynamic code line %d", sourceLine, sinkLine), "Review the request and execution path; do not execute untrusted remote response data.")
			f.Context, f.Disposition = context, disposition
			f.Locations = []model.Location{{Path: path, StartLine: sourceLine, EndLine: sourceLine, Evidence: safeEvidence(originalLines[sourceLine-1])}, {Path: path, StartLine: sinkLine, EndLine: sinkLine, Evidence: safeEvidence(originalLines[i])}}
			add(f)
			found++
			if found >= 64 {
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, path+" (Python flow finding limit)")
				return
			}
		}
		assignment := pythonFlowAssign.FindStringSubmatch(line)
		if assignment == nil {
			continue
		}
		name, expr := assignment[1], strings.TrimSpace(assignment[3])
		if assignment[2] == "=" && strings.HasPrefix(expr, "=") {
			continue
		}
		source := 0
		if assignment[2] != "=" {
			delete(values, name)
			continue
		} else if pythonFlowSource.MatchString(expr) {
			source = i + 1
		} else if value := pythonFlowValue.FindStringSubmatch(expr); value != nil {
			source = values[value[1]]
		}
		delete(values, name)
		if source != 0 {
			values[name] = source
		}
	}
}
