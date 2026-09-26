package scan

import (
	"bytes"
	"fmt"
	"regexp"
	"time"

	"github.com/Kevin-Umali/repyy/internal/model"
)

const jsFlowMaxSource = 1 << 20

var (
	jsAxiosCall     = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(?:get|post|request)\s*\(`)
	jsAxiosAlias    = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*axios\s*;`)
	jsAwaitResult   = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*await\s*$`)
	jsAwait         = regexp.MustCompile(`\bawait\s*$`)
	jsThen          = regexp.MustCompile(`^\s*\.then\s*\(\s*\(?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)?\s*=>\s*\{`)
	jsThenValue     = regexp.MustCompile(`^\s*\.then\s*\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*=>\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*data\s*\)`)
	jsCatchCallback = regexp.MustCompile(`^\s*\.catch\s*\(\s*\(?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)?\s*=>\s*\{`)
	jsSink          = regexp.MustCompile(`\b(?:eval|Function)\s*\(|\bnew\s+Function\s*\(|\b(?:child_process|childProcess)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(`)
	jsFunction      = regexp.MustCompile(`\bfunction(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\)\s*\{|(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*\{`)
	jsCatch         = regexp.MustCompile(`\bcatch\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*\{`)
	jsTry           = regexp.MustCompile(`\btry\s*\{`)
)

type jsScope struct{ start, end int }

func jsBraceEnd(code []byte, opening int) int {
	depth := 0
	for i := opening; i < len(code); i++ {
		switch code[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func jsFunctions(code []byte) ([]jsScope, bool) {
	var scopes []jsScope
	matches := jsFunction.FindAllIndex(code, 129)
	if len(matches) > 128 {
		return nil, false
	}
	for _, match := range matches {
		opening := match[1] - 1
		if end := jsBraceEnd(code, opening); end >= 0 {
			scopes = append(scopes, jsScope{opening, end})
		}
	}
	return scopes, true
}

func jsContainingFunction(scopes []jsScope, offset int) jsScope {
	best := jsScope{-1, -1}
	for _, scope := range scopes {
		if scope.start < offset && offset < scope.end && (best.start < 0 || scope.end-scope.start < best.end-best.start) {
			best = scope
		}
	}
	return best
}

func jsCatchForSource(code []byte, source int) (string, jsScope) {
	best := jsScope{-1, -1}
	for _, match := range jsTry.FindAllIndex(code[:source], -1) {
		opening := match[1] - 1
		end := jsBraceEnd(code, opening)
		if opening < source && source < end && (best.start < 0 || opening > best.start) {
			best = jsScope{opening, end}
		}
	}
	if best.start < 0 {
		return "", best
	}
	rest := code[best.end+1:]
	if len(rest) > 256 {
		rest = rest[:256]
	}
	match := jsCatch.FindSubmatchIndex(rest)
	if match == nil || len(bytes.TrimSpace(rest[:match[0]])) != 0 {
		return "", jsScope{-1, -1}
	}
	opening := best.end + 1 + match[1] - 1
	return string(rest[match[2]:match[3]]), jsScope{opening, jsBraceEnd(code, opening)}
}

func jsSimpleAlias(code []byte, base string, before int) []string {
	aliases := []string{base}
	if base == "" {
		return aliases
	}
	pattern := regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*` + regexp.QuoteMeta(base) + `\s*\.\s*data\b`)
	for _, match := range pattern.FindAllSubmatch(code[:before], -1) {
		if len(aliases) >= 8 {
			break
		}
		aliases = append(aliases, string(match[1]))
	}
	return aliases
}

func jsSinkUses(arg string, aliases []string, errorResponse bool) bool {
	for _, alias := range aliases {
		if alias == "" {
			continue
		}
		quoted := regexp.QuoteMeta(alias)
		if errorResponse {
			if regexp.MustCompile(`\b` + quoted + `\s*\.\s*response\s*\.\s*data\b`).MatchString(arg) {
				return true
			}
		} else if regexp.MustCompile(`\b` + quoted + `\s*\.\s*data\b|^\s*` + quoted + `\s*(?:[,)]|$)`).MatchString(arg) {
			return true
		}
	}
	return false
}

func (s *Scanner) scanJSAxiosFlow(path string, data []byte, add func(model.Finding), coverage *model.Coverage) {
	// Only Axios is a supported source. Files without that identifier cannot
	// contain a supported flow, so their unrelated function count is immaterial.
	if !bytes.Contains(data, []byte("axios")) {
		return
	}
	if len(data) > jsFlowMaxSource {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, path+" (JavaScript flow source-byte limit)")
		return
	}
	code := codeProjection(path, data)
	scopes, withinScopeLimit := jsFunctions(code)
	if !withinScopeLimit || len(jsTry.FindAllIndex(code, 129)) > 128 {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, path+" (JavaScript flow scope limit)")
		return
	}
	sources := jsAxiosCall.FindAllSubmatchIndex(code, -1)
	sinks := jsSink.FindAllIndex(code, -1)
	if len(sources) > 128 || len(sinks) > 256 {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, path+" (JavaScript flow source/sink limit)")
		return
	}
	found := 0
	pairs := 0
	deadline := time.Now().Add(150 * time.Millisecond)
	for _, source := range sources {
		if time.Now().After(deadline) {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (JavaScript flow time limit)")
			return
		}
		start, end := source[0], source[1]
		function := jsContainingFunction(scopes, start)
		name := string(code[source[2]:source[3]])
		if name != "axios" {
			validAlias := false
			for _, alias := range jsAxiosAlias.FindAllSubmatchIndex(code[:start], -1) {
				aliasScope := jsContainingFunction(scopes, alias[0])
				if string(code[alias[2]:alias[3]]) == name && (aliasScope == function || aliasScope.start < 0) {
					validAlias = true
					break
				}
			}
			if !validAlias {
				continue
			}
		}
		response := ""
		prefixStart := start - 180
		if prefixStart < 0 {
			prefixStart = 0
		}
		if match := jsAwaitResult.FindSubmatch(code[prefixStart:start]); match != nil {
			response = string(match[1])
		}
		awaited := jsAwait.Match(code[prefixStart:start])
		catchName, catchScope := "", jsScope{-1, -1}
		if awaited {
			catchName, catchScope = jsCatchForSource(code, start)
		}
		thenName, thenScope, thenError := "", jsScope{-1, -1}, false
		if response == "" {
			// A literal call's closing parenthesis is required before .then.
			callEnd := bytes.IndexByte(code[end:], ')')
			if callEnd >= 0 && callEnd < 1024 {
				candidate := code[end+callEnd+1:]
				if len(candidate) > 256 {
					candidate = candidate[:256]
				}
				m := jsThen.FindSubmatchIndex(candidate)
				if m == nil {
					m = jsCatchCallback.FindSubmatchIndex(candidate)
					thenError = m != nil
				}
				if m == nil {
					if preceding := jsThenValue.FindIndex(candidate); preceding != nil {
						remainder := candidate[preceding[1]:]
						if nested := jsCatchCallback.FindSubmatchIndex(remainder); nested != nil {
							for i := range nested {
								nested[i] += preceding[1]
							}
							m = nested
							thenError = true
						}
					}
				}
				if m != nil {
					thenName = string(candidate[m[2]:m[3]])
					opening := end + callEnd + 1 + m[1] - 1
					thenScope = jsScope{opening, jsBraceEnd(code, opening)}
				}
			}
		}
		for _, sink := range sinks {
			pairs++
			if pairs > 8192 || time.Now().After(deadline) {
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, path+" (JavaScript flow work limit)")
				return
			}
			if sink[0] <= start || sink[0]-start > 64<<10 {
				continue
			}
			argument := code[sink[1]:]
			if len(argument) > 256 {
				argument = argument[:256]
			}
			if stop := bytes.IndexByte(argument, ')'); stop >= 0 {
				argument = argument[:stop]
			}
			arg := string(argument)
			matched := false
			if function.start >= 0 && jsContainingFunction(scopes, sink[0]) == function {
				if response != "" {
					matched = jsSinkUses(arg, jsSimpleAlias(code[end:sink[0]], response, sink[0]-end), false)
				}
				if !matched && catchScope.start < sink[0] && sink[0] < catchScope.end {
					matched = jsSinkUses(arg, []string{catchName}, true)
				}
			}
			if thenScope.start >= 0 && thenScope.end > sink[0] && sink[0] > thenScope.start && thenName != "" {
				matched = jsSinkUses(arg, []string{thenName}, thenError)
			}
			if !matched {
				continue
			}
			sourceLine := 1 + bytes.Count(data[:start], []byte{'\n'})
			sinkLine := 1 + bytes.Count(data[:sink[0]], []byte{'\n'})
			f := s.finding("FLOW-001", "remote-response-execution", model.SeverityCritical, model.ConfidenceHigh, path, sinkLine, fmt.Sprintf("Axios response data from line %d reaches execution at line %d", sourceLine, sinkLine), fmt.Sprintf("Axios source line %d; execution sink line %d", sourceLine, sinkLine), "Do not execute remote response data. Review both the request and execution path.")
			f.Context = classifyContext(path, nil)
			f.Disposition = model.DispositionBlock
			f.Locations = []model.Location{{Path: path, StartLine: sourceLine, EndLine: sourceLine, Evidence: safeEvidence(data[start:end])}, {Path: path, StartLine: sinkLine, EndLine: sinkLine, Evidence: safeEvidence(data[sink[0]:sink[1]])}}
			add(f)
			found++
			if found >= 64 {
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, path+" (JavaScript flow finding limit)")
				return
			}
		}
	}
}
