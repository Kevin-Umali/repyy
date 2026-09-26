package scan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kevin-Umali/repyy/internal/model"
)

const (
	jsDecodeMaxSource   = 2 << 20
	jsDecodeMaxLiteral  = 128 << 10
	jsDecodeMaxOutput   = 1 << 20
	jsDecodeMaxValues   = 4096
	jsDecodeMaxFindings = 64
)

var (
	jsCharCodes       = regexp.MustCompile(`\bString\.fromCharCode\s*\(([^()]+)\)`)
	jsCharCodeStart   = regexp.MustCompile(`\bString\.fromCharCode\s*\(`)
	jsByteArray       = regexp.MustCompile(`\b(?:new\s+)?Uint8Array\s*\(\s*\[([^\]]+)\]\s*\)`)
	jsDynamicRotation = regexp.MustCompile(`\[\s*['"]push['"]\s*\]\s*\([^\n]{0,128}\[\s*['"]shift['"]\s*\]\s*\(`)
	jsArrayDecl       = regexp.MustCompile(`\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\[`)
	jsStaticLookup    = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\[\s*(0x[0-9A-Fa-f]+|[0-9]+)\s*\]`)
	jsTableAlias      = regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:[;,\n]|$)`)
	jsTableMutation   = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(?:push|shift|pop|unshift|reverse|splice|sort)\s*\(`)
)

type jsRecovered struct {
	value   string
	start   int
	end     int
	method  string
	origins []jsSpan
}

type jsSpan struct{ start, end int }

type jsTableValue struct {
	value string
	span  jsSpan
}

type jsStringTable struct {
	values []jsTableValue
	end    int
}

func jsLiteralStringTables(data, projection []byte, deadline time.Time) (map[string]jsStringTable, string) {
	declarations := jsArrayDecl.FindAllSubmatchIndex(projection, 129)
	if len(declarations) > 128 {
		return nil, "JavaScript decoder table limit"
	}
	tables := make(map[string]jsStringTable)
	totalValues, totalBytes := 0, 0
	for _, declaration := range declarations {
		if time.Now().After(deadline) {
			return tables, "JavaScript decoder time limit"
		}
		name := string(data[declaration[2]:declaration[3]])
		start := declaration[1]
		window := data[start:]
		if len(window) > jsDecodeMaxLiteral+1 {
			window = window[:jsDecodeMaxLiteral+1]
		}
		end := bytes.IndexByte(window, ']')
		if end < 0 || end > jsDecodeMaxLiteral {
			continue
		}
		end += start
		var values []jsTableValue
		valid := true
		for cursor := start; cursor < end; {
			for cursor < end && (data[cursor] == ' ' || data[cursor] == '\t' || data[cursor] == '\r' || data[cursor] == '\n') {
				cursor++
			}
			if cursor == end {
				break
			}
			if data[cursor] != '\'' && data[cursor] != '"' {
				valid = false
				break
			}
			value, next, _, ok := jsString(data, cursor)
			if !ok || next > end {
				valid = false
				break
			}
			values = append(values, jsTableValue{value: value, span: jsSpan{cursor, next}})
			totalValues++
			totalBytes += len(value)
			if totalValues > jsDecodeMaxValues || totalBytes > jsDecodeMaxOutput {
				return tables, "JavaScript decoder table output/value limit"
			}
			cursor = next
			for cursor < end && (data[cursor] == ' ' || data[cursor] == '\t' || data[cursor] == '\r' || data[cursor] == '\n') {
				cursor++
			}
			if cursor < end && data[cursor] != ',' {
				valid = false
				break
			}
			if cursor < end {
				cursor++
			}
		}
		if valid && len(values) > 0 {
			if _, exists := tables[name]; exists {
				return tables, "unsupported duplicate literal table identifier"
			}
			tables[name] = jsStringTable{values: values, end: end + 1}
		}
	}
	return tables, ""
}

func jsTableLookup(index []int, code []byte, tables map[string]jsStringTable) (jsTableValue, bool) {
	name := string(code[index[2]:index[3]])
	table, exists := tables[name]
	if !exists || index[0] <= table.end || index[0]-table.end > 1024 || bytes.IndexAny(code[table.end:index[0]], "{}") >= 0 {
		return jsTableValue{}, false
	}
	number := string(code[index[4]:index[5]])
	base := 10
	if strings.HasPrefix(number, "0x") {
		base = 0
	}
	position, err := strconv.ParseUint(number, base, 16)
	if err != nil || position >= uint64(len(table.values)) {
		return jsTableValue{}, false
	}
	return table.values[position], true
}

// decodeJS recovers only literal data and constant indexes into unmodified
// literal string tables. It never executes functions or arbitrary expressions.
func decodeJS(path string, data []byte) ([]jsRecovered, string) {
	if len(data) > jsDecodeMaxSource {
		return nil, "JavaScript decoder source-byte limit"
	}
	deadline := time.Now().Add(50 * time.Millisecond)
	projection := codeProjection(path, data)
	values := make([]jsRecovered, 0)
	outputBytes := 0
	add := func(value string, start, end int, method string, origins ...jsSpan) bool {
		if len(values) >= jsDecodeMaxValues || outputBytes+len(value) > jsDecodeMaxOutput {
			return false
		}
		if value != "" && utf8.ValidString(value) {
			values = append(values, jsRecovered{value: value, start: start, end: end, method: method, origins: append([]jsSpan(nil), origins...)})
			outputBytes += len(value)
		}
		return true
	}
	for i := 0; i < len(data); {
		if i&4095 == 0 && time.Now().After(deadline) {
			return values, "JavaScript decoder time limit"
		}
		if i+1 < len(data) && data[i] == '/' && data[i+1] == '/' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		if data[i] == '`' {
			i++
			for i < len(data) {
				if data[i] == '\\' && i+1 < len(data) {
					i += 2
					continue
				}
				if data[i] == '`' {
					i++
					break
				}
				i++
			}
			continue
		}
		if i+1 < len(data) && data[i] == '/' && data[i+1] == '*' {
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				break
			}
			i += end + 4
			continue
		}
		if data[i] != '\'' && data[i] != '"' {
			i++
			continue
		}
		start := i
		value, next, escaped, ok := jsString(data, i)
		if !ok {
			if next-start > jsDecodeMaxLiteral {
				return values, "JavaScript decoder literal-byte limit"
			}
			i++
			continue
		}
		if next-start > jsDecodeMaxLiteral {
			return values, "JavaScript decoder literal-byte limit"
		}
		i = next
		method := "JavaScript escape"
		// Concatenation is accepted only when every operand is a literal.
		for {
			j := i
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
				j++
			}
			if j >= len(data) || data[j] != '+' {
				break
			}
			j++
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
				j++
			}
			if j >= len(data) || (data[j] != '\'' && data[j] != '"') {
				break
			}
			part, end, _, valid := jsString(data, j)
			if !valid || end-start > jsDecodeMaxLiteral {
				break
			}
			value += part
			i = end
			escaped = true
			method = "literal concatenation"
		}
		if escaped && !add(value, start, i, method) {
			return values, "JavaScript decoder output/value limit"
		}
		if len(value) >= 32 {
			if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && utf8.Valid(decoded) && !add(string(decoded), start, i, "Base64 literal") {
				return values, "JavaScript decoder output/value limit"
			}
			if len(value)%2 == 0 {
				if decoded, err := hex.DecodeString(value); err == nil && utf8.Valid(decoded) && !add(string(decoded), start, i, "hex literal") {
					return values, "JavaScript decoder output/value limit"
				}
			}
		}
	}
	unsupported := false
	for _, pattern := range []*regexp.Regexp{jsCharCodes, jsByteArray} {
		matches := pattern.FindAllSubmatchIndex(data, jsDecodeMaxValues+1)
		if len(matches) > jsDecodeMaxValues {
			return values, "JavaScript decoder expression limit"
		}
		for _, index := range matches {
			if projection[index[0]] != data[index[0]] {
				continue
			}
			if time.Now().After(deadline) {
				return values, "JavaScript decoder time limit"
			}
			if index[3]-index[2] > jsDecodeMaxLiteral {
				return values, "JavaScript decoder literal-byte limit"
			}
			body := string(data[index[2]:index[3]])
			parts := strings.Split(body, ",")
			if len(parts) > 8192 {
				return values, "JavaScript decoder array-item limit"
			}
			decoded := make([]byte, 0, len(parts))
			valid := true
			for _, part := range parts {
				value, err := strconv.ParseUint(strings.TrimSpace(part), 0, 8)
				if err != nil {
					valid = false
					unsupported = true
					break
				}
				decoded = append(decoded, byte(value))
			}
			if valid && utf8.Valid(decoded) && !add(string(decoded), index[0], index[1], "literal character/byte array") {
				return values, "JavaScript decoder output/value limit"
			}
		}
	}
	starts := jsCharCodeStart.FindAllIndex(projection, jsDecodeMaxValues+1)
	if len(starts) > jsDecodeMaxValues {
		return values, "JavaScript decoder expression limit"
	}
	for _, index := range starts {
		match := jsCharCodes.FindIndex(data[index[0]:])
		if match == nil || match[0] != 0 {
			unsupported = true
			break
		}
	}
	tables, tableLimit := jsLiteralStringTables(data, projection, deadline)
	if tableLimit != "" {
		return values, tableLimit
	}
	for _, index := range jsDynamicRotation.FindAllIndex(data, 1) {
		if projection[index[0]] == data[index[0]] {
			unsupported = true
			tables = nil // A rotated table cannot be indexed using its original order.
			break
		}
	}
	aliases := jsTableAlias.FindAllSubmatchIndex(projection, jsDecodeMaxValues+1)
	if len(aliases) > jsDecodeMaxValues {
		return values, "JavaScript decoder alias limit"
	}
	for _, index := range aliases {
		for _, span := range [][2]int{{index[2], index[3]}, {index[4], index[5]}} {
			name := string(projection[span[0]:span[1]])
			if _, exists := tables[name]; exists {
				delete(tables, name)
				unsupported = true
			}
		}
	}
	mutations := jsTableMutation.FindAllSubmatchIndex(projection, jsDecodeMaxValues+1)
	if len(mutations) > jsDecodeMaxValues {
		return values, "JavaScript decoder mutation limit"
	}
	for _, index := range mutations {
		name := string(projection[index[2]:index[3]])
		if _, exists := tables[name]; exists {
			delete(tables, name)
			unsupported = true
		}
	}
	lookups := jsStaticLookup.FindAllSubmatchIndex(projection, jsDecodeMaxValues+1)
	if len(lookups) > jsDecodeMaxValues {
		return values, "JavaScript decoder lookup limit"
	}
	for _, index := range lookups {
		rest := projection[index[1]:]
		if len(rest) > 64 {
			rest = rest[:64]
		}
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) > 0 && rest[0] == '=' && (len(rest) == 1 || rest[1] != '=') {
			name := string(projection[index[2]:index[3]])
			if _, exists := tables[name]; exists {
				delete(tables, name)
				unsupported = true
			}
		}
	}
	for i := 0; i < len(lookups); i++ {
		if time.Now().After(deadline) {
			return values, "JavaScript decoder time limit"
		}
		item, ok := jsTableLookup(lookups[i], projection, tables)
		if !ok {
			continue
		}
		value := item.value
		origins := []jsSpan{item.span}
		start, end := lookups[i][0], lookups[i][1]
		for j := i + 1; j < len(lookups) && j < i+8; j++ {
			if lookups[j][0]-end > 128 {
				break
			}
			between := strings.TrimSpace(string(projection[end:lookups[j][0]]))
			if between != "+" {
				break
			}
			part, valid := jsTableLookup(lookups[j], projection, tables)
			if !valid {
				break
			}
			value += part.value
			origins = append(origins, part.span)
			end = lookups[j][1]
			i = j
		}
		if !add(value, start, end, "static string-table lookup", origins...) {
			return values, "JavaScript decoder output/value limit"
		}
	}
	if unsupported {
		return values, "unsupported JavaScript literal expression or dynamic string-table rotation"
	}
	return values, ""
}

func jsString(data []byte, start int) (string, int, bool, bool) {
	quote := data[start]
	var out strings.Builder
	escaped := false
	for i := start + 1; i < len(data); i++ {
		if i-start > jsDecodeMaxLiteral {
			return "", i, false, false
		}
		if data[i] == quote {
			return out.String(), i + 1, escaped, true
		}
		if data[i] == '\n' || data[i] == '\r' {
			return "", i, false, false
		}
		if data[i] != '\\' {
			out.WriteByte(data[i])
			continue
		}
		escaped = true
		i++
		if i >= len(data) {
			return "", i, false, false
		}
		switch data[i] {
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'b':
			out.WriteByte('\b')
		case 'f':
			out.WriteByte('\f')
		case '\\', '\'', '"', '/':
			out.WriteByte(data[i])
		case 'x', 'u':
			count := 2
			if data[i] == 'u' {
				count = 4
			}
			if i+count >= len(data) {
				return "", i, false, false
			}
			value, err := strconv.ParseUint(string(data[i+1:i+1+count]), 16, 16)
			if err != nil {
				return "", i, false, false
			}
			if value >= 0xd800 && value <= 0xdfff {
				return "", i, false, false
			}
			out.WriteRune(rune(value))
			i += count
		default:
			return "", i, false, false
		}
	}
	return "", len(data), false, false
}

func (s *Scanner) scanJSDecoded(path string, data []byte, add func(model.Finding), coverage *model.Coverage) {
	values, limited := decodeJS(path, data)
	if limited != "" {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, fmt.Sprintf("%s (%s)", path, limited))
	}
	findings := 0
	for _, value := range values {
		for _, rule := range s.opts.Rules {
			if !(strings.HasPrefix(rule.ID, "CRED-") || strings.HasPrefix(rule.ID, "REVSHELL-") || strings.HasPrefix(rule.ID, "PERSIST-") || strings.HasPrefix(rule.ID, "SECRET-") || rule.ID == "EXFIL-002" || rule.ID == "IPURL-001") || !rule.Applies(path) || !rule.re.MatchString(value.value) {
				continue
			}
			line := 1 + bytes.Count(data[:value.start], []byte{'\n'})
			f := s.findingRange("DECODE-001", "decoded-indicator", rule.Severity, model.ConfidenceMedium, path, line, 1+bytes.Count(data[:value.end], []byte{'\n'}), "Static "+value.method+" reveals "+rule.Description, safeEvidence([]byte(value.value)), "Review the source literal and its use without executing it.")
			for _, origin := range value.origins {
				originLine := 1 + bytes.Count(data[:origin.start], []byte{'\n'})
				f.Locations = append(f.Locations, model.Location{Path: path, StartLine: originLine, Evidence: safeEvidence(data[origin.start:origin.end])})
			}
			f.Context = classifyContext(path, nil)
			f.ContributingRuleIDs = []string{rule.ID}
			add(f)
			findings++
			if findings >= jsDecodeMaxFindings {
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, path+" (JavaScript decoder finding limit)")
				return
			}
		}
	}
}
