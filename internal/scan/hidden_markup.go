package scan

import (
	"bytes"
	"encoding/xml"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
	"golang.org/x/net/html"
)

const (
	hiddenDepth    = 256
	hiddenTokens   = 250000
	hiddenRunBytes = 64 << 10
)

var hiddenInstruction = regexp.MustCompile(agentInstructionPattern)
var cssNumber = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?%?$`)

type paintKind byte

const (
	paintUnknown paintKind = iota
	paintOpaque
	paintTransparent
)

type opacityState byte

const (
	opacityUnknown opacityState = iota
	opacityPositive
	opacityZero
)

type paint struct {
	kind paintKind
	rgb  [3]int
}
type hiddenState struct {
	tag                             string
	hard                            string
	visibility                      bool
	color, fill, stroke, background paint
	fillOpacity, strokeOpacity      opacityState
	ignored, svgText, inSVG         bool
}
type hiddenRun struct {
	text       strings.Builder
	start, end int
	reason     string
}
type hiddenParser struct {
	path    string
	svg     bool
	stack   []hiddenState
	run     hiddenRun
	add     func(model.Finding)
	scanner *Scanner
	tokens  int
	status  string
}

func (s *Scanner) scanHiddenInstructions(path string, data []byte, add func(model.Finding), coverage *model.Coverage) {
	ext := strings.ToLower(filepath.Ext(innerPath(path)))
	if ext != ".html" && ext != ".htm" && ext != ".svg" {
		return
	}
	p := hiddenParser{path: path, svg: ext == ".svg", add: add, scanner: s}
	p.stack = []hiddenState{{stroke: paint{kind: paintTransparent}, fillOpacity: opacityPositive, strokeOpacity: opacityPositive}}
	if p.svg {
		p.parseXML(data)
	} else {
		p.parseHTML(data)
	}
	p.flush()
	if p.status != "" {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, path+" (hidden markup: "+p.status+")")
	}
}
func (p *hiddenParser) flush() {
	if p.run.text.Len() != 0 {
		text := strings.Join(strings.Fields(p.run.text.String()), " ")
		if match := hiddenInstruction.FindStringIndex(text); match != nil {
			f := p.scanner.findingRange("AGENT-003", "prompt-injection", model.SeverityHigh, model.ConfidenceMedium, p.path, p.run.start, p.run.end, "Hidden markup contains a potential agent instruction ("+p.run.reason+")", safeEvidence([]byte(text[match[0]:])), "Inspect the source and treat instructions as untrusted data.")
			contextualizeStructuredFinding(p.path, &f, model.DispositionReview)
			if isContextualContext(classifyContext(innerPath(p.path), nil)) {
				contextualizeStructuredFinding(innerPath(p.path), &f, model.DispositionReview)
			}
			p.add(f)
		}
	}
	p.run = hiddenRun{}
}
func (p *hiddenParser) step() bool {
	p.tokens++
	if p.tokens > hiddenTokens {
		p.status = "token limit"
		return false
	}
	return true
}
func (p *hiddenParser) start(tag string, attrs map[string]string, self bool) {
	if len(p.stack) >= hiddenDepth+1 {
		p.status = "depth limit"
		return
	}
	parent := p.stack[len(p.stack)-1]
	st := parent
	st.tag = tag
	st.inSVG = parent.inSVG || p.svg || tag == "svg"
	if blockTag(tag) {
		p.flush()
	}
	st.ignored = parent.ignored || tag == "script" || tag == "style" || tag == "template" || tag == "noscript"
	st.svgText = parent.svgText || tag == "text"
	props := map[string]decl{}
	if st.inSVG {
		for _, k := range []string{"display", "visibility", "opacity", "fill", "fill-opacity", "stroke", "stroke-opacity", "color"} {
			if v, ok := attrs[k]; ok {
				v = strings.ToLower(strings.TrimSpace(v))
				if validVisibilityProperty(k, v) {
					props[k] = decl{value: v}
				}
			}
		}
	}
	for k, v := range parseStyle(attrs["style"]) {
		props[k] = v
	}
	if !st.inSVG {
		if _, ok := attrs["hidden"]; ok && st.hard == "" && (props["display"].value == "" || displayValue(props["display"].value) == displayNone) {
			st.hard = "hidden attribute"
		}
	}
	if v := props["display"].value; v == "none" && st.hard == "" {
		st.hard = "display none"
	}
	if parseOpacity(props["opacity"].value) == opacityZero && st.hard == "" {
		st.hard = "zero opacity"
	}
	if v, ok := props["visibility"]; ok {
		switch v.value {
		case "hidden", "collapse":
			st.visibility = true
		case "inherit", "unset":
		case "visible", "initial":
			st.visibility = false
		default:
			st.visibility = false
		}
	}
	if v, ok := props["color"]; ok {
		st.color = parsePaint(v.value)
		if v.value == "none" {
			st.color = paint{}
		}
	}
	if v, ok := props["fill"]; ok {
		st.fill = parsePaint(v.value)
	}
	if v, ok := props["stroke"]; ok {
		st.stroke = parsePaint(v.value)
	}
	if v, ok := props["fill-opacity"]; ok {
		st.fillOpacity = parseOpacity(v.value)
	}
	if v, ok := props["stroke-opacity"]; ok {
		st.strokeOpacity = parseOpacity(v.value)
	}
	if v, ok := props["background-color"]; ok {
		c := parsePaint(v.value)
		if c.kind != paintTransparent {
			st.background = c
		}
	}
	if v, ok := props["background-image"]; ok && v.value != "none" {
		st.background = paint{}
	}
	if st.ignored != parent.ignored {
		p.flush()
	}
	p.stack = append(p.stack, st)
	if self {
		p.end(tag)
	}
}
func (p *hiddenParser) end(tag string) {
	index := -1
	for i := len(p.stack) - 1; i > 0; i-- {
		if p.stack[i].tag == tag {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	if blockTag(tag) || p.stack[index].ignored {
		p.flush()
	}
	p.stack = p.stack[:index]
}

type displayKind byte

const (
	displayInvalid displayKind = iota
	displayNone
	displayVisible
	displayUnknown
)

func uncertainCSS(v string) bool {
	return strings.Contains(v, "var(") || strings.Contains(v, "env(") || v == "revert" || v == "revert-layer"
}

func displayValue(v string) displayKind {
	if uncertainCSS(v) || strings.HasPrefix(v, "-") || v == "inherit" {
		return displayUnknown
	}
	switch v {
	case "none":
		return displayNone
	case "contents", "initial", "unset", "inline-block", "inline-table", "inline-flex", "inline-grid", "table-row-group", "table-header-group", "table-footer-group", "table-row", "table-cell", "table-column-group", "table-column", "table-caption", "ruby-base", "ruby-text", "ruby-base-container", "ruby-text-container":
		return displayVisible
	}
	outer, inner, list := false, "", false
	for _, word := range strings.Fields(v) {
		switch word {
		case "block", "inline", "run-in":
			if outer {
				return displayInvalid
			}
			outer = true
		case "flow", "flow-root", "table", "flex", "grid", "ruby":
			if inner != "" {
				return displayInvalid
			}
			inner = word
		case "list-item":
			if list {
				return displayInvalid
			}
			list = true
		default:
			return displayInvalid
		}
	}
	if !outer && inner == "" && !list || list && inner != "" && inner != "flow" && inner != "flow-root" {
		return displayInvalid
	}
	return displayVisible
}

func validVisibilityProperty(k, v string) bool {
	if k == "display" {
		return displayValue(v) != displayInvalid
	}
	if k != "visibility" || uncertainCSS(v) {
		return true
	}
	switch v {
	case "visible", "hidden", "collapse", "inherit", "initial", "unset":
		return true
	}
	return false
}

func blockTag(tag string) bool {
	switch tag {
	case "address", "article", "aside", "blockquote", "br", "div", "dl", "dt", "dd", "fieldset", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table", "td", "th", "tr", "ul", "text":
		return true
	}
	return false
}
func (p *hiddenParser) text(text, raw string, start, end int) {
	st := p.stack[len(p.stack)-1]
	if st.ignored || (st.inSVG && !st.svgText) {
		p.flush()
		return
	}
	reason := st.hard
	if reason == "" && st.visibility {
		reason = "visibility hidden"
	}
	if reason == "" {
		if st.inSVG {
			fillHidden := st.fill.kind == paintTransparent || st.fillOpacity == opacityZero || samePaint(st.fill, st.background)
			strokeHidden := st.stroke.kind == paintTransparent || st.strokeOpacity == opacityZero || samePaint(st.stroke, st.background)
			if fillHidden && strokeHidden {
				if samePaint(st.fill, st.background) {
					reason = "matching text and background colors"
				} else {
					reason = "transparent text paint"
				}
			}
		} else if st.color.kind == paintTransparent {
			reason = "transparent text paint"
		} else if samePaint(st.color, st.background) {
			reason = "matching text and background colors"
		}
	}
	if reason == "" {
		if p.run.reason == "" || strings.TrimSpace(text) != "" {
			p.flush()
			return
		}
		reason = p.run.reason
	}
	if p.run.reason != "" && p.run.reason != reason {
		p.run.reason = "multiple hiding mechanisms"
	}
	if p.run.text.Len()+len(text) > hiddenRunBytes {
		p.status = "hidden text run limit"
		return
	}
	if p.run.reason == "" {
		trimmed := strings.TrimLeft(raw, " \t\r\n\f")
		if strings.TrimSpace(text) == "" {
			return
		}
		start += strings.Count(raw[:len(raw)-len(trimmed)], "\n")
		p.run.reason = reason
		p.run.start = start
	}
	trimmedEnd := strings.TrimRight(raw, " \t\r\n\f")
	if trimmedEnd != "" {
		end -= strings.Count(raw[len(trimmedEnd):], "\n")
		if end < start {
			end = start
		}
		p.run.end = end
	}
	p.run.text.WriteString(text)
}

type decl struct {
	value     string
	important bool
}

func parseStyle(style string) map[string]decl {
	result := map[string]decl{}
	set := func(k, v string, important bool) {
		if old, ok := result[k]; !ok || important || !old.important {
			result[k] = decl{v, important}
		}
	}
	var part strings.Builder
	var delimiters []byte
	var quote byte
	escaped := false
	consume := func() {
		k, v, ok := strings.Cut(part.String(), ":")
		part.Reset()
		if !ok {
			return
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.ToLower(strings.TrimSpace(v))
		important := false
		if i := strings.LastIndexByte(v, '!'); i >= 0 && strings.TrimSpace(v[i+1:]) == "important" {
			important = true
			v = strings.TrimSpace(v[:i])
		}
		if !validVisibilityProperty(k, v) {
			return
		}
		if k == "background" {
			if parsePaint(v).kind != paintUnknown {
				set("background-color", v, important)
				set("background-image", "none", important)
			} else {
				set("background-color", "unknown", important)
				set("background-image", "unknown", important)
			}
		} else {
			set(k, v, important)
		}
	}
	for i := 0; i < len(style); i++ {
		c := style[i]
		if escaped {
			part.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			part.WriteByte(c)
			escaped = true
			continue
		}
		if quote != 0 {
			part.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '/' && i+1 < len(style) && style[i+1] == '*' {
			part.WriteByte(' ')
			i += 2
			for i < len(style) && !(style[i] == '*' && i+1 < len(style) && style[i+1] == '/') {
				i++
			}
			if i < len(style) {
				i++
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(', '[', '{':
			delimiters = append(delimiters, c)
		case ')', ']', '}':
			if len(delimiters) > 0 && (c == ')' && delimiters[len(delimiters)-1] == '(' || c == ']' && delimiters[len(delimiters)-1] == '[' || c == '}' && delimiters[len(delimiters)-1] == '{') {
				delimiters = delimiters[:len(delimiters)-1]
			}
		case ';':
			if len(delimiters) == 0 {
				consume()
				continue
			}
		}
		part.WriteByte(c)
	}
	consume()
	return result
}

func parseOpacity(v string) opacityState {
	v = strings.TrimSpace(v)
	if !cssNumber.MatchString(v) {
		return opacityUnknown
	}
	f, err := strconv.ParseFloat(strings.TrimSuffix(v, "%"), 64)
	if err != nil {
		return opacityUnknown
	}
	if f <= 0 {
		return opacityZero
	}
	return opacityPositive
}
func samePaint(a, b paint) bool {
	if a.kind != paintOpaque || b.kind != paintOpaque {
		return false
	}
	for i := 0; i < 3; i++ {
		d := a.rgb[i] - b.rgb[i]
		if d < -1 || d > 1 {
			return false
		}
	}
	return true
}
func parsePaint(v string) paint {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "transparent" || v == "none" {
		return paint{kind: paintTransparent}
	}
	names := map[string]string{"black": "000000", "white": "ffffff", "red": "ff0000", "green": "008000", "blue": "0000ff", "yellow": "ffff00", "gray": "808080", "grey": "808080", "silver": "c0c0c0", "maroon": "800000", "purple": "800080", "fuchsia": "ff00ff", "lime": "00ff00", "olive": "808000", "navy": "000080", "teal": "008080", "aqua": "00ffff"}
	if x, ok := names[v]; ok {
		v = "#" + x
	}
	if strings.HasPrefix(v, "#") {
		h := v[1:]
		if len(h) == 3 {
			h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
		}
		if len(h) == 6 {
			n, e := strconv.ParseUint(h, 16, 32)
			if e == nil {
				return paint{paintOpaque, [3]int{int(n >> 16), int(n >> 8 & 255), int(n & 255)}}
			}
		}
		return paint{}
	}
	if strings.HasPrefix(v, "rgb(") && strings.HasSuffix(v, ")") {
		parts := strings.Split(v[4:len(v)-1], ",")
		if len(parts) == 3 {
			var rgb [3]int
			for i, x := range parts {
				n, e := strconv.Atoi(strings.TrimSpace(x))
				if e != nil || n < 0 || n > 255 {
					return paint{}
				}
				rgb[i] = n
			}
			return paint{paintOpaque, rgb}
		}
	}
	return paint{}
}
func (p *hiddenParser) parseHTML(data []byte) {
	z := html.NewTokenizer(bytes.NewReader(data))
	z.SetMaxBuf(1 << 20)
	line := 1
	for p.step() {
		typ := z.Next()
		raw := z.Raw()
		rawText := string(raw)
		start := line
		line += bytes.Count(raw, []byte{'\n'})
		end := line

		if end < start {
			end = start
		}
		switch typ {
		case html.ErrorToken:
			if z.Err() != io.EOF {
				p.status = "tokenizer limit or error"
			}
			return
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			attrs := map[string]string{}
			for _, a := range t.Attr {
				if _, ok := attrs[a.Key]; !ok {
					attrs[a.Key] = a.Val
				}
			}
			p.start(t.Data, attrs, htmlVoid(t.Data) || (typ == html.SelfClosingTagToken && (t.Data == "svg" || p.stack[len(p.stack)-1].inSVG)))
		case html.EndTagToken:
			p.end(z.Token().Data)
		case html.TextToken:
			p.text(string(z.Text()), rawText, start, end)
		}
		if p.status != "" {
			return
		}
	}
}
func htmlVoid(tag string) bool {
	switch tag {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	}
	return false
}
func (p *hiddenParser) parseXML(data []byte) {
	d := xml.NewDecoder(bytes.NewReader(data))
	line := 1
	offset := int64(0)
	root := false
	closed := false
	for p.step() {
		token, err := d.Token()
		next := d.InputOffset()
		start := line
		if next >= offset && next <= int64(len(data)) {
			line += bytes.Count(data[offset:next], []byte{'\n'})
		}
		end := line

		if end < start {
			end = start
		}
		raw := string(data[offset:next])
		offset = next
		if err == io.EOF {
			if !root || len(p.stack) != 1 {
				p.status = "malformed SVG"
			}
			return
		}
		if err != nil {
			p.status = "malformed SVG"
			return
		}
		switch t := token.(type) {
		case xml.StartElement:
			tag := t.Name.Local
			if closed {
				p.status = "malformed SVG"
				return
			}
			if !root {
				if tag != "svg" {
					p.status = "malformed SVG root"
					return
				}
				root = true
			}
			attrs := map[string]string{}
			for _, a := range t.Attr {
				if a.Name.Space == "" {
					attrs[a.Name.Local] = a.Value
				}
			}
			p.start(tag, attrs, false)
		case xml.EndElement:
			p.end(t.Name.Local)
			if len(p.stack) == 1 {
				closed = true
			}
		case xml.CharData:
			p.text(string(t), raw, start, end)
		}
		if p.status != "" {
			return
		}
	}
}
