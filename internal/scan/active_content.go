package scan

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"os"
	pathpkg "path"
	"regexp"
	"sort"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

var (
	ddeInstruction       = regexp.MustCompile(`(?i)\bDDE(?:AUTO)?\b`)
	downloadCommand      = regexp.MustCompile(`(?i)\b(?:curl|wget|invoke-webrequest|start-bitstransfer)\b`)
	pdfJavaScriptSubtype = regexp.MustCompile(`(?is)/S\s*/JavaScript\b`)
	pdfJavaScriptPayload = regexp.MustCompile(`(?is)/JS\b`)
	pdfLaunchAction      = regexp.MustCompile(`(?is)/S\s*/Launch\b`)
	pdfAutomaticTrigger  = regexp.MustCompile(`(?is)/(?:OpenAction|AA)\b`)
	pdfActiveAction      = regexp.MustCompile(`(?is)/S\s*/(?:JavaScript|Launch|URI|SubmitForm|ImportData)\b`)
	pdfEmbeddedFile      = regexp.MustCompile(`(?is)/Type\s*/EmbeddedFile\b`)
	pdfRichMedia         = regexp.MustCompile(`(?is)/Subtype\s*/RichMedia\b|/RichMediaContent\b`)
)

func (s *Scanner) scanActiveContent(path string, data []byte, add func(model.Finding)) {
	s.scanPDF(path, data, add)
	s.scanOfficePackageEntry(path, data, add)
	s.scanVSIXEntry(path, data, add)
}

func contextualizeStructuredFinding(path string, finding *model.Finding, disposition model.Disposition) {
	finding.Context = classifyContext(path, nil)
	finding.Severity, finding.Confidence = contextualize(Rule{}, finding.Context, finding.Severity, finding.Confidence)
	finding.Disposition = disposition
	if isContextualContext(finding.Context) {
		finding.Disposition = model.DispositionInformational
	}
}

func (s *Scanner) scanStagedExecution(path string, data []byte, mode os.FileMode, add func(model.Finding)) {
	switch strings.ToLower(filepathExt(path)) {
	case ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd":
	default:
		if mode&0o111 == 0 && !bytes.HasPrefix(data, []byte("#!")) {
			return
		}
	}
	lines := splitLines(data)
	codeLines := make([]string, len(lines))
	inPowerShellBlockComment := false
	for index, line := range lines {
		codeLines[index] = stripScriptComment(path, string(line), &inPowerShellBlockComment)
	}
	for downloadLine, line := range codeLines {
		destination := inferDownloadDestination(line)
		if destination == "" {
			continue
		}
		end := downloadLine + 41
		if end > len(lines) {
			end = len(lines)
		}
		for executionLine := downloadLine; executionLine < end; executionLine++ {
			if !executesDownloadedPath(codeLines[executionLine], destination) {
				continue
			}
			finding := s.findingRange("CHAIN-004", "staged-download-execute", model.SeverityCritical, model.ConfidenceHigh, path,
				downloadLine+1, executionLine+1, "Downloaded file is executed later in the same script", destination,
				"Do not run until the downloaded content, destination, and execution path are verified.")
			contextualizeStructuredFinding(path, &finding, model.DispositionBlock)
			add(finding)
			break
		}
	}
}

func stripScriptComment(path, line string, inPowerShellBlock *bool) string {
	extension := strings.ToLower(filepathExt(path))
	trimmed := strings.TrimSpace(line)
	if extension == ".bat" || extension == ".cmd" {
		lower := strings.ToLower(trimmed)
		if lower == "rem" || strings.HasPrefix(lower, "rem ") || strings.HasPrefix(trimmed, "::") {
			return ""
		}
		return line
	}
	if extension == ".ps1" {
		if *inPowerShellBlock {
			if end := strings.Index(line, "#>"); end >= 0 {
				*inPowerShellBlock = false
				line = line[end+2:]
			} else {
				return ""
			}
		}
		if start := strings.Index(line, "<#"); start >= 0 {
			if end := strings.Index(line[start+2:], "#>"); end >= 0 {
				line = line[:start] + line[start+2+end+2:]
			} else {
				*inPowerShellBlock = true
				line = line[:start]
			}
		}
	}
	quote := byte(0)
	for index := 0; index < len(line); index++ {
		current := line[index]
		if quote != 0 {
			if current == '\\' && index+1 < len(line) {
				index++
				continue
			}
			if current == quote {
				quote = 0
			}
			continue
		}
		if current == '\'' || current == '"' {
			quote = current
			continue
		}
		if current == '#' && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
			return line[:index]
		}
	}
	return line
}

func inferDownloadDestination(line string) string {
	segment := downloadCommandSegment(line)
	if segment == "" {
		return ""
	}
	words := unwrapCommandWords(parseCommandWords(segment))
	if len(words) == 0 {
		return ""
	}
	command := strings.ToLower(strings.TrimSuffix(pathpkg.Base(words[0]), ".exe"))
	for index := 1; index < len(words); index++ {
		word := words[index]
		lower := strings.ToLower(word)
		shortOutput := command == "curl" && word == "-o" || command == "wget" && word == "-O"
		if word == ">" || shortOutput || ((command == "curl" || command == "wget") && (lower == "--output" || lower == "--output-document")) ||
			((command == "invoke-webrequest" || command == "start-bitstransfer") && (lower == "-outfile" || lower == "-destination")) {
			if index+1 < len(words) {
				return words[index+1]
			}
			return ""
		}
		for _, prefix := range []string{"--output=", "--output-document=", "-outfile:", "-destination:"} {
			if strings.HasPrefix(lower, prefix) && len(word) > len(prefix) {
				return word[len(prefix):]
			}
		}
		if command == "curl" && strings.HasPrefix(word, "-o") && len(word) > 2 {
			return strings.TrimPrefix(word[2:], "=")
		}
		if command == "wget" && strings.HasPrefix(word, "-O") && len(word) > 2 {
			return strings.TrimPrefix(word[2:], "=")
		}
	}
	remoteName := command == "wget"
	if command == "curl" {
		for _, word := range words[1:] {
			if word == "-O" || strings.EqualFold(word, "--remote-name") {
				remoteName = true
				break
			}
		}
	}
	if !remoteName {
		return ""
	}
	rawURL := ""
	for _, word := range words[1:] {
		if strings.HasPrefix(strings.ToLower(word), "http://") || strings.HasPrefix(strings.ToLower(word), "https://") {
			rawURL = word
			break
		}
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	name := pathpkg.Base(parsed.Path)
	if name == "." || name == "/" {
		return ""
	}
	return name
}

func downloadCommandSegment(line string) string {
	for _, segment := range splitCommandSegments(line) {
		candidate := strings.TrimSpace(segment)
		fields := unwrapCommandWords(parseCommandWords(candidate))
		if len(fields) == 0 {
			continue
		}
		executable := strings.ToLower(pathpkg.Base(fields[0]))
		executable = strings.TrimSuffix(executable, ".exe")
		switch executable {
		case "curl", "wget", "invoke-webrequest", "start-bitstransfer":
			return candidate
		}
	}
	return ""
}

func executesDownloadedPath(line, destination string) bool {
	for _, segment := range splitCommandSegments(line) {
		segment = strings.TrimSpace(segment)
		lower := strings.ToLower(segment)
		if segment == "" || strings.HasPrefix(lower, "chmod ") || strings.HasPrefix(lower, "icacls ") {
			continue
		}
		fields := unwrapExecutionWords(parseCommandWords(segment))
		if len(fields) > 0 && strings.EqualFold(normalizeCommandPath(fields[0]), normalizeCommandPath(destination)) {
			return true
		}
	}
	return false
}

func splitCommandSegments(line string) []string {
	segments := make([]string, 0, 2)
	start := 0
	quote := byte(0)
	for index := 0; index < len(line); index++ {
		current := line[index]
		if quote != 0 {
			if current == '\\' && quote == '"' && index+1 < len(line) {
				index++
			} else if current == quote {
				quote = 0
			}
			continue
		}
		if current == '\'' || current == '"' {
			quote = current
			continue
		}
		width := 0
		if current == ';' {
			width = 1
		} else if index+1 < len(line) && ((current == '&' && line[index+1] == '&') || (current == '|' && line[index+1] == '|')) {
			width = 2
		}
		if width > 0 {
			segments = append(segments, line[start:index])
			index += width - 1
			start = index + 1
		}
	}
	return append(segments, line[start:])
}

func parseCommandWords(command string) []string {
	words := make([]string, 0, 8)
	var current strings.Builder
	quote := byte(0)
	flush := func() {
		if current.Len() > 0 {
			words = append(words, current.String())
			current.Reset()
		}
	}
	for index := 0; index < len(command); index++ {
		character := command[index]
		if quote != 0 {
			if character == '\\' && quote == '"' && index+1 < len(command) {
				index++
				current.WriteByte(command[index])
			} else if character == quote {
				quote = 0
			} else {
				current.WriteByte(character)
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
		case ' ', '\t', '\r', '\n':
			flush()
		default:
			current.WriteByte(character)
		}
	}
	flush()
	return words
}

func unwrapCommandWords(words []string) []string {
	for len(words) > 0 {
		prefix := strings.ToLower(words[0])
		if prefix != "sudo" && prefix != "command" && prefix != "&" {
			break
		}
		words = words[1:]
	}
	return words
}

func unwrapExecutionWords(words []string) []string {
	for len(words) > 0 {
		prefix := strings.ToLower(strings.TrimSuffix(pathpkg.Base(words[0]), ".exe"))
		switch prefix {
		case "sudo", "&", "bash", "sh", "zsh", "python", "python3", "node", "pwsh", "powershell":
			words = words[1:]
		case "start-process":
			words = words[1:]
			if len(words) > 0 && strings.EqualFold(words[0], "-FilePath") {
				words = words[1:]
			}
		default:
			return words
		}
	}
	return words
}

func normalizeCommandPath(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	return strings.TrimPrefix(pathpkg.Clean(value), "./")
}

func (s *Scanner) scanPDF(path string, data []byte, add func(model.Finding)) {
	if !strings.EqualFold(filepathExt(path), ".pdf") || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("%PDF-")) {
		return
	}
	sanitized := decodePDFNames(sanitizePDF(data))
	var labels []string
	for _, item := range []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{pdfLaunchAction, "launch action"},
		{pdfEmbeddedFile, "embedded file"},
		{pdfRichMedia, "rich-media action"},
	} {
		if item.pattern.Match(sanitized) {
			labels = append(labels, item.label)
		}
	}
	if pdfAutomaticTrigger.Match(sanitized) && pdfActiveAction.Match(sanitized) {
		labels = append(labels, "automatically triggered active action")
	}
	if pdfDictionaryContains(sanitized, pdfJavaScriptSubtype, pdfJavaScriptPayload) {
		labels = append(labels, "JavaScript action")
	}
	if len(labels) == 0 {
		return
	}
	sort.Strings(labels)
	finding := s.finding("DOC-001", "document-active-content", model.SeverityHigh, model.ConfidenceMedium, path, 0,
		"PDF declares active or embedded content", strings.Join(labels, ", "),
		"Do not open the PDF in a full-featured viewer until its actions and embedded files have been reviewed or removed.")
	contextualizeStructuredFinding(path, &finding, model.DispositionReview)
	add(finding)
}

func pdfDictionaryContains(data []byte, patterns ...*regexp.Regexp) bool {
	for offset := 0; offset < len(data); {
		startRelative := bytes.Index(data[offset:], []byte("<<"))
		if startRelative < 0 {
			return false
		}
		start := offset + startRelative + 2
		endRelative := bytes.Index(data[start:], []byte(">>"))
		if endRelative < 0 {
			return false
		}
		dictionary := data[start : start+endRelative]
		matched := true
		for _, pattern := range patterns {
			if !pattern.Match(dictionary) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
		offset = start + endRelative + 2
	}
	return false
}

func sanitizePDF(data []byte) []byte {
	result := append([]byte(nil), data...)
	for index := 0; index < len(result); {
		switch result[index] {
		case '%':
			for index < len(result) && result[index] != '\n' && result[index] != '\r' {
				result[index] = ' '
				index++
			}
		case '(':
			depth := 1
			result[index] = ' '
			index++
			for index < len(result) && depth > 0 {
				if result[index] == '\\' {
					result[index] = ' '
					index++
					if index < len(result) {
						result[index] = ' '
						index++
					}
					continue
				}
				if result[index] == '(' {
					depth++
				} else if result[index] == ')' {
					depth--
				}
				result[index] = ' '
				index++
			}
		default:
			if pdfStreamTokenAt(result, index) {
				endRelative := bytes.Index(result[index:], []byte("endstream"))
				end := len(result)
				if endRelative >= 0 {
					end = index + endRelative + len("endstream")
				}
				for clear := index; clear < end; clear++ {
					result[clear] = ' '
				}
				index = end
				continue
			}
			index++
		}
	}
	return result
}

func pdfStreamTokenAt(data []byte, index int) bool {
	if index > 0 && !pdfWhitespace(data[index-1]) {
		return false
	}
	return bytes.HasPrefix(data[index:], []byte("stream\n")) || bytes.HasPrefix(data[index:], []byte("stream\r"))
}

func pdfWhitespace(value byte) bool {
	switch value {
	case 0, '\t', '\n', '\f', '\r', ' ':
		return true
	default:
		return false
	}
}

func decodePDFNames(data []byte) []byte {
	decoded := make([]byte, 0, len(data))
	for index := 0; index < len(data); {
		if data[index] != '/' {
			decoded = append(decoded, data[index])
			index++
			continue
		}
		decoded = append(decoded, '/')
		index++
		for index < len(data) && !pdfNameDelimiter(data[index]) {
			if data[index] == '#' && index+2 < len(data) {
				high, highOK := hexNibble(data[index+1])
				low, lowOK := hexNibble(data[index+2])
				if highOK && lowOK {
					decoded = append(decoded, high<<4|low)
					index += 3
					continue
				}
			}
			decoded = append(decoded, data[index])
			index++
		}
	}
	return decoded
}

func pdfNameDelimiter(value byte) bool {
	switch value {
	case 0, '\t', '\n', '\f', '\r', ' ', '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	default:
		return false
	}
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func (s *Scanner) scanOfficePackageEntry(path string, data []byte, add func(model.Finding)) {
	outer, inner, ok := archiveParts(path)
	if !ok || !isOfficePackage(outer) {
		return
	}
	lowerInner := strings.ToLower(inner)
	vbaTarget := officeVBATarget(data)
	if strings.HasSuffix(lowerInner, "/vbaproject.bin") || lowerInner == "vbaproject.bin" || vbaTarget != "" {
		evidence := "vbaProject.bin"
		if vbaTarget != "" {
			evidence = vbaTarget
		}
		finding := s.finding("DOC-002", "office-macro", model.SeverityHigh, model.ConfidenceHigh, path, 0,
			"Office package contains a VBA macro project", evidence, "Inspect or remove the macro project before opening the document.")
		contextualizeStructuredFinding(path, &finding, model.DispositionReview)
		add(finding)
	}
	if strings.HasSuffix(lowerInner, ".rels") {
		relationship := externalOfficeRelationship(data)
		if relationship != "" {
			finding := s.finding("DOC-003", "office-external-relationship", model.SeverityMedium, model.ConfidenceHigh, path, 0,
				"Office package references external content", safeEvidence([]byte(relationship)),
				"Review the relationship target and remove external templates, objects, or links that are not required.")
			contextualizeStructuredFinding(path, &finding, model.DispositionReview)
			add(finding)
		}
	}
	if strings.HasSuffix(lowerInner, ".xml") {
		if instruction := officeDDEInstruction(data); instruction != "" {
			finding := s.finding("DOC-004", "office-dynamic-data-exchange", model.SeverityHigh, model.ConfidenceMedium, path, 0,
				"Office document contains a Dynamic Data Exchange field", safeEvidence([]byte(instruction)),
				"Remove the DDE field or inspect its command and data source before opening the document.")
			contextualizeStructuredFinding(path, &finding, model.DispositionReview)
			add(finding)
		}
	}
}

func externalOfficeRelationship(data []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		start, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(start.Name.Local, "Relationship") {
			continue
		}
		for _, attribute := range start.Attr {
			if strings.EqualFold(attribute.Name.Local, "TargetMode") && strings.EqualFold(strings.TrimSpace(attribute.Value), "External") {
				return "Relationship TargetMode=External"
			}
		}
	}
}

func officeVBATarget(data []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		var contentType, partName, relationshipType, target string
		for _, attribute := range start.Attr {
			switch strings.ToLower(attribute.Name.Local) {
			case "contenttype":
				contentType = attribute.Value
			case "partname":
				partName = attribute.Value
			case "type":
				relationshipType = attribute.Value
			case "target":
				target = attribute.Value
			}
		}
		if strings.Contains(strings.ToLower(contentType), "vbaproject") && partName != "" {
			return partName
		}
		if strings.Contains(strings.ToLower(relationshipType), "/vbaproject") && target != "" {
			return target
		}
	}
}

func officeDDEInstruction(data []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var complex strings.Builder
	check := func() string {
		instruction := complex.String()
		if ddeInstruction.MatchString(instruction) {
			return instruction
		}
		complex.Reset()
		return ""
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch strings.ToLower(start.Name.Local) {
		case "fldchar":
			fieldType := ""
			for _, attribute := range start.Attr {
				if strings.EqualFold(attribute.Name.Local, "fldCharType") {
					fieldType = strings.ToLower(attribute.Value)
					break
				}
			}
			switch fieldType {
			case "begin":
				if instruction := check(); instruction != "" {
					return instruction
				}
			case "separate", "end":
				if instruction := check(); instruction != "" {
					return instruction
				}
			}
		case "instrtext":
			var text string
			if decoder.DecodeElement(&text, &start) == nil {
				complex.WriteString(text)
			}
		case "fldsimple":
			for _, attribute := range start.Attr {
				if strings.EqualFold(attribute.Name.Local, "instr") && ddeInstruction.MatchString(attribute.Value) {
					return attribute.Value
				}
			}
		}
	}
	if instruction := check(); instruction != "" {
		return instruction
	}
	return ""
}

func (s *Scanner) scanVSIXEntry(path string, data []byte, add func(model.Finding)) {
	outer, inner, ok := archiveParts(path)
	if !ok || !strings.EqualFold(filepathExt(outer), ".vsix") {
		return
	}
	lowerInner := strings.ToLower(inner)
	if lowerInner == "extension/package.json" {
		if capability := vsixCapability(data); capability != "" {
			finding := s.finding("IDE-008", "editor-extension-capability", model.SeverityMedium, model.ConfidenceHigh, path, 0,
				"VSIX extension declares activation or execution capabilities", capability,
				"Review activation events, contributed commands, debuggers, tasks, terminals, and extension entry points before installation.")
			contextualizeStructuredFinding(path, &finding, model.DispositionReview)
			add(finding)
		}
		if script := vsixInstallLifecycle(data); script != "" {
			finding := s.finding("IDE-009", "editor-extension-install-script", model.SeverityHigh, model.ConfidenceHigh, path, 0,
				"VSIX extension package declares an installation lifecycle script", safeEvidence([]byte(script)),
				"Inspect the lifecycle command and bundled files before installing or packaging the extension.")
			contextualizeStructuredFinding(path, &finding, model.DispositionReview)
			add(finding)
		}
	}
}

func vsixCapability(data []byte) string {
	var manifest map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil {
		return ""
	}
	if value, exists := manifest["activationEvents"]; exists && string(value) != "null" {
		return "activationEvents"
	}
	for _, name := range []string{"main", "browser"} {
		var entryPoint string
		if json.Unmarshal(manifest[name], &entryPoint) == nil && strings.TrimSpace(entryPoint) != "" {
			return name
		}
	}
	var contributes map[string]json.RawMessage
	if json.Unmarshal(manifest["contributes"], &contributes) != nil {
		return ""
	}
	for _, name := range []string{"commands", "debuggers", "taskDefinitions", "terminalProfiles", "customEditors", "authentication", "notebooks", "notebookRenderer", "views"} {
		if value, exists := contributes[name]; exists && string(value) != "null" {
			return "contributes." + name
		}
	}
	return ""
}

func vsixInstallLifecycle(data []byte) string {
	var manifest struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return ""
	}
	for _, name := range []string{"preinstall", "install", "postinstall"} {
		raw, ok := manifest.Scripts[name]
		if !ok {
			continue
		}
		var command string
		if json.Unmarshal(raw, &command) == nil && strings.TrimSpace(command) != "" {
			return name + ": " + command
		}
	}
	return ""
}

func archiveParts(path string) (string, string, bool) {
	path = filepathToSlash(path)
	index := strings.LastIndex(path, "!")
	if index < 0 {
		return "", "", false
	}
	return path[:index], path[index+1:], true
}

func isOfficePackage(path string) bool {
	switch strings.ToLower(filepathExt(path)) {
	case ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm":
		return true
	default:
		return false
	}
}

func filepathExt(path string) string {
	path = filepathToSlash(path)
	if index := strings.LastIndex(path, "/"); index >= 0 {
		path = path[index+1:]
	}
	if index := strings.LastIndex(path, "."); index >= 0 {
		return path[index:]
	}
	return ""
}

func filepathToSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}
