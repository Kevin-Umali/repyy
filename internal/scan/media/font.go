package media

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/andybalholm/brotli"
)

const maxExpandedFontSize = 50 << 20

var fontExtensions = map[string]bool{
	".otf": true, ".ttc": true, ".ttf": true, ".woff": true, ".woff2": true,
}

var woff2KnownTags = [...]string{
	"cmap", "head", "hhea", "hmtx", "maxp", "name", "OS/2", "post", "cvt ", "fpgm", "glyf", "loca", "prep", "CFF ", "VORG", "EBDT",
	"EBLC", "gasp", "hdmx", "kern", "LTSH", "PCLT", "VDMX", "vhea", "vmtx", "BASE", "GDEF", "GPOS", "GSUB", "EBSC", "JSTF", "MATH",
	"CBDT", "CBLC", "COLR", "CPAL", "SVG ", "sbix", "acnt", "avar", "bdat", "bloc", "bsln", "cvar", "fdsc", "feat", "fmtx", "fvar",
	"gvar", "hsty", "just", "lcar", "mort", "morx", "opbd", "prop", "trak", "Zapf", "Silf", "Glat", "Gloc", "Feat", "Sill",
}

type fontTable struct {
	tag                          string
	offset, length, storedLength uint64
	body                         []byte
}

type fontAnalysis struct {
	tables []fontTable
	reason string
}

// ScanFont inventories binary font files and reports malformed container
// boundaries or embedded executable payloads without loading or rendering them.
func ScanFont(path string, data []byte, classifyContext func(string) string, isContextual func(string) bool, newFinding FindingFactory, add func(model.Finding)) {
	extension := strings.ToLower(filepath.Ext(innerPath(path)))
	if !fontExtensions[extension] {
		return
	}
	context := classifyContext(path)
	disposition := model.DispositionReview
	if isContextual(context) {
		disposition = model.DispositionInformational
	}
	addFontFinding := func(id, category string, severity model.Severity, confidence model.Confidence, message, evidence, remediation string, forceReview bool) {
		if isContextual(context) {
			if severity.Rank() > model.SeverityMedium.Rank() {
				severity = model.SeverityMedium
			}
			confidence = model.ConfidenceLow
		}
		finding := newFinding(id, category, severity, confidence, path, 0, message, evidence, remediation)
		finding.Context = context
		finding.Disposition = disposition
		if forceReview && !isContextual(context) {
			finding.Disposition = model.DispositionReview
		}
		add(finding)
	}

	addFontFinding("FONT-002", "binary-font", model.SeverityMedium, model.ConfidenceHigh,
		"Binary font file requires provenance review", fmt.Sprintf("%s font; %d bytes", strings.TrimPrefix(extension, "."), len(data)),
		"Verify the font's source, license, hash, and signature before installing or opening it in a font-aware application.", false)

	analysis := analyzeFont(extension, data)
	reason := analysis.reason
	if reason == "" {
		reason = embeddedExecutable(data)
	}
	if reason == "" {
		for _, table := range analysis.tables {
			if table.body != nil {
				if reason = embeddedExecutable(table.body); reason != "" {
					break
				}
			}
		}
	}
	if reason != "" {
		addFontFinding("FONT-003", "font-container-integrity", model.SeverityHigh, model.ConfidenceHigh,
			"Font container is malformed or contains an executable payload", reason,
			"Do not install or preview the font. Obtain a trusted copy and compare its cryptographic hash.", true)
		return
	}

	hasInstructions := false
	for _, table := range analysis.tables {
		switch table.tag {
		case "fpgm", "prep":
			if !hasInstructions {
				addFontFinding("FONT-005", "font-program", model.SeverityLow, model.ConfidenceHigh,
					"Font contains TrueType instructions", fmt.Sprintf("%s table; %d bytes", table.tag, table.length),
					"Treat the instruction stream as untrusted parser input and verify the font's provenance before previewing or installing it.", false)
				hasInstructions = true
			}
		}
	}
	for _, table := range analysis.tables {
		if table.tag != "SVG " {
			continue
		}
		activeReason, integrityReason := inspectOpenTypeSVG(data, table)
		if integrityReason != "" {
			addFontFinding("FONT-003", "font-container-integrity", model.SeverityHigh, model.ConfidenceHigh,
				"Font container is malformed or contains an executable payload", integrityReason,
				"Do not install or preview the font. Obtain a trusted copy and compare its cryptographic hash.", true)
			return
		}
		if activeReason != "" {
			addFontFinding("FONT-004", "font-active-content", model.SeverityMedium, model.ConfidenceMedium,
				"OpenType SVG glyph contains active content", activeReason,
				"Remove scripts, event handlers, and active links from the embedded SVG document, or replace the font with a trusted copy.", true)
		}
	}
}

func analyzeFont(extension string, data []byte) fontAnalysis {
	switch extension {
	case ".ttf", ".otf":
		tables, reason := parseSFNT(data, 0, false)
		return fontAnalysis{tables: tables, reason: reason}
	case ".ttc":
		return analyzeTTC(data)
	case ".woff":
		return analyzeWOFF(data)
	case ".woff2":
		return analyzeWOFF2(data)
	default:
		return fontAnalysis{reason: "unsupported font container"}
	}
}

func parseSFNT(data []byte, directoryOffset uint64, collection bool) ([]fontTable, string) {
	if directoryOffset > uint64(len(data)) || uint64(len(data))-directoryOffset < 12 {
		return nil, "truncated SFNT header"
	}
	header := data[directoryOffset:]
	signature := string(header[:4])
	if !bytes.Equal(header[:4], []byte{0, 1, 0, 0}) && signature != "OTTO" && signature != "true" && signature != "typ1" {
		return nil, "unexpected SFNT signature"
	}
	tableCount := uint64(binary.BigEndian.Uint16(header[4:6]))
	directoryEnd := directoryOffset + 12 + 16*tableCount
	if tableCount == 0 || tableCount > 4096 || directoryEnd > uint64(len(data)) {
		return nil, "invalid SFNT table directory"
	}
	tables := make([]fontTable, 0, tableCount)
	tags := make(map[string]bool, tableCount)
	for index := uint64(0); index < tableCount; index++ {
		entry := directoryOffset + 12 + index*16
		tag := string(data[entry : entry+4])
		if tags[tag] {
			return nil, fmt.Sprintf("duplicate SFNT table tag %q", tag)
		}
		tags[tag] = true
		offset := uint64(binary.BigEndian.Uint32(data[entry+8 : entry+12]))
		length := uint64(binary.BigEndian.Uint32(data[entry+12 : entry+16]))
		if offset%4 != 0 {
			return nil, fmt.Sprintf("SFNT table %q has an unaligned offset", tag)
		}
		if offset > uint64(len(data)) || length > uint64(len(data))-offset {
			return nil, fmt.Sprintf("SFNT table %q extends beyond the file", tag)
		}
		if !collection && length > 0 && offset < directoryEnd {
			return nil, fmt.Sprintf("SFNT table %q overlaps the table directory", tag)
		}
		for _, previous := range tables {
			if length > 0 && previous.length > 0 && offset < previous.offset+previous.length && previous.offset < offset+length {
				return nil, fmt.Sprintf("SFNT tables %q and %q overlap", previous.tag, tag)
			}
		}
		tables = append(tables, fontTable{tag: tag, offset: offset, length: length, storedLength: length})
	}
	for _, table := range tables {
		if reason := validateKnownSFNTTable(data, table); reason != "" {
			return nil, reason
		}
	}
	return tables, ""
}

func validateKnownSFNTTable(data []byte, table fontTable) string {
	if table.offset > uint64(len(data)) || table.length > uint64(len(data))-table.offset {
		return fmt.Sprintf("SFNT table %q has invalid bounds", table.tag)
	}
	return validateKnownSFNTTableBody(table.tag, data[table.offset:table.offset+table.length])
}

func validateKnownSFNTTableBody(tag string, body []byte) string {
	switch tag {
	case "head":
		if len(body) < 54 {
			return "truncated SFNT head table"
		}
		if binary.BigEndian.Uint32(body[12:16]) != 0x5f0f3cf5 {
			return "invalid SFNT head magic number"
		}
		unitsPerEm := binary.BigEndian.Uint16(body[18:20])
		if unitsPerEm < 16 || unitsPerEm > 16384 {
			return "invalid SFNT unitsPerEm value"
		}
		locFormat := int16(binary.BigEndian.Uint16(body[50:52]))
		if locFormat != 0 && locFormat != 1 {
			return "invalid SFNT indexToLocFormat value"
		}
	case "maxp":
		if len(body) < 6 || binary.BigEndian.Uint16(body[4:6]) == 0 {
			return "invalid SFNT maxp table"
		}
	}
	return ""
}

func analyzeTTC(data []byte) fontAnalysis {
	if len(data) < 12 || string(data[:4]) != "ttcf" {
		return fontAnalysis{reason: "invalid TrueType collection header"}
	}
	fontCount := uint64(binary.BigEndian.Uint32(data[8:12]))
	if fontCount == 0 || fontCount > 4096 || 12+4*fontCount > uint64(len(data)) {
		return fontAnalysis{reason: "invalid TrueType collection directory"}
	}
	type fontRange struct{ start, end uint64 }
	protected := []fontRange{{start: 0, end: 12 + 4*fontCount}}
	faces := make([][]fontTable, 0, fontCount)
	totalTables := 0
	for index := uint64(0); index < fontCount; index++ {
		entry := 12 + 4*index
		offset := uint64(binary.BigEndian.Uint32(data[entry : entry+4]))
		tables, reason := parseSFNT(data, offset, true)
		if reason != "" {
			return fontAnalysis{reason: fmt.Sprintf("TrueType collection face %d: %s", index, reason)}
		}
		directoryEnd := offset + 12 + 16*uint64(len(tables))
		protected = append(protected, fontRange{start: offset, end: directoryEnd})
		totalTables += len(tables)
		if totalTables > 65_536 {
			return fontAnalysis{reason: "TrueType collection declares too many aggregate tables"}
		}
		faces = append(faces, tables)
	}
	var all []fontTable
	for faceIndex, tables := range faces {
		for _, table := range tables {
			if table.length > 0 {
				for _, reserved := range protected {
					if table.offset < reserved.end && reserved.start < table.offset+table.length {
						return fontAnalysis{reason: fmt.Sprintf("TrueType collection face %d table %q overlaps a font directory", faceIndex, table.tag)}
					}
				}
			}
			all = append(all, table)
		}
	}
	return fontAnalysis{tables: all}
}

func analyzeWOFF(data []byte) fontAnalysis {
	if len(data) < 44 || string(data[:4]) != "wOFF" {
		return fontAnalysis{reason: "invalid WOFF header"}
	}
	if binary.BigEndian.Uint32(data[8:12]) != uint32(len(data)) {
		return fontAnalysis{reason: "WOFF length does not match the file"}
	}
	tableCount := uint64(binary.BigEndian.Uint16(data[12:14]))
	directoryEnd := uint64(44) + 20*tableCount
	if tableCount == 0 || tableCount > 4096 || directoryEnd > uint64(len(data)) {
		return fontAnalysis{reason: "invalid WOFF table directory"}
	}
	if reason := unreasonableExpansion(uint64(binary.BigEndian.Uint32(data[16:20])), uint64(len(data))); reason != "" {
		return fontAnalysis{reason: reason}
	}
	declaredExpanded := uint64(binary.BigEndian.Uint32(data[16:20]))
	expandedTotal := uint64(12) + 16*tableCount
	tags := map[string]bool{}
	tables := make([]fontTable, 0, tableCount)
	for index := uint64(0); index < tableCount; index++ {
		entry := 44 + 20*index
		tag := string(data[entry : entry+4])
		if tags[tag] {
			return fontAnalysis{reason: fmt.Sprintf("duplicate WOFF table tag %q", tag)}
		}
		tags[tag] = true
		offset := uint64(binary.BigEndian.Uint32(data[entry+4 : entry+8]))
		compressed := uint64(binary.BigEndian.Uint32(data[entry+8 : entry+12]))
		original := uint64(binary.BigEndian.Uint32(data[entry+12 : entry+16]))
		expandedTotal += (original + 3) &^ 3
		if expandedTotal > declaredExpanded || expandedTotal > maxExpandedFontSize {
			return fontAnalysis{reason: "WOFF expanded table sizes exceed the declared limit"}
		}
		if offset%4 != 0 || compressed > original || offset > uint64(len(data)) || compressed > uint64(len(data))-offset || (compressed > 0 && offset < directoryEnd) {
			return fontAnalysis{reason: fmt.Sprintf("WOFF table %q has invalid bounds", tag)}
		}
		for _, previous := range tables {
			if compressed > 0 && previous.storedLength > 0 && offset < previous.offset+previous.storedLength && previous.offset < offset+compressed {
				return fontAnalysis{reason: fmt.Sprintf("WOFF tables %q and %q overlap", previous.tag, tag)}
			}
		}
		table := fontTable{tag: tag, offset: offset, length: original, storedLength: compressed}
		encoded := data[offset : offset+compressed]
		if compressed == original {
			table.body = encoded
		} else {
			reader, err := zlib.NewReader(bytes.NewReader(encoded))
			if err != nil {
				return fontAnalysis{reason: fmt.Sprintf("WOFF table %q has invalid compression", tag)}
			}
			expanded, readErr := io.ReadAll(io.LimitReader(reader, int64(original)+1))
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil || uint64(len(expanded)) != original {
				return fontAnalysis{reason: fmt.Sprintf("WOFF table %q expansion length is invalid", tag)}
			}
			table.body = expanded
		}
		if reason := validateKnownSFNTTableBody(tag, table.body); reason != "" {
			return fontAnalysis{reason: reason}
		}
		tables = append(tables, table)
	}
	if expandedTotal != declaredExpanded {
		return fontAnalysis{reason: "WOFF expanded size does not match its tables"}
	}
	return fontAnalysis{tables: tables}
}

func analyzeWOFF2(data []byte) fontAnalysis {
	if len(data) < 48 || string(data[:4]) != "wOF2" {
		return fontAnalysis{reason: "invalid WOFF2 header"}
	}
	tableCount := uint64(binary.BigEndian.Uint16(data[12:14]))
	if binary.BigEndian.Uint32(data[8:12]) != uint32(len(data)) || tableCount == 0 || tableCount > 4096 {
		return fontAnalysis{reason: "invalid WOFF2 length or table count"}
	}
	position := 48
	tables := make([]fontTable, 0, tableCount)
	seenTags := make(map[string]struct{}, tableCount)
	transformedTables := make([]bool, 0, tableCount)
	isCollection := binary.BigEndian.Uint32(data[4:8]) == 0x74746366
	decompressedSize := uint64(0)
	minimumSfntSize := uint64(12 + 16*tableCount)
	for index := uint64(0); index < tableCount; index++ {
		if position >= len(data) {
			return fontAnalysis{reason: "truncated WOFF2 table directory"}
		}
		flags := data[position]
		position++
		tagIndex := flags & 0x3f
		transformVersion := flags >> 6
		tag := ""
		if int(tagIndex) < len(woff2KnownTags) {
			tag = woff2KnownTags[tagIndex]
		}
		if tagIndex == 0x3f {
			if position+4 > len(data) {
				return fontAnalysis{reason: "truncated WOFF2 custom table tag"}
			}
			tag = string(data[position : position+4])
			position += 4
		}
		if _, exists := seenTags[tag]; exists && !isCollection {
			return fontAnalysis{reason: fmt.Sprintf("duplicate WOFF2 table %q", tag)}
		}
		seenTags[tag] = struct{}{}
		if (tag == "glyf" || tag == "loca") && (transformVersion == 1 || transformVersion == 2) {
			return fontAnalysis{reason: "reserved WOFF2 glyf/loca transform version"}
		}
		if tag == "hmtx" && transformVersion != 0 && transformVersion != 1 {
			return fontAnalysis{reason: "unsupported WOFF2 hmtx transform version"}
		}
		if tag != "glyf" && tag != "loca" && tag != "hmtx" && transformVersion != 0 {
			return fontAnalysis{reason: "unsupported WOFF2 table transform version"}
		}
		originalLength, next, ok := readUIntBase128(data, position)
		if !ok {
			return fontAnalysis{reason: "invalid WOFF2 table length"}
		}
		position = next
		storedLength := originalLength
		transformed := (tag == "glyf" || tag == "loca") && transformVersion == 0
		if tag == "hmtx" {
			transformed = transformVersion == 1
		}
		if transformed {
			storedLength, next, ok = readUIntBase128(data, position)
			if !ok {
				return fontAnalysis{reason: "invalid WOFF2 transformed table length"}
			}
			position = next
		}
		if tag == "loca" && transformed && storedLength != 0 {
			return fontAnalysis{reason: "transformed WOFF2 loca table has a nonzero payload"}
		}
		decompressedSize += uint64(storedLength)
		if decompressedSize > maxExpandedFontSize {
			return fontAnalysis{reason: "WOFF2 expanded tables exceed the inspection limit"}
		}
		if !transformed {
			minimumSfntSize += (uint64(originalLength) + 3) &^ 3
		}
		tables = append(tables, fontTable{tag: tag, length: uint64(originalLength), storedLength: uint64(storedLength)})
		transformedTables = append(transformedTables, transformed)
	}
	if reason := validateWOFF2Pairs(tables, transformedTables, isCollection); reason != "" {
		return fontAnalysis{reason: reason}
	}
	if isCollection {
		var reason string
		var collectionOverhead uint64
		position, collectionOverhead, reason = parseWOFF2CollectionDirectory(data, position, tables, transformedTables)
		if reason != "" {
			return fontAnalysis{reason: reason}
		}
		minimumSfntSize = collectionOverhead
		for index, table := range tables {
			if !transformedTables[index] {
				minimumSfntSize += (table.length + 3) &^ 3
			}
		}
	}
	if uint64(binary.BigEndian.Uint32(data[16:20])) < minimumSfntSize {
		return fontAnalysis{reason: "WOFF2 totalSfntSize is smaller than the decoded table lower bound"}
	}
	compressedSize := uint64(binary.BigEndian.Uint32(data[20:24]))
	if compressedSize == 0 || uint64(position) > uint64(len(data)) || compressedSize > uint64(len(data))-uint64(position) {
		return fontAnalysis{reason: "WOFF2 compressed stream extends beyond the file"}
	}
	compressedEnd := uint64(position) + compressedSize
	for _, block := range []struct {
		offset uint64
		length uint64
		name   string
	}{
		{uint64(binary.BigEndian.Uint32(data[28:32])), uint64(binary.BigEndian.Uint32(data[32:36])), "metadata"},
		{uint64(binary.BigEndian.Uint32(data[40:44])), uint64(binary.BigEndian.Uint32(data[44:48])), "private-data"},
	} {
		if block.length == 0 {
			if block.offset != 0 {
				return fontAnalysis{reason: fmt.Sprintf("WOFF2 %s offset is present without a length", block.name)}
			}
			continue
		}
		if block.offset < compressedEnd || block.offset > uint64(len(data)) || block.length > uint64(len(data))-block.offset {
			return fontAnalysis{reason: fmt.Sprintf("WOFF2 %s block has invalid bounds", block.name)}
		}
	}
	if reason := unreasonableExpansion(uint64(binary.BigEndian.Uint32(data[16:20])), uint64(len(data))); reason != "" {
		return fontAnalysis{reason: reason}
	}
	compressed := data[position : uint64(position)+compressedSize]
	expanded, err := io.ReadAll(io.LimitReader(brotli.NewReader(bytes.NewReader(compressed)), int64(decompressedSize)+1))
	if err != nil || uint64(len(expanded)) != decompressedSize {
		return fontAnalysis{reason: "invalid WOFF2 Brotli stream or expanded length"}
	}
	offset := uint64(0)
	for index := range tables {
		end := offset + tables[index].storedLength
		tables[index].body = expanded[offset:end]
		if !transformedTables[index] {
			if reason := validateKnownSFNTTableBody(tables[index].tag, tables[index].body); reason != "" {
				return fontAnalysis{reason: reason}
			}
		}
		offset = end
	}
	return fontAnalysis{tables: tables}
}

func validateWOFF2Pairs(tables []fontTable, transformed []bool, collection bool) string {
	if collection {
		for index, table := range tables {
			if table.tag == "glyf" && transformed[index] {
				if index+1 >= len(tables) || tables[index+1].tag != "loca" || !transformed[index+1] {
					return "transformed WOFF2 collection glyf table is not followed by loca"
				}
			}
			if table.tag == "loca" && transformed[index] && (index == 0 || tables[index-1].tag != "glyf" || !transformed[index-1]) {
				return "transformed WOFF2 collection loca table is not paired with glyf"
			}
		}
		return ""
	}
	var glyf, loca bool
	for index, table := range tables {
		if table.tag == "glyf" {
			glyf = transformed[index]
		}
		if table.tag == "loca" {
			loca = transformed[index]
		}
	}
	if glyf != loca {
		return "transformed WOFF2 glyf and loca tables are not paired"
	}
	return ""
}

func parseWOFF2CollectionDirectory(data []byte, position int, tables []fontTable, transformed []bool) (int, uint64, string) {
	if position+4 > len(data) {
		return position, 0, "truncated WOFF2 collection header"
	}
	version := binary.BigEndian.Uint32(data[position : position+4])
	position += 4
	if version != 0x00010000 && version != 0x00020000 {
		return position, 0, "invalid WOFF2 collection version"
	}
	numFonts, next, ok := read255UInt16(data, position)
	if !ok || numFonts == 0 || numFonts > 4096 {
		return position, 0, "invalid WOFF2 collection font count"
	}
	position = next
	overhead := uint64(12 + 4*uint64(numFonts))
	for fontIndex := uint16(0); fontIndex < numFonts; fontIndex++ {
		numTables, afterCount, valid := read255UInt16(data, position)
		if !valid || numTables == 0 || int(numTables) > len(tables) || afterCount+4 > len(data) {
			return position, 0, "invalid WOFF2 collection font entry"
		}
		overhead += 12 + 16*uint64(numTables)
		position = afterCount + 4
		seen := make(map[uint16]struct{}, numTables)
		indices := make([]uint16, 0, numTables)
		for tableIndex := uint16(0); tableIndex < numTables; tableIndex++ {
			index, afterIndex, valid := read255UInt16(data, position)
			if !valid || int(index) >= len(tables) {
				return position, 0, "invalid WOFF2 collection table index"
			}
			if _, exists := seen[index]; exists {
				return position, 0, "duplicate WOFF2 collection table index"
			}
			seen[index] = struct{}{}
			indices = append(indices, index)
			position = afterIndex
		}
		for entryIndex, index := range indices {
			if tables[index].tag == "glyf" && transformed[index] {
				if entryIndex+1 >= len(indices) || indices[entryIndex+1] != index+1 || tables[indices[entryIndex+1]].tag != "loca" || !transformed[indices[entryIndex+1]] {
					return position, 0, "WOFF2 collection font has an unpaired transformed glyf table"
				}
			}
			if tables[index].tag == "loca" && transformed[index] {
				if entryIndex == 0 || indices[entryIndex-1]+1 != index || tables[indices[entryIndex-1]].tag != "glyf" || !transformed[indices[entryIndex-1]] {
					return position, 0, "WOFF2 collection font has an unpaired transformed loca table"
				}
			}
		}
	}
	return position, overhead, ""
}

func read255UInt16(data []byte, position int) (uint16, int, bool) {
	if position >= len(data) {
		return 0, position, false
	}
	code := data[position]
	position++
	switch code {
	case 253:
		if position+2 > len(data) {
			return 0, position, false
		}
		return binary.BigEndian.Uint16(data[position : position+2]), position + 2, true
	case 254, 255:
		if position >= len(data) {
			return 0, position, false
		}
		base := uint16(506)
		if code == 255 {
			base = 253
		}
		return base + uint16(data[position]), position + 1, true
	default:
		return uint16(code), position, true
	}
}

func readUIntBase128(data []byte, position int) (uint32, int, bool) {
	var value uint64
	for index := 0; index < 5; index++ {
		if position >= len(data) {
			return 0, position, false
		}
		current := data[position]
		position++
		if index == 0 && current == 0x80 {
			return 0, position, false
		}
		value = value<<7 | uint64(current&0x7f)
		if value > 0xffffffff {
			return 0, position, false
		}
		if current&0x80 == 0 {
			return uint32(value), position, true
		}
	}
	return 0, position, false
}

func unreasonableExpansion(expanded, compressed uint64) string {
	if expanded > maxExpandedFontSize || (compressed > 0 && expanded/compressed > 1000) {
		return fmt.Sprintf("declared expanded font size is unreasonable (%d bytes)", expanded)
	}
	return ""
}

func inspectOpenTypeSVG(data []byte, table fontTable) (string, string) {
	const documentBudget = 8 << 20
	body := table.body
	if body == nil && table.offset <= uint64(len(data)) && table.length <= uint64(len(data))-table.offset {
		body = data[table.offset : table.offset+table.length]
	}
	if table.length < 10 || uint64(len(body)) != table.length {
		return "", "malformed OpenType SVG table"
	}
	docListOffset := uint64(binary.BigEndian.Uint32(body[2:6]))
	if docListOffset > uint64(len(body)) || uint64(len(body))-docListOffset < 2 {
		return "", "malformed OpenType SVG document list"
	}
	docList := body[docListOffset:]
	count := uint64(binary.BigEndian.Uint16(docList[:2]))
	if count > 4096 || 2+12*count > uint64(len(docList)) {
		return "", "malformed OpenType SVG document index"
	}
	expandedTotal := 0
	activeReason := ""
	for index := uint64(0); index < count; index++ {
		entry := 2 + 12*index
		offset := uint64(binary.BigEndian.Uint32(docList[entry+4 : entry+8]))
		length := uint64(binary.BigEndian.Uint32(docList[entry+8 : entry+12]))
		if offset > uint64(len(docList)) || length > uint64(len(docList))-offset {
			return "", "malformed OpenType SVG document bounds"
		}
		document := docList[offset : offset+length]
		if len(document) >= 2 && document[0] == 0x1f && document[1] == 0x8b {
			reader, err := gzip.NewReader(bytes.NewReader(document))
			if err != nil {
				return "", "malformed compressed OpenType SVG document"
			}
			remaining := documentBudget - expandedTotal
			expanded, err := io.ReadAll(io.LimitReader(reader, int64(remaining)+1))
			closeErr := reader.Close()
			if err != nil || closeErr != nil || len(expanded) > remaining {
				return "", "invalid or oversized compressed OpenType SVG document"
			}
			document = expanded
		}
		if len(document) > documentBudget-expandedTotal {
			return "", "OpenType SVG documents exceed the aggregate inspection limit"
		}
		expandedTotal += len(document)
		reason, valid := activeSVGReason(document)
		if !valid {
			return "", "malformed OpenType SVG document"
		}
		if reason != "" {
			if activeReason == "" {
				activeReason = reason
			}
		}
	}
	return activeReason, ""
}

func embeddedExecutable(data []byte) string {
	for offset := bytes.Index(data, []byte{0x7f, 'E', 'L', 'F'}); offset >= 0; {
		if validELFHeader(data[offset:]) {
			return "embedded ELF executable signature"
		}
		next := bytes.Index(data[offset+4:], []byte{0x7f, 'E', 'L', 'F'})
		if next < 0 {
			break
		}
		offset += next + 4
	}
	for offset := bytes.Index(data, []byte{'M', 'Z'}); offset >= 0; {
		if offset+64 <= len(data) {
			peOffset := uint64(offset) + uint64(binary.LittleEndian.Uint32(data[offset+60:offset+64]))
			if peOffset+4 <= uint64(len(data)) && bytes.Equal(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
				return "embedded Windows PE executable signature"
			}
		}
		next := bytes.Index(data[offset+2:], []byte{'M', 'Z'})
		if next < 0 {
			break
		}
		offset += next + 2
	}
	return ""
}

func validELFHeader(data []byte) bool {
	if len(data) < 20 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) || data[6] != 1 {
		return false
	}
	var order binary.ByteOrder
	switch data[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return false
	}
	elfType := order.Uint16(data[16:18])
	if elfType < 1 || elfType > 4 || order.Uint16(data[18:20]) == 0 {
		return false
	}
	switch data[4] {
	case 1:
		if len(data) < 52 {
			return false
		}
		headerSize := uint64(order.Uint16(data[40:42]))
		if order.Uint32(data[20:24]) != 1 || headerSize < 52 || headerSize > uint64(len(data)) {
			return false
		}
		programOffset := uint64(order.Uint32(data[28:32]))
		programEntrySize := uint64(order.Uint16(data[42:44]))
		programCount := uint64(order.Uint16(data[44:46]))
		return boundedELFProgramHeaders(uint64(len(data)), programOffset, programEntrySize, programCount, 32)
	case 2:
		if len(data) < 64 {
			return false
		}
		headerSize := uint64(order.Uint16(data[52:54]))
		if order.Uint32(data[20:24]) != 1 || headerSize < 64 || headerSize > uint64(len(data)) {
			return false
		}
		programOffset := order.Uint64(data[32:40])
		programEntrySize := uint64(order.Uint16(data[54:56]))
		programCount := uint64(order.Uint16(data[56:58]))
		return boundedELFProgramHeaders(uint64(len(data)), programOffset, programEntrySize, programCount, 56)
	default:
		return false
	}
}

func boundedELFProgramHeaders(size, offset, entrySize, count, minimumEntrySize uint64) bool {
	if count == 0 {
		return true
	}
	if entrySize < minimumEntrySize || offset > size || count > (size-offset)/entrySize {
		return false
	}
	return true
}
