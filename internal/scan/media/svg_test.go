package media_test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"github.com/andybalholm/brotli"
)

const maxTestExpandedFontSize = 513 << 20

func writeBytesFixture(t *testing.T, root, name string, body []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func ttfFixture(tableOffset uint32) []byte {
	body := make([]byte, 32)
	binary.BigEndian.PutUint32(body[0:4], 0x00010000)
	binary.BigEndian.PutUint16(body[4:6], 1)
	copy(body[12:16], "name")
	binary.BigEndian.PutUint32(body[20:24], tableOffset)
	binary.BigEndian.PutUint32(body[24:28], 4)
	return body
}

type fontFixtureTable struct {
	tag  string
	body []byte
}

func sfntFixture(tables ...fontFixtureTable) []byte {
	directoryEnd := 12 + 16*len(tables)
	size := directoryEnd
	for _, table := range tables {
		size = (size + 3) &^ 3
		size += len(table.body)
	}
	body := make([]byte, size)
	binary.BigEndian.PutUint32(body[0:4], 0x00010000)
	binary.BigEndian.PutUint16(body[4:6], uint16(len(tables)))
	offset := directoryEnd
	for index, table := range tables {
		offset = (offset + 3) &^ 3
		entry := 12 + 16*index
		copy(body[entry:entry+4], table.tag)
		binary.BigEndian.PutUint32(body[entry+8:entry+12], uint32(offset))
		binary.BigEndian.PutUint32(body[entry+12:entry+16], uint32(len(table.body)))
		copy(body[offset:], table.body)
		offset += len(table.body)
	}
	return body
}

func svgFontFixture(svg string) []byte {
	return svgFontDocumentFixture([]byte(svg))
}

func svgFontDocumentFixture(document []byte) []byte {
	documentList := make([]byte, 14+len(document))
	binary.BigEndian.PutUint16(documentList[0:2], 1)
	binary.BigEndian.PutUint16(documentList[2:4], 0)
	binary.BigEndian.PutUint16(documentList[4:6], 0)
	binary.BigEndian.PutUint32(documentList[6:10], 14)
	binary.BigEndian.PutUint32(documentList[10:14], uint32(len(document)))
	copy(documentList[14:], document)
	table := make([]byte, 10+len(documentList))
	binary.BigEndian.PutUint32(table[2:6], 10)
	copy(table[10:], documentList)
	return sfntFixture(fontFixtureTable{tag: "SVG ", body: table})
}

func woffFixture(tag string, original []byte, compress bool) []byte {
	encoded := original
	if compress {
		var compressed bytes.Buffer
		writer := zlib.NewWriter(&compressed)
		_, _ = writer.Write(original)
		_ = writer.Close()
		encoded = compressed.Bytes()
		if len(encoded) >= len(original) {
			encoded = original
		}
	}
	body := make([]byte, 64+len(encoded))
	copy(body[:4], "wOFF")
	binary.BigEndian.PutUint32(body[4:8], 0x00010000)
	binary.BigEndian.PutUint32(body[8:12], uint32(len(body)))
	binary.BigEndian.PutUint16(body[12:14], 1)
	binary.BigEndian.PutUint32(body[16:20], uint32(28+((len(original)+3)&^3)))
	copy(body[44:48], tag)
	binary.BigEndian.PutUint32(body[48:52], 64)
	binary.BigEndian.PutUint32(body[52:56], uint32(len(encoded)))
	binary.BigEndian.PutUint32(body[56:60], uint32(len(original)))
	copy(body[64:], encoded)
	return body
}

func woff2Fixture(flags byte, originalLength byte, stored []byte, transformed bool) []byte {
	var compressed bytes.Buffer
	writer := brotli.NewWriter(&compressed)
	_, _ = writer.Write(stored)
	_ = writer.Close()
	directory := []byte{flags, originalLength}
	if transformed {
		directory = append(directory, byte(len(stored)))
	}
	body := make([]byte, 48+len(directory)+compressed.Len())
	copy(body[:4], "wOF2")
	binary.BigEndian.PutUint32(body[8:12], uint32(len(body)))
	binary.BigEndian.PutUint16(body[12:14], 1)
	binary.BigEndian.PutUint32(body[16:20], uint32(28+((int(originalLength)+3)&^3)))
	binary.BigEndian.PutUint32(body[20:24], uint32(compressed.Len()))
	copy(body[48:], directory)
	copy(body[48+len(directory):], compressed.Bytes())
	return body
}

func ttfWithEmbeddedPE() []byte {
	body := make([]byte, 128)
	binary.BigEndian.PutUint32(body[0:4], 0x00010000)
	binary.BigEndian.PutUint16(body[4:6], 1)
	copy(body[12:16], "name")
	binary.BigEndian.PutUint32(body[20:24], 28)
	binary.BigEndian.PutUint32(body[24:28], 100)
	copy(body[32:34], "MZ")
	binary.LittleEndian.PutUint32(body[92:96], 64)
	copy(body[96:100], []byte{'P', 'E', 0, 0})
	return body
}

func ttfWithELF(valid bool) []byte {
	payload := []byte("ordinary bytes \x7fELF ordinary bytes")
	if valid {
		payload = make([]byte, 64)
		copy(payload[:4], []byte{0x7f, 'E', 'L', 'F'})
		payload[4] = 2
		payload[5] = 1
		payload[6] = 1
		binary.LittleEndian.PutUint16(payload[16:18], 2)
		binary.LittleEndian.PutUint16(payload[18:20], 0x3e)
		binary.LittleEndian.PutUint32(payload[20:24], 1)
		binary.LittleEndian.PutUint16(payload[52:54], 64)
	}
	return sfntFixture(fontFixtureTable{tag: "name", body: payload})
}

func ttfWithTruncatedELFHeader() []byte {
	payload := make([]byte, 20)
	copy(payload[:4], []byte{0x7f, 'E', 'L', 'F'})
	payload[4] = 2
	payload[5] = 1
	payload[6] = 1
	binary.LittleEndian.PutUint16(payload[16:18], 2)
	binary.LittleEndian.PutUint16(payload[18:20], 0x3e)
	return sfntFixture(fontFixtureTable{tag: "name", body: payload})
}

func writeFixture(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasRule(findings []model.Finding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}

func ruleFinding(findings []model.Finding, id string) (model.Finding, bool) {
	for _, finding := range findings {
		if finding.RuleID == id {
			return finding, true
		}
	}
	return model.Finding{}, false
}

func TestSVGActiveContentIsDetectedWithoutRendering(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "assets/active.svg", `<svg xmlns="http://www.w3.org/2000/svg">
  <script>void 0;</script>
  <rect onload="void 0"/>
  <a href="&#x6a;avascript:void(0)"><text>fixture</text></a>
</svg>`)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "IMAGE-001")
	if !ok || finding.Path != "assets/active.svg" || finding.Context != "executable" || finding.Occurrences != 3 || len(finding.Locations) != 3 {
		t.Fatalf("active SVG content was not located: %+v", findings)
	}
	for index, location := range finding.Locations {
		if location.StartLine != index+2 {
			t.Fatalf("SVG location %d has line %d, want %d: %+v", index, location.StartLine, index+2, finding)
		}
	}
}

func TestSVGCommentsAndDataScriptsAreNotActive(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "assets/passive.svg", `<svg xmlns="http://www.w3.org/2000/svg">
  <!-- <script>void 0;</script> -->
  <script type="application/json">{"message":"fixture"}</script>
  <rect width="10" height="10"/>
</svg>`)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if hasRule(findings, "IMAGE-001") {
		t.Fatalf("passive SVG was flagged: %+v", findings)
	}
}

func TestSVGActiveURLSchemes(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "assets/links.svg", `<svg xmlns="http://www.w3.org/2000/svg">
  <a href="vbscript:MsgBox(1)"/>
  <a href="data:text/html,&lt;script&gt;void 0&lt;/script&gt;"/>
  <a href="data:image/svg+xml;base64,PHN2Zy8+"/>
  <image href="data:image/png;base64,AAAA"/>
</svg>`)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "IMAGE-001")
	if !ok || finding.Occurrences != 3 || len(finding.Locations) != 3 {
		t.Fatalf("active SVG links were not distinguished from an embedded image: %+v", findings)
	}
}

func TestBinaryFontsAreInventoriedAndMalformedTablesAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name        string
		font        []byte
		wantInvalid bool
	}{
		{"bounded TrueType", ttfFixture(28), false},
		{"out of bounds TrueType table", ttfFixture(0xfffffff0), true},
		{"embedded Windows executable", ttfWithEmbeddedPE(), true},
		{"incidental ELF magic", ttfWithELF(false), false},
		{"truncated ELF-like header", ttfWithTruncatedELFHeader(), false},
		{"embedded valid ELF", ttfWithELF(true), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeBytesFixture(t, root, "assets/fixture.ttf", tc.font)
			_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
			if !hasRule(findings, "FONT-002") {
				t.Fatalf("binary font was not inventoried: %+v", findings)
			}
			if got := hasRule(findings, "FONT-003"); got != tc.wantInvalid {
				t.Fatalf("FONT-003 present=%v want=%v: %+v", got, tc.wantInvalid, findings)
			}
		})
	}
}

func TestFontTableGraphIntegrity(t *testing.T) {
	duplicate := sfntFixture(
		fontFixtureTable{tag: "name", body: []byte("one")},
		fontFixtureTable{tag: "name", body: []byte("two")},
	)
	misaligned := sfntFixture(fontFixtureTable{tag: "name", body: []byte("fixture")})
	binary.BigEndian.PutUint32(misaligned[20:24], binary.BigEndian.Uint32(misaligned[20:24])+1)
	invalidHead := make([]byte, 54)
	binary.BigEndian.PutUint16(invalidHead[18:20], 1000)
	invalidCollection := make([]byte, 16)
	copy(invalidCollection[:4], "ttcf")
	binary.BigEndian.PutUint32(invalidCollection[8:12], 1)
	binary.BigEndian.PutUint32(invalidCollection[12:16], 128)
	overlappingCollection := make([]byte, 44)
	copy(overlappingCollection[:4], "ttcf")
	binary.BigEndian.PutUint32(overlappingCollection[8:12], 1)
	binary.BigEndian.PutUint32(overlappingCollection[12:16], 16)
	binary.BigEndian.PutUint32(overlappingCollection[16:20], 0x00010000)
	binary.BigEndian.PutUint16(overlappingCollection[20:22], 1)
	copy(overlappingCollection[28:32], "name")
	binary.BigEndian.PutUint32(overlappingCollection[36:40], 20)
	binary.BigEndian.PutUint32(overlappingCollection[40:44], 4)
	expandingWOFF := make([]byte, 64)
	copy(expandingWOFF[:4], "wOFF")
	binary.BigEndian.PutUint32(expandingWOFF[8:12], uint32(len(expandingWOFF)))
	binary.BigEndian.PutUint16(expandingWOFF[12:14], 1)
	binary.BigEndian.PutUint32(expandingWOFF[16:20], maxTestExpandedFontSize)
	copy(expandingWOFF[44:48], "name")
	binary.BigEndian.PutUint32(expandingWOFF[48:52], 64)
	overlappingWOFF := make([]byte, 65)
	copy(overlappingWOFF[:4], "wOFF")
	binary.BigEndian.PutUint32(overlappingWOFF[8:12], uint32(len(overlappingWOFF)))
	binary.BigEndian.PutUint16(overlappingWOFF[12:14], 1)
	binary.BigEndian.PutUint32(overlappingWOFF[16:20], 32)
	copy(overlappingWOFF[44:48], "name")
	binary.BigEndian.PutUint32(overlappingWOFF[48:52], 44)
	binary.BigEndian.PutUint32(overlappingWOFF[52:56], 1)
	binary.BigEndian.PutUint32(overlappingWOFF[56:60], 1)
	truncatedWOFF2 := make([]byte, 48)
	copy(truncatedWOFF2[:4], "wOF2")
	binary.BigEndian.PutUint32(truncatedWOFF2[8:12], uint32(len(truncatedWOFF2)))
	binary.BigEndian.PutUint16(truncatedWOFF2[12:14], 1)
	reservedTransformWOFF2 := make([]byte, 51)
	copy(reservedTransformWOFF2[:4], "wOF2")
	binary.BigEndian.PutUint32(reservedTransformWOFF2[8:12], uint32(len(reservedTransformWOFF2)))
	binary.BigEndian.PutUint16(reservedTransformWOFF2[12:14], 1)
	binary.BigEndian.PutUint32(reservedTransformWOFF2[16:20], 32)
	binary.BigEndian.PutUint32(reservedTransformWOFF2[20:24], 1)
	reservedTransformWOFF2[48] = 0x4a // glyf tag with reserved transform version 1
	reservedTransformWOFF2[49] = 1
	unsupportedTransformWOFF2 := append([]byte(nil), reservedTransformWOFF2...)
	unsupportedTransformWOFF2[48] = 0x45 // name tag with undefined transform version 1
	malformedSVG := sfntFixture(fontFixtureTable{tag: "SVG ", body: []byte{0, 0, 0, 0}})
	malformedSVGDocument := svgFontFixture(`<svg xmlns="http://www.w3.org/2000/svg"><g></svg>`)

	for _, tc := range []struct {
		name string
		font []byte
		ext  string
	}{
		{"duplicate table tag", duplicate, ".ttf"},
		{"misaligned table offset", misaligned, ".ttf"},
		{"invalid head magic", sfntFixture(fontFixtureTable{tag: "head", body: invalidHead}), ".ttf"},
		{"invalid collection face", invalidCollection, ".ttc"},
		{"collection table overlaps face directory", overlappingCollection, ".ttc"},
		{"unreasonable WOFF expansion", expandingWOFF, ".woff"},
		{"WOFF table overlaps directory", overlappingWOFF, ".woff"},
		{"truncated WOFF2 directory", truncatedWOFF2, ".woff2"},
		{"reserved WOFF2 transform", reservedTransformWOFF2, ".woff2"},
		{"unsupported WOFF2 transform", unsupportedTransformWOFF2, ".woff2"},
		{"malformed OpenType SVG table", malformedSVG, ".ttf"},
		{"malformed OpenType SVG document", malformedSVGDocument, ".ttf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeBytesFixture(t, root, "assets/fixture"+tc.ext, tc.font)
			_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
			if !hasRule(findings, "FONT-003") {
				t.Fatalf("malformed font table graph was accepted: %+v", findings)
			}
			if strings.HasPrefix(tc.name, "malformed OpenType SVG") && hasRule(findings, "FONT-004") {
				t.Fatalf("malformed SVG table was classified as active content: %+v", findings)
			}
		})
	}
}

func TestFontProgramsAndEmbeddedSVGAreReported(t *testing.T) {
	var compressedSVG bytes.Buffer
	writer := gzip.NewWriter(&compressedSVG)
	if _, err := writer.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><path onload="void 0"/></svg>`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	sfntSVG := svgFontFixture(`<svg xmlns="http://www.w3.org/2000/svg"><!--` + strings.Repeat("padding", 200) + `--><script>void 0</script></svg>`)
	svgOffset := binary.BigEndian.Uint32(sfntSVG[20:24])
	svgLength := binary.BigEndian.Uint32(sfntSVG[24:28])
	svgTable := sfntSVG[svgOffset : svgOffset+svgLength]
	for _, tc := range []struct {
		name string
		font []byte
		rule string
		ext  string
	}{
		{"TrueType program", sfntFixture(fontFixtureTable{tag: "fpgm", body: []byte{0x2c, 0x2d}}), "FONT-005", ".ttf"},
		{"active OpenType SVG", sfntSVG, "FONT-004", ".ttf"},
		{"compressed active OpenType SVG", svgFontDocumentFixture(compressedSVG.Bytes()), "FONT-004", ".ttf"},
		{"active SVG in WOFF", woffFixture("SVG ", svgTable, true), "FONT-004", ".woff"},
		{"program in WOFF", woffFixture("fpgm", []byte{0x2c, 0x2d}, true), "FONT-005", ".woff"},
		{"compressed PE in WOFF", woffFixture("name", ttfWithEmbeddedPE()[28:], true), "FONT-003", ".woff"},
		{"passive OpenType SVG", svgFontFixture(`<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>`), "", ".ttf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeBytesFixture(t, root, "assets/fixture"+tc.ext, tc.font)
			_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
			if tc.rule == "" {
				if hasRule(findings, "FONT-004") || hasRule(findings, "FONT-005") {
					t.Fatalf("passive font content was flagged: %+v", findings)
				}
				return
			}
			if !hasRule(findings, tc.rule) {
				t.Fatalf("missing %s: %+v", tc.rule, findings)
			}
		})
	}
}

func TestBoundedWOFF2DirectoryIsAccepted(t *testing.T) {
	body := woff2Fixture(5, 1, []byte{0}, false)

	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/fixture.woff2", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-002") || hasRule(findings, "FONT-003") {
		t.Fatalf("bounded WOFF2 directory was rejected: %+v", findings)
	}
}

func TestTransformedHmtxWOFF2IsAccepted(t *testing.T) {
	body := woff2Fixture(0x43, 1, []byte{0}, true)

	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/fixture.woff2", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-002") || hasRule(findings, "FONT-003") {
		t.Fatalf("standard hmtx transform was rejected: %+v", findings)
	}
}

func TestInvalidWOFF2BrotliStreamIsRejected(t *testing.T) {
	body := woff2Fixture(5, 1, []byte{0}, false)
	body[len(body)-1] ^= 0xff
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/invalid.woff2", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-003") {
		t.Fatalf("invalid WOFF2 Brotli stream was accepted: %+v", findings)
	}
}

func TestWOFF2TablePayloadIsInspected(t *testing.T) {
	payload := ttfWithEmbeddedPE()[28:128]
	body := woff2Fixture(5, byte(len(payload)), payload, false)
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/payload.woff2", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-002") {
		t.Fatalf("executable WOFF2 table payload was missed: %+v", findings)
	}
}

func TestDuplicateWOFF2TableIsRejected(t *testing.T) {
	var compressed bytes.Buffer
	writer := brotli.NewWriter(&compressed)
	_, _ = writer.Write([]byte{0, 0})
	_ = writer.Close()
	body := make([]byte, 52+compressed.Len())
	copy(body[:4], "wOF2")
	binary.BigEndian.PutUint32(body[8:12], uint32(len(body)))
	binary.BigEndian.PutUint16(body[12:14], 2)
	binary.BigEndian.PutUint32(body[16:20], 44)
	binary.BigEndian.PutUint32(body[20:24], uint32(compressed.Len()))
	copy(body[48:52], []byte{5, 1, 5, 1})
	copy(body[52:], compressed.Bytes())
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/duplicate.woff2", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-003") {
		t.Fatalf("duplicate WOFF2 table was accepted: %+v", findings)
	}
}

func TestWOFF2CollectionDirectoryIsAccepted(t *testing.T) {
	var compressed bytes.Buffer
	writer := brotli.NewWriter(&compressed)
	_, _ = writer.Write([]byte{0})
	_ = writer.Close()
	directory := []byte{5, 1}
	collection := make([]byte, 11)
	binary.BigEndian.PutUint32(collection[0:4], 0x00010000)
	collection[4] = 1
	collection[5] = 1
	binary.BigEndian.PutUint32(collection[6:10], 0x00010000)
	collection[10] = 0
	body := make([]byte, 48+len(directory)+len(collection)+compressed.Len())
	copy(body[:4], "wOF2")
	copy(body[4:8], "ttcf")
	binary.BigEndian.PutUint32(body[8:12], uint32(len(body)))
	binary.BigEndian.PutUint16(body[12:14], 1)
	binary.BigEndian.PutUint32(body[16:20], 48)
	binary.BigEndian.PutUint32(body[20:24], uint32(compressed.Len()))
	copy(body[48:], directory)
	copy(body[48+len(directory):], collection)
	copy(body[48+len(directory)+len(collection):], compressed.Bytes())
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/collection.woff2", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if hasRule(findings, "FONT-003") {
		t.Fatalf("valid WOFF2 collection directory was rejected: %+v", findings)
	}
}

func TestTransformedWOFF2LocaPayloadMustBeEmpty(t *testing.T) {
	directory := []byte{10, 1, 1, 11, 1, 1}
	body := make([]byte, 48+len(directory)+1)
	copy(body[:4], "wOF2")
	binary.BigEndian.PutUint32(body[8:12], uint32(len(body)))
	binary.BigEndian.PutUint16(body[12:14], 2)
	binary.BigEndian.PutUint32(body[16:20], 48)
	binary.BigEndian.PutUint32(body[20:24], 1)
	copy(body[48:], directory)
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/invalid-loca.woff2", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-003") {
		t.Fatalf("nonzero transformed loca payload was accepted: %+v", findings)
	}
}

func TestWrappedSFNTTablesReceiveStructuralValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"woff", woffFixture("head", make([]byte, 10), false)},
		{"woff2", woff2Fixture(1, 10, make([]byte, 10), false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeBytesFixture(t, root, "assets/invalid."+tc.name, tc.body)
			_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
			if !hasRule(findings, "FONT-003") {
				t.Fatalf("invalid wrapped head table was accepted: %+v", findings)
			}
		})
	}
}

func TestWOFF2TotalSizeLowerBoundIsValidated(t *testing.T) {
	body := woff2Fixture(5, 1, []byte{0}, false)
	binary.BigEndian.PutUint32(body[16:20], 1)
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/invalid-size.woff2", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-003") {
		t.Fatalf("impossible WOFF2 totalSfntSize was accepted: %+v", findings)
	}
}

func TestActiveSVGDoesNotHideLaterMalformedDocument(t *testing.T) {
	active := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>void 0</script></svg>`)
	invalidGzip := []byte{0x1f, 0x8b, 0, 0}
	docList := make([]byte, 26+len(active)+len(invalidGzip))
	binary.BigEndian.PutUint16(docList[0:2], 2)
	binary.BigEndian.PutUint32(docList[6:10], 26)
	binary.BigEndian.PutUint32(docList[10:14], uint32(len(active)))
	binary.BigEndian.PutUint32(docList[18:22], uint32(26+len(active)))
	binary.BigEndian.PutUint32(docList[22:26], uint32(len(invalidGzip)))
	copy(docList[26:], active)
	copy(docList[26+len(active):], invalidGzip)
	table := make([]byte, 10+len(docList))
	binary.BigEndian.PutUint32(table[2:6], 10)
	copy(table[10:], docList)
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/mixed.ttf", sfntFixture(fontFixtureTable{tag: "SVG ", body: table}))
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-003") {
		t.Fatalf("later malformed SVG document was hidden by active content: %+v", findings)
	}
}

func TestTrueTypeCollectionAggregateTableLimit(t *testing.T) {
	const tableCount = 4096
	const faceCount = 17
	fontOffset := 12 + 4*faceCount
	body := make([]byte, fontOffset+12+16*tableCount)
	copy(body[:4], "ttcf")
	binary.BigEndian.PutUint32(body[8:12], faceCount)
	for face := 0; face < faceCount; face++ {
		binary.BigEndian.PutUint32(body[12+4*face:16+4*face], uint32(fontOffset))
	}
	binary.BigEndian.PutUint32(body[fontOffset:fontOffset+4], 0x00010000)
	binary.BigEndian.PutUint16(body[fontOffset+4:fontOffset+6], tableCount)
	for table := 0; table < tableCount; table++ {
		entry := fontOffset + 12 + 16*table
		binary.BigEndian.PutUint32(body[entry:entry+4], uint32(table))
		binary.BigEndian.PutUint32(body[entry+8:entry+12], uint32(len(body)))
	}

	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/fixture.ttc", body)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-003") {
		t.Fatalf("aggregate TTC table limit was not enforced: %+v", findings)
	}
}

func TestMalformedFontFixtureIsContextual(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "testdata/malformed.ttf", ttfFixture(0xfffffff0))
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "FONT-003")
	if !ok || finding.Severity != model.SeverityMedium || finding.Confidence != model.ConfidenceLow || finding.Disposition != model.DispositionInformational {
		t.Fatalf("malformed font fixture was not contextualized: %+v", findings)
	}
}

func TestOpenTypeSVGAggregateExpansionLimit(t *testing.T) {
	document := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><!--` + strings.Repeat("a", 5<<20) + `--></svg>`)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(document); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	payload := compressed.Bytes()
	documentList := make([]byte, 26+2*len(payload))
	binary.BigEndian.PutUint16(documentList[:2], 2)
	for index := 0; index < 2; index++ {
		entry := 2 + 12*index
		binary.BigEndian.PutUint16(documentList[entry:entry+2], uint16(index))
		binary.BigEndian.PutUint16(documentList[entry+2:entry+4], uint16(index))
		binary.BigEndian.PutUint32(documentList[entry+4:entry+8], uint32(26+index*len(payload)))
		binary.BigEndian.PutUint32(documentList[entry+8:entry+12], uint32(len(payload)))
		copy(documentList[26+index*len(payload):], payload)
	}
	table := make([]byte, 10+len(documentList))
	binary.BigEndian.PutUint32(table[2:6], 10)
	copy(table[10:], documentList)
	font := sfntFixture(fontFixtureTable{tag: "SVG ", body: table})

	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeBytesFixture(t, root, "assets/fixture.ttf", font)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "FONT-003") {
		t.Fatalf("aggregate OpenType SVG expansion limit was not enforced: %+v", findings)
	}
}
