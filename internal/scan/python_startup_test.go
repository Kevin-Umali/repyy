package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestPythonPTHStartupImports(t *testing.T) {
	cases := []struct {
		name, body string
		line       int
	}{
		{"paths and comments", "# import ignored\n./library\nimported_folder\n IMPORT module\n import module\n", 0},
		{"space", "# benign\nimport module\n", 2},
		{"tab", "path\nimport\tmodule\n", 2},
		{"UTF-8 BOM", "\ufeffimport module\n", 1},
		{"carriage returns", "# comment\rpath\rimport module\r", 3},
		{"mixed line endings", "\ufeff# comment\r\npath\rimport\tmodule\n", 3},
		{"uppercase", "IMPORT module\n", 0},
		{"other whitespace", "import\vmodule\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "startup.pth", tc.body)
			_, findings := New(Options{}).Scan(context.Background(), root)
			finding, ok := ruleFinding(findings, "PY-004")
			if (tc.line != 0) != ok || ok && (finding.Line != tc.line || finding.Severity != model.SeverityMedium || finding.Confidence != model.ConfidenceHigh || finding.Disposition != model.DispositionReview) {
				t.Fatalf("unexpected finding: %+v", finding)
			}
		})
	}
}

func TestPythonStartupCustomizationAndContext(t *testing.T) {
	for _, name := range []string{"sitecustomize.py", "usercustomize.py"} {
		for _, dir := range []string{"", "fixtures", "docs"} {
			t.Run(filepath.Join(dir, name), func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(dir, name)
				writeFixture(t, root, path, "# configuration\n\nsetting = True\n")
				_, findings := New(Options{}).Scan(context.Background(), root)
				finding, ok := ruleFinding(findings, "PY-005")
				if !ok || finding.Line != 3 || finding.Path != filepath.ToSlash(path) {
					t.Fatalf("missing customization: %+v", finding)
				}
				if dir != "fixtures" && (finding.Confidence != model.ConfidenceHigh || finding.Disposition != model.DispositionReview) || dir == "fixtures" && (finding.Confidence != model.ConfidenceLow || finding.Disposition != model.DispositionInformational) {
					t.Fatalf("wrong context: %+v", finding)
				}
			})
		}
	}
	root := t.TempDir()
	writeFixture(t, root, "sitecustomize.py", "# only a comment\n\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	if hasRule(findings, "PY-005") {
		t.Fatalf("empty customization flagged: %+v", findings)
	}
}

func TestPythonPTHArchiveAndCoverage(t *testing.T) {
	root := t.TempDir()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("package/startup.pth")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("# path file\nimport module\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.whl"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	coverage, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "PY-004")
	if !coverage.Complete || !ok || finding.Path != "package.whl!package/startup.pth" || finding.Line != 2 {
		t.Fatalf("wheel entry not scanned: coverage=%+v finding=%+v", coverage, finding)
	}
	writeFixture(t, root, "invalid.pth", string([]byte{0xff, 0xfe, 0x00}))
	coverage, _ = New(Options{}).Scan(context.Background(), root)
	if coverage.Complete || !strings.Contains(strings.Join(coverage.Skipped, " "), "invalid.pth (undecodable source or configuration)") {
		t.Fatalf("undecodable .pth did not affect coverage: %+v", coverage)
	}
}

func TestPythonPTHContextDowngrade(t *testing.T) {
	for _, dir := range []string{"fixtures", "docs"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, filepath.Join(dir, "startup.pth"), "import module\n")
			_, findings := New(Options{}).Scan(context.Background(), root)
			finding, ok := ruleFinding(findings, "PY-004")
			if !ok || dir == "fixtures" && (finding.Confidence != model.ConfidenceLow || finding.Disposition != model.DispositionInformational) || dir == "docs" && (finding.Confidence != model.ConfidenceHigh || finding.Disposition != model.DispositionReview) {
				t.Fatalf("unexpected startup import context: %+v", finding)
			}
		})
	}
}
