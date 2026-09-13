//go:build unix

package scan

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestGitMetadataFIFODoesNotBlockPastTimeout(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(repo, ".git", "config"), 0o600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	finished := make(chan bool, 1)
	go func() {
		coverage, _ := New(Options{}).Scan(ctx, repo)
		finished <- coverage.Complete
	}()
	select {
	case complete := <-finished:
		if complete {
			t.Fatal("FIFO was marked as fully scanned")
		}
	case <-time.After(time.Second):
		t.Fatal("Git metadata FIFO blocked the scan")
	}
}
