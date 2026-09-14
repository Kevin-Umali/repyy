package scan

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func FuzzArchiveInspection(f *testing.F) {
	f.Add([]byte("PK\x03\x04"), uint8(0))
	f.Add([]byte("not a tar"), uint8(1))
	scanner := New(Options{Limits: Limits{MaxFiles: 100, MaxFileBytes: 16384, MaxArchiveFiles: 32, MaxArchiveBytes: 65536, MaxArchiveDepth: 2}})
	f.Fuzz(func(t *testing.T, data []byte, format uint8) {
		if len(data) > 65536 {
			t.Skip()
		}
		name := []string{"fixture.zip", "fixture.tar", "fixture.tar.gz"}[int(format)%3]
		coverage := model.Coverage{Complete: true}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		scanner.scanArchive(ctx, name, data, 1, func(model.Finding) {}, &coverage)
		if len(coverage.Skipped) > 256 {
			t.Fatal("unbounded archive diagnostics")
		}
	})
}

func FuzzArchivePaths(f *testing.F) {
	for _, seed := range []string{"../escape", "a/../../escape", "/absolute", `..\escape`, "C:\\escape", "ordinary/file"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 4096 {
			t.Skip()
		}
		if !unsafeArchivePath(name) {
			clean := path.Clean(strings.ReplaceAll(name, "\\", "/"))
			if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
				t.Fatalf("accepted escaping path %q", name)
			}
		}
	})
}

func FuzzGitMetadata(f *testing.F) {
	f.Add([]byte("[core]\n hooksPath = /outside\n"))
	f.Add([]byte("[include]\n path = ../outside\n"))
	scanner := New(Options{Limits: Limits{MaxFiles: 100, MaxFileBytes: 8192, MaxArchiveFiles: 32, MaxArchiveBytes: 65536, MaxArchiveDepth: 2}})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".git", "config"), data, 0600); err != nil {
			t.Fatal(err)
		}
		coverage := model.Coverage{Complete: true}
		scanner.scanGitMetadata(context.Background(), root, ".git", func(model.Finding) {}, &coverage)
		if coverage.BytesScanned > int64(len(data)) {
			t.Fatal("metadata followed an external include")
		}
	})
}

func FuzzSymlinkConfinement(f *testing.F) {
	f.Add("../outside.txt")
	f.Add("inside/../../outside.txt")
	scanner := New(Options{})
	f.Fuzz(func(t *testing.T, target string) {
		if len(target) > 4096 {
			t.Skip()
		}
		parent := t.TempDir()
		root := filepath.Join(parent, "repository")
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, "outside.txt"), []byte("external sentinel; not repository data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
			t.Skipf("target unsupported by filesystem: %v", err)
		}
		coverage, _ := scanner.Scan(context.Background(), root)
		if coverage.BytesScanned != 0 {
			t.Fatalf("symlink content was read: %+v", coverage)
		}
	})
}
