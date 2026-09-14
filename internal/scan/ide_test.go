package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFolderOpenTaskRecognizesJSONPropertyWithoutFlaggingManualTask(t *testing.T) {
	for _, tc := range []struct {
		name, options string
		want          bool
	}{
		{"automatic", `,"runOptions":{"runOn":"folderOpen"}`, true},
		{"manual", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, ".vscode"), 0700); err != nil {
				t.Fatal(err)
			}
			body := `{"version":"2.0.0","tasks":[{"label":"inert","type":"process","command":"REPYY_NONEXISTENT_INERT_MARKER"` + tc.options + `}]}`
			if err := os.WriteFile(filepath.Join(root, ".vscode", "tasks.json"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			coverage, findings := New(Options{}).Scan(context.Background(), root)
			if !coverage.Complete {
				t.Fatalf("incomplete fixture: %+v", coverage)
			}
			_, found := ruleFinding(findings, "IDE-001")
			if found != tc.want {
				t.Fatalf("IDE-001 present=%v want=%v: %+v", found, tc.want, findings)
			}
		})
	}
}
