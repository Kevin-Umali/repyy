package integration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCleanRepositoryFromBuiltCLI(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"README.md": "# Fixture\n",
		"LICENSE":   "Inert integration fixture\n",
		"main.go":   "package main\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	binary := filepath.Join(root, "repyy")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "../../cmd/repyy")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}

	scan := exec.Command(binary, "scan", target)
	scan.Env = append(os.Environ(), "REPYY_CACHE_DIR="+filepath.Join(root, "cache"))
	output, err := scan.CombinedOutput()
	if err != nil {
		t.Fatalf("scan clean fixture: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "NO RELEVANT FINDINGS DETECTED") {
		t.Fatalf("unexpected output:\n%s", output)
	}
}
