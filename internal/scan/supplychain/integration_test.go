package supplychain_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
)

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
	_, ok := ruleFinding(findings, id)
	return ok
}

func ruleFinding(findings []model.Finding, id string) (model.Finding, bool) {
	for _, finding := range findings {
		if finding.RuleID == id {
			return finding, true
		}
	}
	return model.Finding{}, false
}

func scanInertPackageFixture(t *testing.T, path, body string) []model.Finding {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "README.md", "Inert package source fixture\n")
	writeFixture(t, root, "LICENSE", "Inert fixture\n")
	writeFixture(t, root, path, body)
	coverage, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !coverage.Complete {
		t.Fatalf("fixture scan incomplete: %+v", coverage)
	}
	return findings
}
