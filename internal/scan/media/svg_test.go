package media_test

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
