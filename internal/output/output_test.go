package output

import (
	"bytes"
	"encoding/json"
	stdhtml "html"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func sampleReport() model.Report {
	return model.Report{SchemaVersion: "1", ToolVersion: "test", RulesVersion: "test-rules", Intelligence: model.IntelligenceInfo{Version: "test-intel", Date: "2026-09-12", Source: "embedded"}, GeneratedAt: time.Unix(0, 0).UTC(), Results: []model.RepoResult{{Target: "fixture", Verdict: model.VerdictReview, Coverage: model.Coverage{Complete: true, FilesScanned: 1}, Findings: []model.Finding{{RuleID: "TEST-001", Category: "test", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Disposition: model.DispositionReview, Context: "executable", Path: "file.txt", Line: 2, Occurrences: 2, Message: "test finding", Evidence: "safe evidence", Remediation: "review it", Fingerprint: "sha256:test", Locations: []model.Location{{Path: "file.txt", StartLine: 2, Evidence: "safe evidence"}, {Path: "file.txt", StartLine: 8, Evidence: "other evidence"}}}}}}}
}

func TestTerminalIncludesVerdictAndDisclaimer(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "terminal", sampleReport()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), model.VerdictReview) || !strings.Contains(out.String(), "does not prove") || !strings.Contains(out.String(), "not proof that code executed") {
		t.Fatalf("unexpected terminal output: %s", out.String())
	}
}

func TestJSONOutput(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "json", sampleReport()); err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Results) != 1 || decoded.Intelligence.Version != "test-intel" {
		t.Fatalf("unexpected report: %+v", decoded)
	}
}

func TestSARIFOutput(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "sarif", sampleReport()); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF: %+v", decoded)
	}
	runs := decoded["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	locations := results[0].(map[string]any)["locations"].([]any)
	if len(locations) != 2 {
		t.Fatalf("SARIF locations = %d, want 2", len(locations))
	}
}

func TestTerminalPrioritizesAndPrintsRemediation(t *testing.T) {
	report := sampleReport()
	report.Results[0].Findings = append(report.Results[0].Findings, model.Finding{RuleID: "INFO-001", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, Disposition: model.DispositionInformational, Context: "generated", Path: "generated.js", Message: "context only", Occurrences: 1})
	var out bytes.Buffer
	if err := Write(&out, "terminal", report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "fix: review it") || !strings.Contains(out.String(), "showing 1 of 2 findings") || !strings.Contains(out.String(), "1 contextual or filtered findings hidden") || strings.Contains(out.String(), "context only") {
		t.Fatalf("unexpected prioritized output: %s", out.String())
	}
}

func TestTerminalExplainsWhenAllDetailIsFiltered(t *testing.T) {
	report := sampleReport()
	opts := DefaultOptions()
	opts.Detail = "all"
	opts.MinSeverity = model.SeverityCritical
	var out bytes.Buffer
	if err := WriteWithOptions(&out, "terminal", report, opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "showing 0 of 1 findings; 1 hidden by display filters") || strings.Contains(out.String(), "use --detail all") {
		t.Fatalf("misleading filtered output: %s", out.String())
	}
}

func TestHTMLIsSelfContainedAndEscapesFindings(t *testing.T) {
	report := sampleReport()
	report.Results[0].Findings[0].Message = `</script><img src=x onerror=alert(1)>`
	report.Results[0].Findings[0].Locations[0].Evidence = `<script>alert(1)</script>`
	var first, second bytes.Buffer
	if err := Write(&first, "html", report); err != nil {
		t.Fatal(err)
	}
	if err := Write(&second, "html", report); err != nil {
		t.Fatal(err)
	}
	html := first.String()
	if first.String() != second.String() {
		t.Fatal("HTML rendering is not deterministic")
	}
	if !strings.Contains(html, "Content-Security-Policy") || !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") || !strings.Contains(html, `data-filter="rule"`) || !strings.Contains(html, `<option value="actionable" selected>Review queue</option>`) || !strings.Contains(html, `data-reset`) || !strings.Contains(html, `data-empty`) || !strings.Contains(html, "Needs attention") || !strings.Contains(html, "not proof that code executed") || !strings.Contains(html, "0 block") || strings.Contains(html, `<img src=x`) {
		t.Fatalf("unsafe or incomplete HTML: %s", html)
	}
	decoded := stdhtml.UnescapeString(html)
	if strings.Contains(html, "https://cdn") || strings.Contains(html, "http://") || strings.Contains(decoded, "unsafe-inline") || !strings.Contains(decoded, "style-src 'sha256-") || !strings.Contains(decoded, "script-src 'sha256-") {
		t.Fatal("HTML report contains an external asset")
	}
	if !strings.Contains(html, "color-scheme: light;") || strings.Contains(html, "prefers-color-scheme: dark") {
		t.Fatal("HTML report is not consistently light themed")
	}
	for _, semantic := range []string{`<main id="report-content">`, `<header class="masthead"`, `<time datetime=`, `<output data-visible-count`, `<footer class="muted report-footer"`, `aria-live="polite"`, `aria-label="Scan coverage"`} {
		if !strings.Contains(html, semantic) {
			t.Errorf("HTML report is missing semantic marker %q", semantic)
		}
	}
}

func TestRemoteSourceLinkValidation(t *testing.T) {
	revision := strings.Repeat("a", 40)
	location := model.Location{Path: "src/main.go", StartLine: 4, EndLine: 6}
	for _, test := range []struct {
		base, fragment string
	}{
		{"https://github.com/example/repo", "/blob/" + revision + "/src/main.go#L4-L6"},
		{"https://gitlab.com/example/repo", "/-/blob/" + revision + "/src/main.go#L4-L6"},
		{"https://bitbucket.org/example/repo", "/src/" + revision + "/src/main.go#lines-4"},
	} {
		link := remoteSourceLink(&model.SourceInfo{RepositoryURL: test.base, Revision: revision}, location)
		if link != test.base+test.fragment {
			t.Errorf("link = %q, want %q", link, test.base+test.fragment)
		}
	}
	for _, source := range []string{
		"http://github.com/example/repo",
		"https://user:secret@github.com/example/repo",
		"https://github.com/example/repo?token=secret",
		"https://github.com/example/../repo",
		"https://example.invalid/example/repo",
	} {
		if link := remoteSourceLink(&model.SourceInfo{RepositoryURL: source, Revision: revision}, location); link != "" {
			t.Errorf("unsafe source %q produced %q", source, link)
		}
	}
	if link := remoteSourceLink(&model.SourceInfo{RepositoryURL: "https://github.com/example/repo", Revision: revision}, model.Location{Path: "../secret", StartLine: 1}); link != "" {
		t.Errorf("traversing location produced %q", link)
	}
}

func TestEvidenceSanitizationIsSharedByEveryFormat(t *testing.T) {
	report := sampleReport()
	report.Results[0].Findings[0].Evidence = `password = "correct horse battery staple 🔐"`
	report.Results[0].Findings[0].Locations[0].Evidence = report.Results[0].Findings[0].Evidence
	for _, format := range []string{"terminal", "json", "sarif", "html"} {
		var out bytes.Buffer
		if err := Write(&out, format, report); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if strings.Contains(out.String(), "correct horse") || !strings.Contains(out.String(), "REDACTED") || !utf8.Valid(out.Bytes()) {
			t.Errorf("%s leaked or corrupted evidence: %s", format, out.String())
		}
	}
}

func TestSourceDerivedSecretsAreRedactedAcrossFormats(t *testing.T) {
	report := sampleReport()
	token := "ghp_" + strings.Repeat("A", 36)
	report.Results[0].Target = "package-" + token
	report.Results[0].Resolved = "/tmp/" + token
	report.Results[0].Error = "backend reported " + token
	report.Results[0].Coverage.Warnings = []string{"warning: " + token}
	report.Results[0].Coverage.Skipped = []string{"path/" + token}
	report.Results[0].Source = &model.SourceInfo{RepositoryURL: "https://user:" + token + "@github.com/example/repo", Revision: strings.Repeat("a", 40)}
	report.Results[0].Findings[0].Message = "Non-lifecycle package script downloads content: " + token
	report.Results[0].Findings[0].Path = "scripts/" + token + ".js"
	report.Results[0].Findings[0].Remediation = "Rotate " + token
	report.Results[0].Findings[0].Locations[0].Path = "scripts/" + token + ".js"
	for _, format := range []string{"terminal", "json", "sarif", "html"} {
		var out bytes.Buffer
		if err := Write(&out, format, report); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if strings.Contains(out.String(), token) || !strings.Contains(out.String(), "REDACTED") {
			t.Errorf("%s leaked source-derived secret: %s", format, out.String())
		}
		if format != "terminal" && format != "html" && !json.Valid(out.Bytes()) {
			t.Errorf("%s output is not valid JSON", format)
		}
	}
}

func TestVerdictReasonUsesHighestPriorityFinding(t *testing.T) {
	report := sampleReport()
	report.Results[0].Verdict = model.VerdictDoNotRun
	report.Results[0].Findings = append([]model.Finding{{
		RuleID: "INFO-001", Category: "context", Severity: model.SeverityLow, Confidence: model.ConfidenceLow,
		Disposition: model.DispositionInformational, Context: "generated", Path: "generated.js", Line: 1,
		Occurrences: 1, Message: "context only", Fingerprint: "sha256:info",
	}}, report.Results[0].Findings...)
	report.Results[0].Findings[1].RuleID = "BLOCK-001"
	report.Results[0].Findings[1].Severity = model.SeverityCritical
	report.Results[0].Findings[1].Disposition = model.DispositionBlock
	var out bytes.Buffer
	if err := Write(&out, "terminal", report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "why: BLOCK-001") {
		t.Fatalf("wrong verdict reason: %s", out.String())
	}
}

func TestTerminalShowsCorrelationProvenance(t *testing.T) {
	report := sampleReport()
	report.Results[0].Findings[0].ContributingRuleIDs = []string{"EXEC-002", "EXFIL-001"}
	var out bytes.Buffer
	if err := Write(&out, "terminal", report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "contributing rules: EXEC-002, EXFIL-001") {
		t.Fatalf("missing correlation provenance: %s", out.String())
	}
}

func TestHumanReportsNeutralizeControlCharacters(t *testing.T) {
	report := sampleReport()
	report.Results[0].Target = "fixture\x1b[2J"
	report.Results[0].Findings[0].Message = "finding\x1b[31m"
	report.Results[0].Findings[0].Locations[0].Evidence = "evidence\x1b[2J"
	for _, format := range []string{"terminal", "html"} {
		var out bytes.Buffer
		if err := Write(&out, format, report); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out.Bytes(), []byte{0x1b}) || !strings.Contains(out.String(), "�") {
			t.Errorf("%s retained terminal controls: %q", format, out.String())
		}
	}
}

func TestRemoteSourceLinksArePinnedAndLocalLinksAreAbsent(t *testing.T) {
	report := sampleReport()
	report.Results[0].Source = &model.SourceInfo{RepositoryURL: "https://github.com/example/repo", Revision: strings.Repeat("a", 40)}
	var remote bytes.Buffer
	if err := Write(&remote, "html", report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(remote.String(), "https://github.com/example/repo/blob/"+strings.Repeat("a", 40)+"/file.txt#L2") {
		t.Fatal("missing pinned source link")
	}
	report.Results[0].Source = nil
	var local bytes.Buffer
	if err := Write(&local, "html", report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(local.String(), "file://") {
		t.Fatal("local report contains a file URL")
	}
}

func TestHTMLShowsSanitizedBackendErrorAndAllFindingFiles(t *testing.T) {
	report := sampleReport()
	report.Results[0].Verdict = model.VerdictIncomplete
	report.Results[0].Error = `docker failed <script>alert("secret")</script>`
	report.Results[0].Findings[0].Locations = []model.Location{
		{Path: "first.txt", StartLine: 2, Evidence: "one"},
		{Path: "second.txt", StartLine: 8, Evidence: "two"},
	}
	var out bytes.Buffer
	if err := Write(&out, "html", report); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, "The scan backend failed before completion") ||
		!strings.Contains(html, "&lt;script&gt;alert(&#34;secret&#34;)&lt;/script&gt;") {
		t.Fatalf("missing safely rendered backend error: %s", html)
	}
	if strings.Contains(html, "<script>alert") || !strings.Contains(html, `data-file="first.txt`) || !strings.Contains(html, "second.txt\">") {
		t.Fatalf("error or location escaped unsafely: %s", html)
	}
}

func TestHTMLKeepsFileListReadableWithoutJavaScript(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "html", sampleReport()); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, `<section data-view-panel="files"`) ||
		strings.Contains(html, `data-view-panel="files" aria-label="Files with findings for fixture" hidden`) ||
		!strings.Contains(html, `.review-controls { display: none;`) ||
		!strings.Contains(html, `.js .review-controls { display: block }`) {
		t.Fatal("report fallback does not expose the file list without JavaScript")
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", sampleReport()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestHTMLReportsRecordedScanModeWithoutGuessingLegacyMode(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"host", "Scan mode: host"},
		{"docker", "Scan mode: docker"},
		{"", "Scan mode: unknown (not recorded)"},
		{`<script>`, "Scan mode: &lt;script&gt;"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			report := sampleReport()
			report.Results[0].ScanMode = model.ScanMode(tc.mode)
			report.Results[0].Source = nil
			var out bytes.Buffer
			if err := Write(&out, "html", report); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tc.want) || !strings.Contains(out.String(), "Scanned commit: unavailable (not recorded)") {
				t.Fatalf("missing or guessed scan identity: %s", out.String())
			}
		})
	}
}
