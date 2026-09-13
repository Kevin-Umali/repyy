package supplychain_test

import (
	"context"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestNPMNonRegistrySourcesAcrossDependencyScopesAndOverrides(t *testing.T) {
	findings := scanInertPackageFixture(t, "package.json", `{
  "optionalDependencies": {"optional": "github:team/fork#main"},
  "peerDependencies": {"peer": "file:../peer"},
  "overrides": {"outer": {"inner": "git+https://fixture.invalid/fork.git"}},
  "resolutions": {"another": "https://fixture.invalid/pkg.tgz"},
  "pnpm": {"overrides": {"last": "file:./last"}}
}`)
	if !hasRule(findings, "PKG-002") || !hasRule(findings, "PKG-008") {
		t.Fatalf("non-registry sources escaped review: %+v", findings)
	}
	finding, _ := ruleFinding(findings, "PKG-008")
	if finding.Severity != model.SeverityHigh || finding.Context != "manifest" {
		t.Fatalf("override risk was misclassified: %+v", finding)
	}
	benign := scanInertPackageFixture(t, "package.json", `{"dependencies":{"ordinary":"^1.2.3"},"overrides":{"ordinary":"1.2.4"},"resolutions":{"other":"^2.0.0"}}`)
	if hasRule(benign, "PKG-002") || hasRule(benign, "PKG-008") {
		t.Fatalf("registry versions were flagged as source redirects: %+v", benign)
	}
}

func TestNPMAliasIsReviewedByActualPackageName(t *testing.T) {
	findings := scanInertPackageFixture(t, "package.json", `{"dependencies":{"lodash":"npm:lodahs@1.0.0"},"overrides":{"safe":"npm:other@1.0.0"}}`)
	for _, id := range []string{"PKG-009", "PKG-008"} {
		if !hasRule(findings, id) {
			t.Errorf("npm alias escaped %s: %+v", id, findings)
		}
	}
	identifiedTarget := false
	for _, finding := range findings {
		if strings.HasPrefix(finding.RuleID, "IOC-PKG-") && strings.Contains(finding.Evidence, "lodahs 1.0.0") {
			identifiedTarget = true
		}
	}
	if !identifiedTarget {
		t.Fatalf("alias target was not checked against package intelligence: %+v", findings)
	}
	benign := scanInertPackageFixture(t, "package.json", `{"dependencies":{"same":"npm:same@1.0.0"}}`)
	if hasRule(benign, "PKG-009") {
		t.Fatalf("same-name alias was treated as identity change: %+v", benign)
	}
}

func TestPipAlternateLookupSourcesAndBenignLocalOptions(t *testing.T) {
	for _, tc := range []struct {
		path, body string
		want       bool
	}{
		{"requirements-dev.txt", "--extra-index-url https://fixture.invalid/simple\nrequests==2.0\n", true},
		{"pip.conf", "[global]\nextra-index-url = https://fixture.invalid/simple\n", true},
		{"Pipfile", "[[source]]\nurl = 'https://fixture.invalid/simple'\nname = 'fixture'\n", true},
		{"pyproject.toml", "[[tool.uv.index]]\nname = 'fixture'\nurl = 'https://fixture.invalid/simple'\n", true},
		{"uv.toml", "index-strategy = 'unsafe-best-match'\n", true},
		{"requirements-dev.txt", "--index-url https://pypi.org/simple\n--find-links ./wheelhouse\n", false},
		{"pyproject.toml", "[[tool.uv.index]]\nurl = 'https://pypi.org/simple'\n", false},
		{"pip.conf", "[global]\n# extra-index-url = https://fixture.invalid/simple\n", false},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			findings := scanInertPackageFixture(t, tc.path, tc.body)
			if hasRule(findings, "PY-003") != tc.want {
				t.Fatalf("unexpected pip source decision: %+v", findings)
			}
		})
	}
}

func TestYarnRuntimeConfigurationAndPassiveConfiguration(t *testing.T) {
	findings := scanInertPackageFixture(t, ".yarnrc.yml", "yarnPath: ./tools/yarn.cjs\nplugins:\n  - path: .yarn/plugins/review.cjs\n    spec: review-plugin\n")
	if !hasRule(findings, "YARN-001") || !hasRule(findings, "YARN-002") {
		t.Fatalf("Yarn executable or plugin escaped review: %+v", findings)
	}
	benign := scanInertPackageFixture(t, ".yarnrc.yml", "nodeLinker: node-modules\n")
	if hasRule(benign, "YARN-001") || hasRule(benign, "YARN-002") {
		t.Fatalf("passive Yarn configuration was flagged: %+v", benign)
	}
	redirected := scanInertPackageFixture(t, ".yarnrc.yml", "yarnPath: ../outside/yarn.cjs\n")
	finding, ok := ruleFinding(redirected, "YARN-001")
	if !ok || finding.Severity != model.SeverityHigh {
		t.Fatalf("escaping Yarn binary was not elevated: %+v", redirected)
	}
}

func TestRubyComposerAndNuGetSourceRedirection(t *testing.T) {
	cases := []struct {
		path, positive, negative string
		want                     []string
	}{
		{"Gemfile", "source 'https://gems.fixture.invalid'\ngem 'safe', '1.0'\n", "source 'https://rubygems.org'\ngem 'safe', '1.0'\n", []string{"RUBY-002"}},
		{".bundle/config", "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG: https://fixture.invalid\n", "BUNDLE_PATH: vendor/bundle\n", []string{"RUBY-002"}},
		{"composer.json", `{"repositories":[{"type":"vcs","url":"https://fixture.invalid/fork"}],"config":{"allow-plugins":true}}`, `{"repositories": [],"config":{"allow-plugins":false}}`, []string{"PHP-002", "PHP-003"}},
		{"NuGet.Config", `<configuration><packageSources><add key="mirror" value="https://fixture.invalid/v3/index.json" /></packageSources><packageSourceMapping><packageSource key="mirror"><package pattern="*" /></packageSource></packageSourceMapping></configuration>`, `<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>`, []string{"NUGET-001"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			findings := scanInertPackageFixture(t, tc.path, tc.positive)
			for _, id := range tc.want {
				if !hasRule(findings, id) {
					t.Errorf("missing %s in positive fixture: %+v", id, findings)
				}
			}
			benign := scanInertPackageFixture(t, tc.path, tc.negative)
			for _, id := range tc.want {
				if hasRule(benign, id) {
					t.Errorf("flagged benign %s: %+v", id, benign)
				}
			}
		})
	}
}

func TestImplicitCargoBuildScriptRequiresPackageManifest(t *testing.T) {
	for _, tc := range []struct {
		name, manifest string
		want           bool
	}{
		{"implicit build script", "[package]\nname = 'fixture'\nversion = '0.1.0'\n", true},
		{"disabled build script", "[package]\nname = 'fixture'\nversion = '0.1.0'\nbuild = false\n", false},
		{"explicit other build script", "[package]\nname = 'fixture'\nversion = '0.1.0'\nbuild = 'scripts/custom.rs'\n", false},
		{"no manifest", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "Inert fixture\n")
			writeFixture(t, root, "LICENSE", "Inert fixture\n")
			writeFixture(t, root, "build.rs", "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n")
			if tc.manifest != "" {
				writeFixture(t, root, "Cargo.toml", tc.manifest)
			}
			_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
			if hasRule(findings, "RUST-002") != tc.want {
				t.Fatalf("unexpected build.rs decision: %+v", findings)
			}
		})
	}
}

func TestGoWorkspaceReplacementBlockAndOrdinaryUse(t *testing.T) {
	redirected := scanInertPackageFixture(t, "go.work", "go 1.22\nreplace (\n  example.invalid/library => ../fork\n)\n")
	if !hasRule(redirected, "GO-002") {
		t.Fatalf("go.work replacement escaped review: %+v", redirected)
	}
	ordinary := scanInertPackageFixture(t, "go.work", "go 1.22\nuse ./module\n")
	if hasRule(ordinary, "GO-002") {
		t.Fatalf("ordinary workspace use was flagged: %+v", ordinary)
	}
}

func TestMSBuildDirectoryTargetsExecutionAndPassiveTarget(t *testing.T) {
	active := scanInertPackageFixture(t, "Directory.Build.targets", `<Project><Target Name="Fixture" BeforeTargets="Build"><Exec Command="echo inert-fixture" /></Target></Project>`)
	if !hasRule(active, "DOTNET-001") {
		t.Fatalf("MSBuild command escaped review: %+v", active)
	}
	passive := scanInertPackageFixture(t, "Directory.Build.targets", `<Project><Target Name="Fixture" BeforeTargets="Build"><Message Text="inert fixture" /></Target></Project>`)
	if hasRule(passive, "DOTNET-001") {
		t.Fatalf("passive MSBuild target was flagged: %+v", passive)
	}
}

func TestNuGetConfigurationCasingDoesNotHidePackageSource(t *testing.T) {
	findings := scanInertPackageFixture(t, "NUGET.CONFIG", `<Configuration><PackageSources><Add KEY="Mirror" VALUE="https://fixture.invalid/v3/index.json" /></PackageSources><PackageSourceMapping><PackageSource KEY="mirror"><Package PATTERN="*" /></PackageSource></PackageSourceMapping></Configuration>`)
	finding, ok := ruleFinding(findings, "NUGET-001")
	if !ok || finding.Severity != model.SeverityHigh {
		t.Fatalf("mixed-case NuGet source escaped review: %+v", findings)
	}
}

func TestUndecodableSupplyChainConfigurationIsIncomplete(t *testing.T) {
	for _, path := range []string{"NuGet.Config", "go.work", "gradle/wrapper/gradle-wrapper.properties", ".bundle/config", "Directory.Build.targets"} {
		t.Run(path, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "Inert fixture\n")
			writeFixture(t, root, "LICENSE", "Inert fixture\n")
			writeFixture(t, root, path, "\x00not-readable-text")
			coverage, _ := scan.New(scan.Options{}).Scan(context.Background(), root)
			if coverage.Complete {
				t.Fatal("undecodable supply-chain configuration was treated as clean")
			}
		})
	}
}
