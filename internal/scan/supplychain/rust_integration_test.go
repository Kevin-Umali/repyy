package supplychain_test

import (
	"context"
	"github.com/Kevin-Umali/repyy/internal/scan"
	"testing"
)

func TestRustSupplyChainDetectsRegistryRedirectionAndDependencyOverrides(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "Cargo.toml", `[package]
name = "fixture"
version = "0.1.0"

[patch.crates-io]
fixture-dependency = { git = "https://example.invalid/fixture.git", rev = "0123456789abcdef" }

[replace]
"fixture:0.1.0" = { path = "vendor/fixture" }
`)
	writeFixture(t, root, ".cargo/config.toml", `[source.crates-io]
replace-with = "fixture-mirror"

[source.fixture-mirror]
registry = "https://example.invalid/index"

[registries.fixture]
index = "https://example.invalid/registry-index"
`)

	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	for _, id := range []string{"RUST-003", "RUST-004"} {
		if !hasRule(findings, id) {
			t.Errorf("missing %s in %+v", id, findings)
		}
	}
	finding, ok := ruleFinding(findings, "RUST-003")
	if !ok || finding.Occurrences != 3 {
		t.Fatalf("registry redirects were not fully counted: %+v", finding)
	}
	finding, ok = ruleFinding(findings, "RUST-004")
	if !ok || finding.Occurrences != 2 {
		t.Fatalf("dependency overrides were not fully counted: %+v", finding)
	}
}

func TestRustSupplyChainIgnoresOrdinaryCargoConfiguration(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "Cargo.toml", `[package]
name = "clean"
version = "0.1.0"

[dependencies]
serde = "1"
`)
	writeFixture(t, root, ".cargo/config.toml", `[net]
git-fetch-with-cli = true
`)

	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	for _, finding := range findings {
		if finding.RuleID == "RUST-003" || finding.RuleID == "RUST-004" {
			t.Fatalf("benign or disabled Rust configuration was flagged: %+v", finding)
		}
	}
}

func TestRustDependencyGitAndPathSourcesAreReviewed(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "Cargo.toml", `[package]
name = "fixture"
version = "0.1.0"

[dependencies]
serde = "1"
remote = { git = "https://fixture.invalid/remote.git", rev = "0123456789abcdef" }

[build-dependencies.local]
path = "../fork"
`)
	_, findings := scan.New(scan.Options{}).Scan(context.Background(), root)
	finding, ok := ruleFinding(findings, "RUST-005")
	if !ok || finding.Occurrences != 2 {
		t.Fatalf("Cargo dependency sources escaped review: %+v", findings)
	}
}
