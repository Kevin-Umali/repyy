package intel

import "testing"

func TestDatabasePackageMatching(t *testing.T) {
	d := Builtin()
	if got := d.MatchPackage("npm", "tailwind-form-kit", "1.0.0"); len(got) != 1 {
		t.Fatalf("expected package match, got %#v", got)
	}
	if got := d.MatchPackage("npm", "call-bind-apply-helpers", "1.0.2"); len(got) != 0 {
		t.Fatalf("known-benign package was blocklisted: %#v", got)
	}
}

func TestDatabasePackageMatchingIsUnaffectedByCallerMutation(t *testing.T) {
	packages := []Package{{Ecosystem: "npm", Name: "sample", Affected: []string{"= 1.0.0"}, References: []string{"https://example.invalid/advisory"}}}
	database := NewDatabase(packages, nil)
	packages[0].Affected[0] = "= 2.0.0"
	packages[0].References[0] = "changed source"
	matched := database.MatchPackage("npm", "sample", "1.0.0")
	if len(matched) != 1 || !matched[0].VersionMatched || matched[0].Indicator.References[0] != "https://example.invalid/advisory" {
		t.Fatalf("caller changed indexed package metadata: %+v", matched)
	}
	matched[0].Indicator.Affected[0] = "= 3.0.0"
	matched[0].Indicator.References[0] = "changed result"
	again := database.MatchPackage("npm", "sample", "1.0.0")
	if len(again) != 1 || !again[0].VersionMatched || again[0].Indicator.References[0] != "https://example.invalid/advisory" {
		t.Fatalf("returned match changed indexed package metadata: %+v", again)
	}
}

func TestDatabaseHashMatchingIsUnaffectedByCallerMutation(t *testing.T) {
	hashes := []FileHash{{SHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", References: []string{"https://example.invalid/report"}}}
	database := NewDatabase(nil, hashes)
	hashes[0].References[0] = "changed source"
	matched, ok := database.MatchHash([]byte("test"))
	if !ok || matched.References[0] != "https://example.invalid/report" {
		t.Fatalf("caller changed indexed hash provenance: %+v", matched)
	}
	matched.References[0] = "changed result"
	again, ok := database.MatchHash([]byte("test"))
	if !ok || again.References[0] != "https://example.invalid/report" {
		t.Fatalf("returned match changed indexed hash provenance: %+v", again)
	}
}

func TestAffectedExactAndAllVersions(t *testing.T) {
	if !affected("1.2.3", []string{"= 1.2.3"}) {
		t.Fatal("exact version should match")
	}
	if affected("^1.2.3", []string{"= 1.2.3"}) || affected("1.2.4", []string{"= 1.2.3"}) {
		t.Fatal("different version matched")
	}
	if !rangeCanInclude("^1.14.0", []string{"= 1.14.1", "= 0.30.4"}) || rangeCanInclude("^2.0.0", []string{"= 1.14.1"}) {
		t.Fatal("caret range exposure was misclassified")
	}
	if rangeCanInclude("^0.0.3", []string{"= 0.0.4"}) || !rangeCanInclude("^0.0.3", []string{"= 0.0.3"}) {
		t.Fatal("zero-major caret range crossed its patch boundary")
	}
	if !affected("2.0.0", []string{">= 0"}) {
		t.Fatal("all-version advisory did not match")
	}
	if !affected("1.0.1", []string{"<= 1.0.1"}) || affected("1.0.2", []string{"<= 1.0.1"}) {
		t.Fatal("ordered range matching failed")
	}
}
