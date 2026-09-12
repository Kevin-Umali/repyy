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

func TestAffectedExactAndAllVersions(t *testing.T) {
	if !affected("^1.2.3", []string{"= 1.2.3"}) {
		t.Fatal("exact version should match")
	}
	if affected("^1.2.4", []string{"= 1.2.3"}) {
		t.Fatal("different version matched")
	}
	if !affected("2.0.0", []string{">= 0"}) {
		t.Fatal("all-version advisory did not match")
	}
	if !affected("1.0.1", []string{"<= 1.0.1"}) || affected("1.0.2", []string{"<= 1.0.1"}) {
		t.Fatal("ordered range matching failed")
	}
}
