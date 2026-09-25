package manifest

import "testing"

func TestParseSupportedAndUnknownManifests(t *testing.T) {
	tests := []struct{ path, body, ecosystem, name, version string }{
		{"package.json", `{"dependencies":{"cors-parser":"1.0.0"}}`, "npm", "cors-parser", "1.0.0"},
		{"requirements.txt", "openaii==1.2.3\n", "pip", "openaii", "==1.2.3"},
		{"go.mod", "module x\nrequire github.com/utilizedsun/layout v1.0.0\n", "go", "github.com/utilizedsun/layout", "v1.0.0"},
		{"Cargo.toml", "[dependencies]\ntinymember = \"1.0.0\"\n", "rust", "tinymember", "1.0.0"},
		{"pom.xml", `<project><dependencies><dependency><groupId>org.mvnpm</groupId><artifactId>posthog-node</artifactId><version>1.0.0</version></dependency></dependencies></project>`, "maven", "org.mvnpm:posthog-node", "1.0.0"},
		{"Gemfile", "gem 'rack', '1.0.0'\n", "rubygems", "rack", "1.0.0"},
		{"composer.json", `{"require":{"vendor/pkg":"1.0.0"}}`, "composer", "vendor/pkg", "1.0.0"},
		{"packages.config", `<packages><package id="StripeApi.Net" version="1.0.0"/></packages>`, "nuget", "StripeApi.Net", "1.0.0"},
		{"Directory.Packages.props", `<Project><ItemGroup><PackageVersion Include="StripeApi.Net" Version="1.0.0" /></ItemGroup></Project>`, "nuget", "StripeApi.Net", "1.0.0"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got, ok := Parse(tc.path, []byte(tc.body))
			if !ok || len(got) != 1 || got[0].Ecosystem != tc.ecosystem || got[0].Name != tc.name || got[0].Version != tc.version || got[0].Line < 1 {
				t.Fatalf("got %#v, supported=%v", got, ok)
			}
		})
	}
	if got, ok := Parse("README.md", []byte("x")); ok || got != nil {
		t.Fatalf("unknown file parsed: %#v, supported=%v", got, ok)
	}
}

func TestDeclarationLineUsesIdentifierBoundaries(t *testing.T) {
	data := []byte("{\n  \"foobar\": \"1.0.0\",\n  \"foo\": \"2.0.0\"\n}\n")
	if got := DeclarationLine(data, "foo"); got != 3 {
		t.Fatalf("DeclarationLine(foo) = %d, want 3", got)
	}
	if got := DeclarationLine(data, "foobar"); got != 2 {
		t.Fatalf("DeclarationLine(foobar) = %d, want 2", got)
	}
}

func TestNPMAliasExposesResolvedPackageIdentity(t *testing.T) {
	data := []byte(`{"dependencies":{"expected":"npm:@fixture/actual@1.2.3"}}`)
	got, ok := Parse("package.json", data)
	if !ok || len(got) != 2 {
		t.Fatalf("npm alias target was not parsed: %+v", got)
	}
	for _, dependency := range got {
		if dependency.Name == "@fixture/actual" {
			if dependency.Version != "1.2.3" || dependency.Alias != "expected" || dependency.Line != 1 {
				t.Fatalf("alias target lost provenance: %+v", dependency)
			}
			return
		}
	}
	t.Fatalf("actual npm package identity missing: %+v", got)
}
