package manifest

import "testing"

func TestParseSupportedManifests(t *testing.T) {
	tests := []struct{ path, body, ecosystem, name, version string }{
		{"package.json", `{"dependencies":{"cors-parser":"1.0.0"}}`, "npm", "cors-parser", "1.0.0"},
		{"requirements.txt", "openaii==1.2.3\n", "pip", "openaii", "==1.2.3"},
		{"go.mod", "module x\nrequire github.com/utilizedsun/layout v1.0.0\n", "go", "github.com/utilizedsun/layout", "v1.0.0"},
		{"Cargo.toml", "[dependencies]\ntinymember = \"1.0.0\"\n", "rust", "tinymember", "1.0.0"},
		{"pom.xml", `<project><dependencies><dependency><groupId>org.mvnpm</groupId><artifactId>posthog-node</artifactId><version>1.0.0</version></dependency></dependencies></project>`, "maven", "org.mvnpm:posthog-node", "1.0.0"},
		{"Gemfile", "gem 'rack', '1.0.0'\n", "rubygems", "rack", "1.0.0"},
		{"composer.json", `{"require":{"vendor/pkg":"1.0.0"}}`, "composer", "vendor/pkg", "1.0.0"},
		{"packages.config", `<packages><package id="StripeApi.Net" version="1.0.0"/></packages>`, "nuget", "StripeApi.Net", "1.0.0"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got, ok := Parse(tc.path, []byte(tc.body))
			if !ok || len(got) != 1 || got[0].Ecosystem != tc.ecosystem || got[0].Name != tc.name || got[0].Version != tc.version || got[0].Line < 1 {
				t.Fatalf("got %#v, supported=%v", got, ok)
			}
		})
	}
}

func TestUnknownFile(t *testing.T) {
	if got, ok := Parse("README.md", []byte("x")); ok || got != nil {
		t.Fatalf("got %#v, %v", got, ok)
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
