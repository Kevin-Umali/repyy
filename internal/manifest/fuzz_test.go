package manifest

import "testing"

func FuzzManifests(f *testing.F) {
	f.Add([]byte(`{"dependencies":{"example":"1.0.0"}}`), uint8(0))
	f.Add([]byte("[dependencies]\nexample = \"1.0\"\n"), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, kind uint8) {
		if len(data) > 8192 {
			t.Skip()
		}
		names := []string{"package.json", "Cargo.toml", "pom.xml", "requirements.txt", "pyproject.toml", "go.mod", "Gemfile", "composer.json"}
		deps, supported := Parse(names[int(kind)%len(names)], data)
		if !supported {
			t.Fatal("known manifest became unsupported")
		}
		for _, dep := range deps {
			if dep.Line < 0 {
				t.Fatal("negative source location")
			}
		}
	})
}
