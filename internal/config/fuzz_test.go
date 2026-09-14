package config

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzConfiguration(f *testing.F) {
	f.Add([]byte("version: 1\nrules: []\n"))
	f.Add([]byte("version: 999\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		file := filepath.Join(t.TempDir(), "rules.yaml")
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(file)
		if err == nil && cfg.Version != 1 {
			t.Fatal("accepted unsupported configuration version")
		}
	})
}
