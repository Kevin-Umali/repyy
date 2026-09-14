package buildinfo

import (
	"bytes"
	"strings"
	"testing"
)

func TestDevelopmentIdentity(t *testing.T) {
	var b bytes.Buffer
	Write(&b, "0.5.0-dev", "test")
	for _, want := range []string{"repyy 0.5.0-dev\n", "commit: unknown", "built-by: development", "source: github.com/Kevin-Umali/repyy", "go: go", "build-date: unknown"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in %q", want, b.String())
		}
	}
	if value("") != "unknown" {
		t.Fatal("missing identity must remain unknown")
	}
}
