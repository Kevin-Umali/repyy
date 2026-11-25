package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeSkipsNonRegistrySources(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ecosystem, name, spec string
		want                  Package
		ok                    bool
	}{
		{"npm", "express", "^4.19.2", Package{NPM, "express"}, true},
		{"npm", "@acme/ui", "~1.2.0", Package{NPM, "@acme/ui"}, true},
		{"npm", "JSONStream", "^1.3.5", Package{NPM, "JSONStream"}, true},
		{"npm", "local", "file:../local", Package{}, false},
		{"npm", "fork", "git+https://example.invalid/fork.git", Package{}, false},
		{"npm", "short", "someone/short", Package{}, false},
		{"npm", "aliased", "npm:real-package@1.0.0", Package{}, false},
		{"npm", "../escape", "1.0.0", Package{}, false},
		{"pip", "Fresh_Crypto.Tools", ">=0.1", Package{PyPI, "fresh-crypto-tools"}, true},
		{"pip", "python", "^3.11", Package{}, false},
		{"pip", "pkg", "@", Package{}, false},
		{"go", "golang.org/x/net", "v0.30.0", Package{}, false},
	}
	for _, tc := range cases {
		got, ok := Normalize(tc.ecosystem, tc.name, tc.spec)
		if ok != tc.ok || got != tc.want {
			t.Errorf("Normalize(%q, %q, %q) = %+v, %v; want %+v, %v", tc.ecosystem, tc.name, tc.spec, got, ok, tc.want, tc.ok)
		}
	}
}

func TestLookupEscapesScopedNPMNames(t *testing.T) {
	t.Parallel()
	var rawPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.0.0"},"time":{"created":"2020-01-01T00:00:00Z","1.0.0":"2020-01-01T00:00:00Z"}}`))
	}))
	defer server.Close()
	client := &Client{HTTP: server.Client(), NPMRegistry: server.URL}

	record, err := client.Lookup(context.Background(), Package{NPM, "@acme/ui"})

	if err != nil || record.Versions != 1 || record.Status != Published {
		t.Fatalf("lookup = %+v, %v", record, err)
	}
	if rawPath != "/@acme%2Fui" {
		t.Errorf("scoped name should be one path segment, got %q", rawPath)
	}
}

func TestLookupRejectsOversizedMetadata(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"readme":"`))
		chunk := []byte(strings.Repeat("a", 1<<20))
		for range maxMetadataBytes>>20 + 1 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	defer server.Close()
	client := &Client{HTTP: server.Client(), NPMRegistry: server.URL}

	_, err := client.Lookup(context.Background(), Package{NPM, "padded"})

	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized metadata should fail, got %v", err)
	}
}
