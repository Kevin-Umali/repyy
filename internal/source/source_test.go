package source

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestPrepareLocalDirectory(t *testing.T) {
	dir := t.TempDir()
	p, err := Prepare(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Remote || p.Path == "" {
		t.Fatalf("unexpected prepared target: %+v", p)
	}
}

func TestSecureGitEnvironmentIsNonInteractive(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret-for-test")
	t.Setenv("GIT_SSH_COMMAND", "malicious-helper")
	env := secureGitEnv("https://github.com/org/private.git")
	want := map[string]bool{"GIT_CONFIG_NOSYSTEM=1": false, "GIT_TERMINAL_PROMPT=0": false, "GCM_INTERACTIVE=Never": false}
	for _, item := range env {
		if _, ok := want[item]; ok {
			want[item] = true
		}
		if item == "GIT_SSH_COMMAND=malicious-helper" {
			t.Fatal("inherited Git execution setting was not removed")
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("missing %s", key)
		}
	}
	if got := os.Getenv("GITHUB_TOKEN"); got != "secret-for-test" {
		t.Fatal("test setup changed")
	}
}

func TestRejectsCredentialsInURL(t *testing.T) {
	_, err := Prepare(context.Background(), "https://user:secret@example.com/repo.git", Options{})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("expected redacted rejection, got %v", err)
	}
}
