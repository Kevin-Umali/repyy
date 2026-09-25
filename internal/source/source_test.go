package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareLocalDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A supplied .git directory must never cause local preparation to run Git.
	t.Setenv("PATH", t.TempDir())
	p, err := Prepare(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Remote || p.Path == "" {
		t.Fatalf("unexpected prepared target: %+v", p)
	}
}

func TestPrepareCanonicalizesDirectorySymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "review")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	prepared, err := Prepare(context.Background(), link, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Path != want || prepared.Target != link {
		t.Fatalf("symlink target lost or unresolved: %+v", prepared)
	}
}

func TestSecureGitEnvironmentIsNonInteractive(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret-for-test")
	t.Setenv("GIT_SSH_COMMAND", "malicious-helper")
	t.Setenv("GIT_SSL_NO_VERIFY", "1")
	t.Setenv("GIT_EXEC_PATH", "/tmp/untrusted-git-helpers")
	t.Setenv("GIT_CONFIG_COUNT", "99")
	env := secureGitEnv("https://github.com/org/private.git")
	want := map[string]bool{"GIT_CONFIG_NOSYSTEM=1": false, "GIT_TERMINAL_PROMPT=0": false, "GIT_ALLOW_PROTOCOL=https": false, "GIT_PROTOCOL_FROM_USER=0": false, "GCM_INTERACTIVE=Never": false}
	for _, item := range env {
		if _, ok := want[item]; ok {
			want[item] = true
		}
		if item == "GIT_SSH_COMMAND=malicious-helper" || item == "GIT_SSL_NO_VERIFY=1" ||
			item == "GIT_EXEC_PATH=/tmp/untrusted-git-helpers" || item == "GIT_CONFIG_COUNT=99" {
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

func TestSecureGitEnvironmentAllowsOnlyRequestedSSHProtocol(t *testing.T) {
	env := secureGitEnv("git@example.com:team/repo.git")
	for _, item := range env {
		if item == "GIT_ALLOW_PROTOCOL=ssh" {
			return
		}
	}
	t.Fatal("SSH clone did not restrict Git to the SSH protocol")
}

func TestRejectsRemoteURLsContainingSecretsWithoutLeakingThem(t *testing.T) {
	for _, tc := range []struct {
		input   string
		secrets []string
	}{
		{"https://user:secret@example.com/repo.git", []string{"secret"}},
		{"https://example.com/repo.git?token=secret#fragment", []string{"secret", "token=", "#fragment"}},
	} {
		_, err := Prepare(context.Background(), tc.input, Options{})
		if err == nil {
			t.Errorf("expected rejection for %q", tc.input)
			continue
		}
		for _, secret := range tc.secrets {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("rejection leaked %q: %v", secret, err)
			}
		}
	}
}

func TestCanonicalRemoteURL(t *testing.T) {
	for input, want := range map[string]string{
		"https://github.com/Example/Repo.git":   "https://github.com/Example/Repo",
		"git@gitlab.com:group/repo.git":         "https://gitlab.com/group/repo",
		"ssh://git@bitbucket.org/team/repo.git": "https://bitbucket.org/team/repo",
	} {
		if got := canonicalRemoteURL(input); got != want {
			t.Errorf("canonicalRemoteURL(%q) = %q, want %q", input, got, want)
		}
	}
}
