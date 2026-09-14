// Package source safely prepares local and remote repositories for inspection.
package source

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Options controls safe remote-history depth and checkout retention.
type Options struct {
	History string
	Keep    bool
}

// Prepared is a local scan target and an idempotent cleanup function.
type Prepared struct {
	Target        string
	Path          string
	Remote        bool
	RepositoryURL string
	Revision      string
	Cleanup       func() error
}

// Prepare validates a local directory or clones a remote without running hooks.
func Prepare(ctx context.Context, target string, opts Options) (Prepared, error) {
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		abs, err := filepath.Abs(target)
		if err != nil {
			return Prepared{}, err
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return Prepared{}, fmt.Errorf("resolve local target: %w", err)
		}
		return Prepared{Target: target, Path: resolved, Cleanup: func() error { return nil }}, nil
	}
	if !isRemote(target) {
		return Prepared{}, fmt.Errorf("target is neither a local directory nor a supported Git URL")
	}
	if hasURLCredentials(target) {
		return Prepared{}, fmt.Errorf("credentials in Git URLs are not allowed; use an SSH agent or provider token environment variable")
	}
	if hasURLQueryOrFragment(target) {
		return Prepared{}, fmt.Errorf("query strings and fragments in Git URLs are not allowed; use a provider token environment variable")
	}
	tmp, err := os.MkdirTemp("", "repyy-clone-*")
	if err != nil {
		return Prepared{}, fmt.Errorf("create isolated checkout: %w", err)
	}
	cleanup := func() error {
		if opts.Keep {
			return nil
		}
		return os.RemoveAll(tmp)
	}
	dest := filepath.Join(tmp, "repo")
	args := []string{"-c", "core.hooksPath=" + nullDevice(), "-c", "protocol.file.allow=never", "-c", "http.followRedirects=false", "clone", "--no-recurse-submodules", "--template=", "--config", "core.hooksPath=" + nullDevice()}
	switch opts.History {
	case "", "1":
		args = append(args, "--depth", "1")
	case "all":
	default:
		args = append(args, "--depth", opts.History)
	}
	args = append(args, "--", target, dest)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = secureGitEnv(target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return Prepared{}, errors.Join(fmt.Errorf("safe clone failed: %s", sanitizeGitError(string(output))), removeFailedCheckout(tmp))
	}
	revisionCmd := exec.CommandContext(ctx, "git", "-c", "core.hooksPath="+nullDevice(), "-C", dest, "rev-parse", "HEAD")
	revisionCmd.Env = secureGitEnv(target)
	revisionOutput, err := revisionCmd.Output()
	if err != nil {
		return Prepared{}, errors.Join(fmt.Errorf("resolve cloned revision: %w", err), removeFailedCheckout(tmp))
	}
	return Prepared{
		Target: target, Path: dest, Remote: true,
		RepositoryURL: canonicalRemoteURL(target),
		Revision:      strings.TrimSpace(string(revisionOutput)),
		Cleanup:       cleanup,
	}, nil
}

func canonicalRemoteURL(target string) string {
	if strings.HasPrefix(target, "git@") {
		parts := strings.SplitN(strings.TrimPrefix(target, "git@"), ":", 2)
		if len(parts) == 2 {
			return "https://" + strings.ToLower(parts[0]) + "/" + strings.TrimSuffix(parts[1], ".git")
		}
		return ""
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	if u.Scheme != "https" && u.Scheme != "ssh" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	path := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), ".git")
	if path == "" {
		return ""
	}
	return "https://" + host + "/" + path
}

func isRemote(v string) bool {
	if strings.HasPrefix(v, "git@") || strings.HasPrefix(v, "ssh://") {
		return true
	}
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func secureGitEnv(target string) []string {
	env := filteredGitEnv(os.Environ())
	protocol := "https"
	if strings.HasPrefix(target, "git@") || strings.HasPrefix(target, "ssh://") {
		protocol = "ssh"
	}
	env = append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+nullDevice(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL="+protocol,
		"GIT_PROTOCOL_FROM_USER=0",
		"GCM_INTERACTIVE=Never",
		"SSH_ASKPASS_REQUIRE=never",
	)
	host, token := tokenFor(target)
	if token != "" {
		auth := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http.https://"+host+"/.extraHeader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+auth,
		)
	}
	return env
}

func filteredGitEnv(input []string) []string {
	out := make([]string, 0, len(input))
	for _, item := range input {
		name, _, _ := strings.Cut(item, "=")
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "GIT_") || upper == "SSH_ASKPASS" || upper == "SSH_ASKPASS_REQUIRE" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func tokenFor(target string) (string, string) {
	u, err := url.Parse(target)
	if err != nil {
		return "", ""
	}
	switch strings.ToLower(u.Hostname()) {
	case "github.com":
		return "github.com", os.Getenv("GITHUB_TOKEN")
	case "gitlab.com":
		return "gitlab.com", os.Getenv("GITLAB_TOKEN")
	case "bitbucket.org":
		return "bitbucket.org", os.Getenv("BITBUCKET_TOKEN")
	default:
		return "", ""
	}
}

func hasURLCredentials(target string) bool {
	u, err := url.Parse(target)
	return err == nil && u.User != nil
}

func hasURLQueryOrFragment(target string) bool {
	u, err := url.Parse(target)
	return err == nil && (u.RawQuery != "" || u.Fragment != "")
}

func nullDevice() string {
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

func sanitizeGitError(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 500 {
		v = v[len(v)-500:]
	}
	for _, name := range []string{"GITHUB_TOKEN", "GITLAB_TOKEN", "BITBUCKET_TOKEN"} {
		if token := os.Getenv(name); token != "" {
			v = strings.ReplaceAll(v, token, "[REDACTED]")
		}
	}
	return v
}

func removeFailedCheckout(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return errors.New("temporary checkout cleanup failed; private files may remain in the system temporary directory")
	}
	return nil
}
