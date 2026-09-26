// Package sandbox runs scans in a narrowly configured Docker container.
package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
)

// ImageDigest is injected by release builds with -ldflags. Development builds
// fail closed until a release image digest is supplied.
var ImageDigest = ""

const imageRepository = "ghcr.io/kevin-umali/repyy-sandbox"

const maxJSON = 16 << 20

var pinnedImage = regexp.MustCompile(`^(?:[^:@]+(?:/[^:@]+)*:[^@]+|[^:@]+(?:/[^:@]+)*)@sha256:[a-f0-9]{64}$`)
var gitRevision = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)

type Options struct {
	Image               string
	Version             string
	Timeout             time.Duration
	History             string
	IncludeDependencies bool
	MaxFiles            int
	MaxFileBytes        int64
	Config              string
}

// Preflight verifies Docker and that the exact digest-pinned image is locally
// available. It intentionally does not pull images implicitly.
func Preflight(ctx context.Context, opts Options) error {
	image := resolveImage(opts)
	if !pinnedImage.MatchString(image) {
		if image == "" {
			return errors.New("sandbox image is unavailable in this build; install a release with a signed image digest")
		}
		return errors.New("sandbox image must be digest-pinned")
	}
	if opts.Version != "" && imageHasTag(image) && !imageVersion(image, opts.Version) {
		return fmt.Errorf("sandbox image must match repyy version %s", opts.Version)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("Docker is required for --sandbox=docker; install Docker and pull the version-matched image explicitly")
	}
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", image)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sandbox image is not available locally; pull it explicitly: %s", image)
	}
	return nil
}

func imageVersion(image, version string) bool {
	tag := image[strings.LastIndex(image, "/")+1:]
	tag = tag[:strings.IndexByte(tag, '@')]
	return strings.TrimPrefix(tag, "v") == strings.TrimPrefix(version, "v")
}

func imageHasTag(image string) bool {
	name := image[:strings.IndexByte(image, '@')]
	return strings.Contains(name[strings.LastIndex(name, "/")+1:], ":")
}

func resolveImage(opts Options) string {
	if opts.Image != "" {
		return opts.Image
	}
	if ImageDigest != "" {
		return imageRepository + "@" + ImageDigest
	}
	return ""
}

// Scan executes the worker image and accepts only a bounded JSON report.
// Local paths are mounted read-only and scanned with networking disabled.
// HTTPS remotes are fetched in a temporary networked stage, then scanned
// from a read-only mount in a second, network-disabled container.
func Scan(ctx context.Context, target string, opts Options) (result model.RepoResult, scanErr error) {
	image := resolveImage(opts)
	if strings.HasPrefix(target, "git@") || strings.HasPrefix(target, "ssh://") {
		return model.RepoResult{}, errors.New("SSH URLs are not supported by Docker sandbox; use an HTTPS Git URL")
	}
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		abs, err := filepath.Abs(target)
		if err != nil {
			return model.RepoResult{}, err
		}
		return runContainer(ctx, image, abs, false, opts)
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return model.RepoResult{}, errors.New("sandbox target must be a local directory or HTTPS Git URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return model.RepoResult{}, errors.New("credentials, query strings, and fragments are not allowed in sandbox Git URLs")
	}
	tmp, err := os.MkdirTemp("", "repyy-sandbox-*")
	if err != nil {
		return model.RepoResult{}, err
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			const warning = "temporary sandbox checkout cleanup failed; private files may remain in the system temporary directory"
			if scanErr != nil {
				scanErr = errors.Join(scanErr, errors.New(warning))
			} else {
				result.Coverage.Complete = false
				result.Verdict = model.VerdictIncomplete
				result.Coverage.Warnings = append(result.Coverage.Warnings, warning)
			}
		}
	}()
	stageDir := filepath.Join(tmp, "stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return model.RepoResult{}, err
	}
	// The private parent is only accessible to the host user. Docker mounts
	// this child directly, so the unprivileged container user can clone into it.
	if err := os.Chmod(stageDir, 0o777); err != nil {
		return model.RepoResult{}, err
	}
	revision, err := fetch(ctx, image, target, stageDir, opts)
	if err != nil {
		return model.RepoResult{}, err
	}
	result, err = runContainer(ctx, image, filepath.Join(stageDir, "repo"), true, opts)
	if err != nil {
		return model.RepoResult{}, err
	}
	result.Source = &model.SourceInfo{RepositoryURL: canonicalURL(target), Revision: revision}
	return result, nil
}

func canonicalURL(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return "https://" + strings.ToLower(u.Hostname()) + "/" + strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), ".git")
}

func tokenFor(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Hostname()) {
	case "github.com":
		return os.Getenv("GITHUB_TOKEN")
	case "gitlab.com":
		return os.Getenv("GITLAB_TOKEN")
	case "bitbucket.org":
		return os.Getenv("BITBUCKET_TOKEN")
	default:
		return ""
	}
}

func fetch(ctx context.Context, image, target, tmp string, opts Options) (revision string, fetchErr error) {
	args := []string{"run", "--rm", "--network", "bridge", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "1g", "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,mode=1777", "--env", "GIT_CONFIG_NOSYSTEM=1", "--env", "GIT_CONFIG_GLOBAL=/dev/null", "--env", "GIT_TERMINAL_PROMPT=0", "--env", "GIT_ALLOW_PROTOCOL=https", "--env", "GIT_PROTOCOL_FROM_USER=0", "--entrypoint", "git", "--mount", bindMount(tmp, "/work", false)}
	args = append(args, containerUserArgs()...)
	args = append(args, image, "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "http.followRedirects=false", "clone", "--no-recurse-submodules", "--template=")
	if opts.History != "all" {
		args = append(args, "--depth", history(opts.History))
	}
	args = append(args, "--", target, "/work/repo")
	var envFile string
	if token := tokenFor(target); token != "" {
		f, err := os.CreateTemp("", "repyy-git-env-*")
		if err != nil {
			return "", err
		}
		envFile = f.Name()
		defer func() {
			if err := os.Remove(envFile); err != nil && !os.IsNotExist(err) {
				fetchErr = errors.Join(fetchErr, errors.New("temporary authentication file cleanup failed; credentials may remain in the system temporary directory"))
			}
		}()
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		u, _ := url.Parse(target)
		contents := "GIT_CONFIG_NOSYSTEM=1\nGIT_CONFIG_GLOBAL=/dev/null\nGIT_TERMINAL_PROMPT=0\nGIT_CONFIG_COUNT=1\nGIT_CONFIG_KEY_0=http.https://" + strings.ToLower(u.Hostname()) + "/.extraHeader\nGIT_CONFIG_VALUE_0=Authorization: Basic " + basic + "\n"
		if _, err := f.WriteString(contents); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
		if err := os.Chmod(envFile, 0o600); err != nil {
			return "", err
		}
		args = append(args[:2], append([]string{"--env-file", envFile}, args[2:]...)...)
	}
	var fetchOutput limitedBuffer
	if err := runDocker(ctx, args, &fetchOutput, &fetchOutput); err != nil {
		return "", errors.New("sandbox fetch failed; check HTTPS URL, provider token, network, and Docker mount access")
	}
	if fetchOutput.tooLarge {
		return "", errors.New("sandbox fetch output exceeded its limit")
	}
	// Resolve the revision inside the container boundary; host Git never reads
	// an untrusted checkout.
	revArgs := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--entrypoint", "git", "--mount", bindMount(tmp, "/work", true)}
	revArgs = append(revArgs, containerUserArgs()...)
	revArgs = append(revArgs, image, "-C", "/work/repo", "rev-parse", "HEAD")
	var revOut limitedBuffer
	err := runDocker(ctx, revArgs, &revOut, io.Discard)
	if err != nil || revOut.tooLarge {
		return "", errors.New("sandbox could not resolve fetched revision")
	}
	revision = strings.TrimSpace(revOut.String())
	if !gitRevision.MatchString(revision) {
		return "", errors.New("sandbox returned an invalid fetched revision")
	}
	return revision, nil
}

func history(h string) string {
	if h == "" {
		return "1"
	}
	return h
}

func runContainer(ctx context.Context, image, path string, remote bool, opts Options) (model.RepoResult, error) {
	args := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "1g", "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,mode=1777", "--mount", bindMount(path, "/input", true)}
	if opts.Config != "" {
		args = append(args, "--mount", bindMount(opts.Config, "/config/rules.yaml", true))
	}
	args = append(args, containerUserArgs()...)
	args = append(args, image, "scan", "--format", "json", "--progress", "quiet", "/input")
	if opts.Config != "" {
		args = append(args, "--config", "/config/rules.yaml")
	}
	if opts.IncludeDependencies {
		args = append(args, "--include-dependencies")
	}
	if opts.MaxFiles > 0 {
		args = append(args, "--max-files", fmt.Sprint(opts.MaxFiles))
	}
	if opts.MaxFileBytes > 0 {
		args = append(args, "--max-file-size", fmt.Sprint(opts.MaxFileBytes))
	}
	var stdout limitedBuffer
	var stderr limitedBuffer
	err := runDocker(ctx, args, &stdout, &stderr)
	if stdout.Len() == 0 && err != nil {
		return model.RepoResult{}, errors.New("sandbox scan container failed; check Docker mount access, resources, or timeout")
	}
	if stdout.tooLarge {
		return model.RepoResult{}, errors.New("sandbox returned oversized JSON")
	}
	if stderr.tooLarge {
		return model.RepoResult{}, errors.New("sandbox diagnostic output exceeded its limit")
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.DisallowUnknownFields()
	var report model.Report
	if err := dec.Decode(&report); err != nil {
		return model.RepoResult{}, fmt.Errorf("invalid sandbox JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return model.RepoResult{}, errors.New("sandbox returned trailing JSON data")
	}
	if report.SchemaVersion != "1" || report.RulesVersion != scan.BuiltinRulesVersion ||
		report.Intelligence.Version != intel.SnapshotVersion || report.Intelligence.Date != intel.SnapshotDate ||
		(opts.Version != "" && report.ToolVersion != opts.Version) {
		return model.RepoResult{}, errors.New("sandbox report metadata does not match this release")
	}
	if len(report.Results) != 1 {
		return model.RepoResult{}, errors.New("sandbox JSON must contain exactly one result")
	}
	result := report.Results[0]
	if result.Target == "" || result.Verdict == "" {
		return model.RepoResult{}, errors.New("sandbox result is incomplete")
	}
	expectedExit := 0
	if result.Error != "" || result.Verdict == model.VerdictIncomplete || !result.Coverage.Complete {
		expectedExit = 2
	} else {
		for _, finding := range result.Findings {
			if finding.Severity.Rank() >= model.SeverityHigh.Rank() {
				expectedExit = 1
				break
			}
		}
	}
	actualExit := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return model.RepoResult{}, errors.New("sandbox scan container did not complete")
		}
		actualExit = exitErr.ExitCode()
	}
	if actualExit != expectedExit {
		return model.RepoResult{}, errors.New("sandbox report exit status did not match findings")
	}
	result.Error = scrub(result.Error)
	result.Coverage.Skipped = scrubList(result.Coverage.Skipped)
	result.Coverage.Warnings = scrubList(result.Coverage.Warnings)
	result.Resolved = ""
	result.Source = nil
	result.ScanMode = model.ScanModeDocker
	result.Isolation = &model.IsolationInfo{Backend: "docker", ImageDigest: digest(image), FetchNetwork: "none", ScanNetwork: "none"}
	if remote {
		result.Isolation.FetchNetwork = "bridge"
	}
	return result, nil
}

type limitedBuffer struct {
	buf      bytes.Buffer
	tooLarge bool
}

func (b *limitedBuffer) Len() int       { return b.buf.Len() }
func (b *limitedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitedBuffer) String() string { return b.buf.String() }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > maxJSON {
		b.tooLarge = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func scrub(s string) string {
	return strings.NewReplacer("/input", "repository", "/work", "repository", "/config", "configuration").Replace(s)
}

func bindMount(path, destination string, readOnly bool) string {
	fields := []string{"type=bind", "src=" + path, "dst=" + destination}
	if readOnly {
		fields = append(fields, "readonly")
	}
	var buf strings.Builder
	writer := csv.NewWriter(&buf)
	_ = writer.Write(fields)
	writer.Flush()
	return strings.TrimSuffix(buf.String(), "\n")
}

func containerUserArgs() []string {
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid < 0 {
		return nil // use the image's unprivileged USER on Windows or a root host
	}
	return []string{"--user", fmt.Sprintf("%d:%d", uid, gid)}
}

func runDocker(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	// Give every container a unique name so a timed-out Docker client can
	// forcibly remove its daemon-side container. --rm handles normal exits.
	tmp, err := os.CreateTemp("", "repyy-container-*")
	if err != nil {
		return err
	}
	name := filepath.Base(tmp.Name())
	tmp.Close()
	os.Remove(tmp.Name())
	withName := append([]string{"run", "--name", name}, args[1:]...)
	cmd := exec.CommandContext(ctx, "docker", withName...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cleanup := exec.CommandContext(cleanupCtx, "docker", "rm", "--force", name)
		cleanup.Stdout, cleanup.Stderr = io.Discard, io.Discard
		if cleanupErr := cleanup.Run(); cleanupErr != nil {
			err = errors.Join(err, errors.New("timed-out sandbox container cleanup failed; inspect Docker for remaining repyy containers"))
		}
	}
	return err
}
func scrubList(in []string) []string {
	for i := range in {
		in[i] = scrub(in[i])
	}
	return in
}

func digest(image string) string {
	if i := strings.Index(image, "@sha256:"); i >= 0 {
		return image[i+1:]
	}
	return ""
}
