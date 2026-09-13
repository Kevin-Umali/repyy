package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/intel"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/scan"
)

func requireUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script requires Unix")
	}
}

func installFakeDocker(t *testing.T) {
	t.Helper()
	requireUnix(t)
	dir := t.TempDir()
	script := `#!/bin/sh
case "${FAKE_DOCKER_MODE:-output}" in
inspect)
	exit "${FAKE_DOCKER_EXIT:-0}"
	;;
oversized)
	dd if=/dev/zero bs=1048576 count=128 2>/dev/null
	exit 0
	;;
*)
	printf '%s' "${FAKE_DOCKER_STDOUT:-}"
	printf '%s' "${FAKE_DOCKER_STDERR:-}" >&2
	exit "${FAKE_DOCKER_EXIT:-0}"
	;;
esac
`
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func validImage() string {
	return "ghcr.io/example/repyy-sandbox:v1@sha256:" + strings.Repeat("a", 64)
}

func validReport() model.Report {
	return model.Report{
		SchemaVersion: "1",
		ToolVersion:   "v1",
		RulesVersion:  scan.BuiltinRulesVersion,
		Intelligence:  model.IntelligenceInfo{Version: intel.SnapshotVersion, Date: intel.SnapshotDate},
		Results: []model.RepoResult{{
			Target:   "/input",
			Verdict:  model.VerdictNoFindings,
			Coverage: model.Coverage{Complete: true},
		}},
	}
}

func setWorkerOutput(t *testing.T, report model.Report, exit int) {
	t.Helper()
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DOCKER_MODE", "output")
	t.Setenv("FAKE_DOCKER_STDOUT", string(b))
	t.Setenv("FAKE_DOCKER_STDERR", "")
	t.Setenv("FAKE_DOCKER_EXIT", strconv.Itoa(exit))
}

func TestPreflightRequiresPinnedAvailableImage(t *testing.T) {
	installFakeDocker(t)

	t.Run("missing image", func(t *testing.T) {
		if err := Preflight(context.Background(), Options{}); err == nil || !strings.Contains(err.Error(), "image is unavailable") {
			t.Fatalf("Preflight() error = %v, want unavailable image", err)
		}
	})

	t.Run("inspect failure", func(t *testing.T) {
		t.Setenv("FAKE_DOCKER_MODE", "inspect")
		t.Setenv("FAKE_DOCKER_EXIT", "1")
		err := Preflight(context.Background(), Options{Image: validImage()})
		if err == nil || !strings.Contains(err.Error(), "not available locally") {
			t.Fatalf("Preflight() error = %v, want local image failure", err)
		}
	})
}

func TestRunContainerAcceptsValidWorkerJSON(t *testing.T) {
	installFakeDocker(t)
	setWorkerOutput(t, validReport(), 0)

	result, err := runContainer(context.Background(), validImage(), "/tmp/repository", false, Options{})
	if err != nil {
		t.Fatalf("runContainer() error = %v", err)
	}
	if result.Target != "/input" || result.Verdict != model.VerdictNoFindings {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Isolation == nil || result.Isolation.ImageDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("unexpected isolation: %#v", result.Isolation)
	}
}

func TestRunContainerPreservesIncompleteFindings(t *testing.T) {
	installFakeDocker(t)
	report := validReport()
	report.Results[0].Verdict = model.VerdictIncomplete
	report.Results[0].Coverage.Complete = false
	report.Results[0].Coverage.Warnings = []string{"file could not be inspected"}
	report.Results[0].Findings = []model.Finding{{Severity: model.SeverityHigh, RuleID: "TEST-001", Path: "source.js"}}
	setWorkerOutput(t, report, 2)

	result, err := runContainer(context.Background(), validImage(), "/tmp/repository", false, Options{})
	if err != nil {
		t.Fatalf("runContainer() error = %v", err)
	}
	if result.Verdict != model.VerdictIncomplete || len(result.Findings) != 1 || result.Findings[0].RuleID != "TEST-001" {
		t.Fatalf("incomplete result lost its findings: %#v", result)
	}
}

func TestRunContainerRejectsMalformedOversizedAndTrailingJSON(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{name: "malformed", out: "{not json", want: "invalid sandbox JSON"},
		{name: "trailing", out: "{} {}", want: "trailing JSON data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installFakeDocker(t)
			t.Setenv("FAKE_DOCKER_STDOUT", tc.out)
			t.Setenv("FAKE_DOCKER_EXIT", "0")
			_, err := runContainer(context.Background(), validImage(), "/tmp/repository", false, Options{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runContainer() error = %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("oversized", func(t *testing.T) {
		installFakeDocker(t)
		t.Setenv("FAKE_DOCKER_MODE", "oversized")
		_, err := runContainer(context.Background(), validImage(), "/tmp/repository", false, Options{})
		if err == nil || !strings.Contains(err.Error(), "oversized JSON") {
			t.Fatalf("runContainer() error = %v, want oversized JSON", err)
		}
	})
}

func TestLimitedBufferRejectsOversizedOutput(t *testing.T) {
	var b limitedBuffer
	if _, err := b.Write(make([]byte, maxJSON+1)); err != nil {
		t.Fatal(err)
	}
	if !b.tooLarge {
		t.Fatal("limitedBuffer did not detect oversized output")
	}
}

func TestRunContainerRequiresExitStatusToMatchReport(t *testing.T) {
	cases := []struct {
		name      string
		severity  model.Severity
		reportErr string
		exit      int
		wantErr   bool
	}{
		{name: "high finding exit one", severity: model.SeverityHigh, exit: 1},
		{name: "report error exit two", reportErr: "worker failed", exit: 2},
		{name: "mismatched exit", severity: model.SeverityHigh, exit: 0, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installFakeDocker(t)
			report := validReport()
			report.Results[0].Error = tc.reportErr
			report.Results[0].Verdict = model.VerdictReview
			if tc.severity != "" {
				report.Results[0].Findings = []model.Finding{{Severity: tc.severity}}
			}
			setWorkerOutput(t, report, tc.exit)
			_, err := runContainer(context.Background(), validImage(), "/tmp/repository", false, Options{})
			if tc.wantErr && (err == nil || !strings.Contains(err.Error(), "exit status")) {
				t.Fatalf("runContainer() error = %v, want exit mismatch", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("runContainer() error = %v", err)
			}
		})
	}
}

func TestBindMountQuotesSpecialPaths(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{path: "/tmp/repo,with comma", want: `type=bind,src="/tmp/repo,with comma",dst=/input,readonly`},
		{path: `/tmp/repo"with quote`, want: `type=bind,src="/tmp/repo""with quote",dst=/input`},
		{path: `C:\repo,with comma`, want: `type=bind,src="C:\repo,with comma",dst=/input`},
		{path: "/tmp/plain", want: "type=bind,src=/tmp/plain,dst=/input"},
	}
	for _, tc := range cases {
		if got := bindMount(tc.path, "/input", strings.HasSuffix(tc.want, ",readonly")); got != tc.want {
			t.Errorf("bindMount(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
