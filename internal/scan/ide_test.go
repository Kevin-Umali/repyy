package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFolderOpenTaskRecognizesJSONPropertyWithoutFlaggingManualTask(t *testing.T) {
	for _, tc := range []struct {
		name, options string
		want          bool
	}{
		{"automatic", `,"runOptions":{"runOn":"folderOpen"}`, true},
		{"manual", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, ".vscode"), 0700); err != nil {
				t.Fatal(err)
			}
			body := `{"version":"2.0.0","tasks":[{"label":"inert","type":"process","command":"REPYY_NONEXISTENT_INERT_MARKER"` + tc.options + `}]}`
			if err := os.WriteFile(filepath.Join(root, ".vscode", "tasks.json"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			coverage, findings := New(Options{}).Scan(context.Background(), root)
			if !coverage.Complete {
				t.Fatalf("incomplete fixture: %+v", coverage)
			}
			_, found := ruleFinding(findings, "IDE-001")
			if found != tc.want {
				t.Fatalf("IDE-001 present=%v want=%v: %+v", found, tc.want, findings)
			}
		})
	}
}

func TestEditorExtensionProvisioningSurfaces(t *testing.T) {
	tests := []struct {
		name, path, body, rule string
		want                   bool
	}{
		{
			name: "workspace recommendation",
			path: ".vscode/extensions.json",
			body: `{
  "recommendations": [
    "fixture.reviewed-extension"
  ]
}`,
			rule: "IDE-003",
			want: true,
		},
		{
			name: "JSONC comments before hidden recommendation",
			path: ".vscode/extensions.json",
			body: `{
  "recommendations": [
    // Kept far below the property so a reviewer must scroll.
    /* repository controlled */
    "fixture.hidden-extension"
  ]
}`,
			rule: "IDE-003",
			want: true,
		},
		{
			name: "multi-root workspace recommendation",
			path: "fixture.code-workspace",
			body: `{"extensions":{"recommendations":["fixture.reviewed-extension"]}}`,
			rule: "IDE-003",
			want: true,
		},
		{
			name: "devcontainer automatic installation",
			path: ".devcontainer/devcontainer.json",
			body: `{
  "customizations": {
    "vscode": {
      "extensions": [
        "fixture.reviewed-extension"
      ]
    }
  }
}`,
			rule: "IDE-004",
			want: true,
		},
		{
			name: "command line extension installation",
			path: "scripts/bootstrap.sh",
			body: `code --install-extension fixture.reviewed-extension`,
			rule: "IDE-004",
			want: true,
		},
		{
			name: "unwanted recommendation is not an install request",
			path: ".vscode/extensions.json",
			body: `{"unwantedRecommendations":["fixture.blocked-extension"]}`,
			rule: "IDE-003",
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, tc.path, tc.body)
			coverage, findings := New(Options{}).Scan(context.Background(), root)
			if !coverage.Complete {
				t.Fatalf("incomplete fixture: %+v", coverage)
			}
			if got := hasRule(findings, tc.rule); got != tc.want {
				t.Fatalf("%s present=%v want=%v: %+v", tc.rule, got, tc.want, findings)
			}
		})
	}
}

func TestWorkspaceCommandsAndDevcontainerFeaturesAreInventoried(t *testing.T) {
	tests := []struct {
		name, path, body, rule string
	}{
		{
			name: "manual workspace task command",
			path: ".vscode/tasks.json",
			body: `{
  "version": "2.0.0",
  "tasks": [{
    "label": "fixture",
    "type": "shell",
    "command": "./scripts/fixture-task.sh"
  }]
}`,
			rule: "IDE-005",
		},
		{
			name: "debug task linkage",
			path: ".vscode/launch.json",
			body: `{"configurations":[{"name":"fixture","preLaunchTask":"fixture-task"}]}`,
			rule: "IDE-005",
		},
		{
			name: "devcontainer feature",
			path: ".devcontainer/devcontainer.json",
			body: `{"features":{"ghcr.io/fixture/features/tool:1":{}}}`,
			rule: "IDE-006",
		},
		{
			name: "devcontainer extension after JSONC comment",
			path: ".devcontainer/devcontainer.json",
			body: "{\"customizations\":{\"vscode\":{\"extensions\":[// reviewed below\n\"fixture.publisher\"]}}}",
			rule: "IDE-004",
		},
		{
			name: "devcontainer feature after JSONC comment",
			path: ".devcontainer/devcontainer.json",
			body: "{\"features\":{/* reviewed below */\"ghcr.io/fixture/features/tool:1\":{}}}",
			rule: "IDE-006",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, tc.path, tc.body)
			_, findings := New(Options{}).Scan(context.Background(), root)
			if !hasRule(findings, tc.rule) {
				t.Fatalf("missing %s: %+v", tc.rule, findings)
			}
		})
	}
}

func TestPackagedVSIXExtensionIsInventoried(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "extensions/fixture.vsix", "PK fixture archive")
	_, findings := New(Options{}).Scan(context.Background(), root)
	if !hasRule(findings, "IDE-007") {
		t.Fatalf("packaged VSIX editor extension was not inventoried: %+v", findings)
	}
}

func TestRepositoryManagedHookAndMultilineAgentCommands(t *testing.T) {
	tests := []struct {
		name, path, body, rule string
	}{
		{
			name: "pre-commit repository hook",
			path: ".pre-commit-config.yaml",
			body: "repos:\n  - repo: https://example.invalid/reviewed-hooks\n    rev: fixture\n    hooks:\n      - id: fixture\n",
			rule: "GITHOOK-003",
		},
		{
			name: "multiline agent hook command",
			path: ".claude/settings.json",
			body: `{
  "hooks": {
    "PostToolUse": [{
      "matcher": "fixture",
      "hooks": [{
        "type": "command",
        "command": "./scripts/review-me.sh"
      }]
    }]
  }
}`,
			rule: "AGENT-001",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, tc.path, tc.body)
			_, findings := New(Options{}).Scan(context.Background(), root)
			if !hasRule(findings, tc.rule) {
				t.Fatalf("missing %s: %+v", tc.rule, findings)
			}
		})
	}
}

func TestAgentHookProseIsNotConfiguration(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture\n")
	writeFixture(t, root, "LICENSE", "fixture\n")
	writeFixture(t, root, "AGENTS.md", "The webhook forwards status updates.\n\nRun the test suite before submitting.\n")
	_, findings := New(Options{}).Scan(context.Background(), root)
	if hasRule(findings, "AGENT-001") {
		t.Fatalf("ordinary webhook prose was treated as agent configuration: %+v", findings)
	}
}

func TestAdditionalAutomaticExecutionAndInstallationSurfaces(t *testing.T) {
	tests := []struct {
		name, path, body, rule string
	}{
		{"devcontainer lifecycle command", ".devcontainer/devcontainer.json", `{"postAttachCommand":"printf fixture"}`, "IDE-001"},
		{"direnv hook", ".envrc", `use flake`, "AUTORUN-001"},
		{"Nix shell hook", "flake.nix", `shellHook = "printf fixture";`, "AUTORUN-002"},
		{"host package installer", "scripts/bootstrap.sh", `brew install fixture-package`, "INSTALL-001"},
		{"Linux font installer", "scripts/install-fonts.sh", `install -m 0644 Fixture.ttf "$HOME/.local/share/fonts/"`, "FONT-001"},
		{"Windows font installer", "scripts/install-fonts.ps1", `Copy-Item Fixture.ttf "$env:LOCALAPPDATA\Microsoft\Windows\Fonts"`, "FONT-001"},
		{"Windows startup registration", "scripts/setup.ps1", `reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Fixture`, "SHELL-001"},
		{"font installer hidden at end of long line", "scripts/install-fonts.sh", strings.Repeat("x", 70000) + ` ; fc-cache -f`, "FONT-001"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "README.md", "fixture\n")
			writeFixture(t, root, "LICENSE", "fixture\n")
			writeFixture(t, root, tc.path, tc.body)
			coverage, findings := New(Options{}).Scan(context.Background(), root)
			if !coverage.Complete {
				t.Fatalf("incomplete fixture: %+v", coverage)
			}
			if !hasRule(findings, tc.rule) {
				t.Fatalf("missing %s: %+v", tc.rule, findings)
			}
		})
	}
}
