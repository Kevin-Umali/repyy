package app

import (
	"strings"
	"testing"
)

func TestRegistryCheckIsOptInAndHostOnly(t *testing.T) {
	defaults, err := parseScanArgs([]string{"."})
	if err != nil || defaults.registryCheck {
		t.Fatalf("registry lookups must be off by default: %+v, %v", defaults, err)
	}
	enabled, err := parseScanArgs([]string{"--registry-check", "."})
	if err != nil || !enabled.registryCheck || len(enabled.targets) != 1 {
		t.Fatalf("--registry-check should be a boolean flag: %+v, %v", enabled, err)
	}
	if _, err := parseScanArgs([]string{".", "--registry-check", "--sandbox=docker"}); err == nil || !strings.Contains(err.Error(), "--registry-check") {
		t.Fatalf("docker scans have no network and must reject --registry-check, got %v", err)
	}
}
