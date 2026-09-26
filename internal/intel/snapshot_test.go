package intel

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestSnapshotEntriesAreValidAndUnique(t *testing.T) {
	packages := map[string]bool{}
	for _, entry := range Packages {
		key := entry.Ecosystem + "\x00" + entry.Name
		if entry.Ecosystem == "" || entry.Name == "" || entry.AdvisoryID == "" || entry.Source == "" || entry.SourceURL == "" || entry.Description == "" || entry.Added == "" || entry.SnapshotVersion != SnapshotVersion {
			t.Fatalf("incomplete package entry: %+v", entry)
		}
		if packages[key] {
			t.Fatalf("duplicate package entry: %+v", entry)
		}
		packages[key] = true
	}

	hashes := map[string]bool{}
	for _, entry := range FileHashes {
		decoded, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("invalid SHA-256 entry: %+v", entry)
		}
		if entry.Source == "" || entry.SourceName == "" || entry.Description == "" || entry.Added == "" || entry.SnapshotVersion != SnapshotVersion {
			t.Fatalf("incomplete hash provenance: %+v", entry)
		}
		if hashes[entry.SHA256] {
			t.Fatalf("duplicate hash entry: %s", entry.SHA256)
		}
		hashes[entry.SHA256] = true
	}
}

func TestBuiltinSnapshotDoesNotShareIndicatorSlices(t *testing.T) {
	snapshot := BuiltinSnapshot()
	foundAxios := false
	for index := range snapshot.Packages {
		if snapshot.Packages[index].Name != "axios" {
			continue
		}
		foundAxios = true
		original := snapshot.Packages[index].Affected[0]
		defer func() { snapshot.Packages[index].Affected[0] = original }()
		snapshot.Packages[index].Affected[0] = "changed by caller"
		if got := BuiltinSnapshot().Packages[index].Affected[0]; got != original {
			t.Fatalf("caller changed embedded affected versions: %q", got)
		}
		originalReference := snapshot.Packages[index].References[0]
		defer func() { snapshot.Packages[index].References[0] = originalReference }()
		snapshot.Packages[index].References[0] = "changed by caller"
		if got := BuiltinSnapshot().Packages[index].References[0]; got != originalReference {
			t.Fatalf("caller changed embedded package provenance: %q", got)
		}
		break
	}
	if !foundAxios {
		t.Fatal("Axios indicator missing from embedded snapshot")
	}
	originalHashReference := snapshot.FileHashes[0].References[0]
	defer func() { snapshot.FileHashes[0].References[0] = originalHashReference }()
	snapshot.FileHashes[0].References[0] = "changed by caller"
	if got := BuiltinSnapshot().FileHashes[0].References[0]; got != originalHashReference {
		t.Fatalf("caller changed embedded hash provenance: %q", got)
	}
}

func TestWithdrawnAdvisoryIsNotSelected(t *testing.T) {
	for _, entry := range Packages {
		if entry.AdvisoryID == "GHSA-rwq7-v7c7-27gx" {
			t.Fatal("withdrawn advisory remained selected")
		}
	}
}

func TestSnapshotStaleness(t *testing.T) {
	if Stale(SnapshotTime().AddDate(0, 0, 30)) {
		t.Fatal("snapshot became stale too early")
	}
	if !Stale(SnapshotTime().AddDate(0, 0, 91)) {
		t.Fatal("snapshot should be stale after 90 days")
	}
	if SnapshotTime().After(time.Now().AddDate(1, 0, 0)) {
		t.Fatal("snapshot date is implausibly far in the future")
	}
}
