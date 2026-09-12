package intel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func signedClient(t *testing.T, private ed25519.PrivateKey, snapshot func() Snapshot) (*http.Client, *int) {
	t.Helper()
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		data, err := json.MarshalIndent(snapshot(), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, '\n')
		body := data
		contentType := "application/json"
		if filepath.Ext(request.URL.Path) == ".sig" {
			body = ed25519.Sign(private, data)
			contentType = "application/octet-stream"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    request,
		}, nil
	})}
	return client, &requests
}

func testSnapshot(version, date string) Snapshot {
	snapshot := BuiltinSnapshot()
	snapshot.SnapshotVersion = version
	snapshot.SnapshotDate = date
	for i := range snapshot.Packages {
		snapshot.Packages[i].SnapshotVersion = version
	}
	for i := range snapshot.FileHashes {
		snapshot.FileHashes[i].SnapshotVersion = version
	}
	return snapshot
}

func TestUpdateLoadsVerifiedSnapshotWithoutLaterNetwork(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot("2026-09-13.2", "2026-09-13")
	client, requests := signedClient(t, private, func() Snapshot { return snapshot })
	store := &Store{Dir: t.TempDir(), URL: "https://updates.invalid/snapshot.json", Client: client, PublicKey: public}
	status, err := store.Update(context.Background(), time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if status.Source != "cache" || status.SnapshotVersion != "2026-09-13.2" || *requests != 2 {
		t.Fatalf("unexpected update: status=%+v requests=%d", status, *requests)
	}
	store.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("cached load attempted network access")
		return nil, nil
	})}
	_, loaded := store.LoadActive(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	if loaded.SnapshotVersion != "2026-09-13.2" || *requests != 2 {
		t.Fatalf("cached load used network or wrong snapshot: status=%+v requests=%d", loaded, *requests)
	}
}

func TestInvalidSignatureDoesNotActivate(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot("2026-09-13.9", "2026-09-13")
	client, _ := signedClient(t, wrongPrivate, func() Snapshot { return snapshot })
	store := &Store{Dir: t.TempDir(), URL: "https://updates.invalid/snapshot.json", Client: client, PublicKey: public}
	if _, err := store.Update(context.Background(), time.Now()); err == nil {
		t.Fatal("update accepted an invalid signature")
	}
	_, status := store.LoadActive(time.Now())
	if status.Source != "embedded" {
		t.Fatalf("untrusted snapshot became active: %+v", status)
	}
}

func TestFailedUpdatePreservesLastKnownGoodSnapshot(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot("2026-09-13.1", "2026-09-13")
	client, _ := signedClient(t, private, func() Snapshot { return snapshot })
	store := &Store{Dir: t.TempDir(), URL: "https://updates.invalid/snapshot.json", Client: client, PublicKey: public}
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	if _, err := store.Update(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	store.Client, _ = signedClient(t, wrongPrivate, func() Snapshot {
		return testSnapshot("2026-09-14.9", "2026-09-14")
	})
	if _, err := store.Update(context.Background(), now); err == nil {
		t.Fatal("update accepted an invalid replacement signature")
	}
	_, status := store.LoadActive(now)
	if status.Source != "cache" || status.SnapshotVersion != "2026-09-13.1" {
		t.Fatalf("failed update replaced the last-known-good snapshot: %+v", status)
	}
}

func TestRollbackSwapsVerifiedSnapshots(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := []Snapshot{testSnapshot("2026-09-13.1", "2026-09-13"), testSnapshot("2026-09-14.1", "2026-09-14")}
	index := 0
	client, _ := signedClient(t, private, func() Snapshot { return snapshots[index] })
	store := &Store{Dir: t.TempDir(), URL: "https://updates.invalid/snapshot.json", Client: client, PublicKey: public}
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	if _, err := store.Update(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	index = 1
	if _, err := store.Update(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	status, err := store.Rollback(now)
	if err != nil {
		t.Fatal(err)
	}
	if status.SnapshotVersion != "2026-09-13.1" {
		t.Fatalf("rollback selected %s", status.SnapshotVersion)
	}
}

func TestCorruptCacheFallsBackToEmbedded(t *testing.T) {
	key, err := embeddedPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{Dir: t.TempDir(), PublicKey: key}
	if err := os.WriteFile(filepath.Join(store.Dir, "active"), []byte("not-a-digest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, status := store.LoadActive(time.Now())
	if status.Source != "embedded" || status.Warning == "" {
		t.Fatalf("corrupt cache did not produce a safe fallback: %+v", status)
	}
}

func TestUpdateRejectsOlderSnapshot(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot("2026-09-11.9", "2026-09-11")
	client, _ := signedClient(t, private, func() Snapshot { return snapshot })
	store := &Store{Dir: t.TempDir(), URL: "https://updates.invalid/snapshot.json", Client: client, PublicKey: public}
	if _, err := store.Update(context.Background(), time.Now()); err == nil || !strings.Contains(err.Error(), "refusing older snapshot") {
		t.Fatalf("expected downgrade rejection, got %v", err)
	}
	_, status := store.LoadActive(time.Now())
	if status.Source != "embedded" {
		t.Fatalf("older snapshot became active: %+v", status)
	}
}

func TestUpdateRejectsLowerRevisionFromSameDate(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := []Snapshot{
		testSnapshot("2026-09-13.2", "2026-09-13"),
		testSnapshot("2026-09-13.1", "2026-09-13"),
	}
	index := 0
	client, _ := signedClient(t, private, func() Snapshot { return snapshots[index] })
	store := &Store{Dir: t.TempDir(), URL: "https://updates.invalid/snapshot.json", Client: client, PublicKey: public}
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	if _, err := store.Update(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	index = 1
	if _, err := store.Update(context.Background(), now); err == nil || !strings.Contains(err.Error(), "refusing older snapshot") {
		t.Fatalf("expected same-date revision downgrade rejection, got %v", err)
	}
}

func TestUpdateRejectsFutureDatedSnapshot(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot("2026-09-15.1", "2026-09-15")
	client, _ := signedClient(t, private, func() Snapshot { return snapshot })
	store := &Store{Dir: t.TempDir(), URL: "https://updates.invalid/snapshot.json", Client: client, PublicKey: public}
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	if _, err := store.Update(context.Background(), now); err == nil || !strings.Contains(err.Error(), "future-dated") {
		t.Fatalf("expected future-date rejection, got %v", err)
	}
}

func TestDecodeSnapshotRejectsUnknownAndTrailingContent(t *testing.T) {
	valid, err := json.Marshal(testSnapshot("2026-09-13.1", "2026-09-13"))
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := bytes.Replace(valid, []byte(`"snapshot_date"`), []byte(`"unexpected":true,"snapshot_date"`), 1)
	for name, data := range map[string][]byte{
		"unknown field": withUnknown,
		"trailing JSON": append(valid, []byte("\n{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSnapshot(data); err == nil {
				t.Fatal("malformed snapshot was accepted")
			}
		})
	}
}

func TestDefaultStoreUsesPrivateCacheSubdirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("REPYY_CACHE_DIR", root)
	store, err := NewDefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "intelligence"); store.Dir != want {
		t.Fatalf("store directory = %q, want %q", store.Dir, want)
	}
}

func TestPublishedPublicKeyMatchesEmbeddedKey(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("..", "..", "keys", "intelligence-ed25519.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(published)
	if block == nil {
		t.Fatal("published public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publishedKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatal("published public key is not Ed25519")
	}
	embedded, err := embeddedPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publishedKey, embedded) {
		t.Fatal("published and embedded public keys differ")
	}
}
