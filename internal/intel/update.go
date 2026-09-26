package intel

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultSnapshotURL is contacted only by an explicit intel update command.
	DefaultSnapshotURL = "https://github.com/Kevin-Umali/repyy/releases/latest/download/repyy-intelligence.json"
	publicKeyDER       = "MCowBQYDK2VwAyEADWR2WdKsgOcmsiz72vS7y6YsrhvMPdAMU1pElpLLrSw="
	maxSnapshotBytes   = 16 << 20
	maxSignatureBytes  = 1024
)

var (
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hashPattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	versionPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\.(\d{1,9})$`)
)

// Status describes which intelligence snapshot is active and why.
type Status struct {
	Source          string `json:"source"`
	SnapshotVersion string `json:"snapshot_version"`
	SnapshotDate    string `json:"snapshot_date"`
	Packages        int    `json:"packages"`
	FileHashes      int    `json:"file_hashes"`
	Stale           bool   `json:"stale"`
	Verified        bool   `json:"verified"`
	CacheDirectory  string `json:"cache_directory"`
	Warning         string `json:"warning,omitempty"`
}

// Store manages signed snapshots in an atomic content-addressed cache.
type Store struct {
	Dir       string
	URL       string
	Client    *http.Client
	PublicKey ed25519.PublicKey
}

// NewDefaultStore returns the per-user intelligence store without network I/O.
func NewDefaultStore() (*Store, error) {
	cache := os.Getenv("REPYY_CACHE_DIR")
	if cache == "" {
		var err error
		cache, err = os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("locate user cache: %w", err)
		}
		cache = filepath.Join(cache, "repyy")
	}
	key, err := embeddedPublicKey()
	if err != nil {
		return nil, err
	}
	return &Store{
		Dir:       filepath.Join(cache, "intelligence"),
		URL:       DefaultSnapshotURL,
		Client:    &http.Client{Timeout: 30 * time.Second},
		PublicKey: key,
	}, nil
}

// LoadActive returns a verified cached database or the embedded fallback.
// It never accesses the network.
func (s *Store) LoadActive(now time.Time) (*Database, Status) {
	snapshot, status := s.LoadActiveSnapshot(now)
	return NewDatabase(snapshot.Packages, snapshot.FileHashes), status
}

// LoadActiveSnapshot returns verified cached records or the embedded fallback.
// It never accesses the network.
func (s *Store) LoadActiveSnapshot(now time.Time) (Snapshot, Status) {
	builtin := BuiltinSnapshot()
	snapshot, err := s.loadPointer("active")
	if err == nil {
		if snapshotOlderThan(snapshot, builtin) {
			return builtin, statusFor(builtin, "embedded", true, s.Dir, now, "cached intelligence predates the embedded snapshot")
		}
		return snapshot, statusFor(snapshot, "cache", true, s.Dir, now, "")
	}
	warning := ""
	if !errors.Is(err, os.ErrNotExist) {
		warning = "cached intelligence was ignored: " + err.Error()
	}
	return builtin, statusFor(builtin, "embedded", true, s.Dir, now, warning)
}

// Inspect reports the active snapshot without accessing the network.
func (s *Store) Inspect(now time.Time) Status {
	_, status := s.LoadActive(now)
	return status
}

// Update downloads, verifies, validates, and atomically activates a snapshot.
func (s *Store) Update(ctx context.Context, now time.Time) (Status, error) {
	if s.URL == "" || s.Client == nil || len(s.PublicKey) != ed25519.PublicKeySize {
		return Status{}, errors.New("intelligence store is not fully configured")
	}
	data, err := s.download(ctx, s.URL, maxSnapshotBytes)
	if err != nil {
		return Status{}, fmt.Errorf("download snapshot: %w", err)
	}
	signature, err := s.download(ctx, s.URL+".sig", maxSignatureBytes)
	if err != nil {
		return Status{}, fmt.Errorf("download signature: %w", err)
	}
	if !ed25519.Verify(s.PublicKey, data, signature) {
		return Status{}, errors.New("snapshot signature verification failed")
	}
	snapshot, err := decodeSnapshot(data)
	if err != nil {
		return Status{}, err
	}
	if snapshotTime(snapshot).After(now.Add(24 * time.Hour)) {
		return Status{}, fmt.Errorf("refusing future-dated snapshot %s", snapshot.SnapshotDate)
	}
	active, _ := s.LoadActiveSnapshot(now)
	if snapshotOlderThan(snapshot, active) {
		return Status{}, fmt.Errorf("refusing older snapshot %s; active snapshot is %s", snapshot.SnapshotDate, active.SnapshotDate)
	}
	digest := sha256.Sum256(data)
	digestText := hex.EncodeToString(digest[:])
	if err := os.MkdirAll(filepath.Join(s.Dir, "objects"), 0o700); err != nil {
		return Status{}, fmt.Errorf("create intelligence cache: %w", err)
	}
	if err := atomicWrite(filepath.Join(s.Dir, "objects", digestText+".json"), data, 0o600); err != nil {
		return Status{}, err
	}
	if err := atomicWrite(filepath.Join(s.Dir, "objects", digestText+".sig"), signature, 0o600); err != nil {
		return Status{}, err
	}
	if oldDigest, err := s.readPointer("active"); err == nil && oldDigest != digestText {
		if err := atomicWrite(filepath.Join(s.Dir, "previous"), []byte(oldDigest+"\n"), 0o600); err != nil {
			return Status{}, err
		}
	}
	if err := atomicWrite(filepath.Join(s.Dir, "active"), []byte(digestText+"\n"), 0o600); err != nil {
		return Status{}, err
	}
	return statusFor(snapshot, "cache", true, s.Dir, now, ""), nil
}

// Rollback atomically activates the previously verified cached snapshot.
func (s *Store) Rollback(now time.Time) (Status, error) {
	previous, err := s.readPointer("previous")
	if err != nil {
		return Status{}, errors.New("no previous cached snapshot is available")
	}
	snapshot, err := s.loadDigest(previous)
	if err != nil {
		return Status{}, fmt.Errorf("previous snapshot is invalid: %w", err)
	}
	current, _ := s.readPointer("active")
	if err := atomicWrite(filepath.Join(s.Dir, "active"), []byte(previous+"\n"), 0o600); err != nil {
		return Status{}, err
	}
	if current != "" && current != previous {
		if err := atomicWrite(filepath.Join(s.Dir, "previous"), []byte(current+"\n"), 0o600); err != nil {
			return Status{}, err
		}
	}
	return statusFor(snapshot, "cache", true, s.Dir, now, ""), nil
}

func (s *Store) download(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "repyy-intelligence-updater")
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func (s *Store) loadPointer(name string) (Snapshot, error) {
	digest, err := s.readPointer(name)
	if err != nil {
		return Snapshot{}, err
	}
	return s.loadDigest(digest)
}

func (s *Store) readPointer(name string) (string, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return "", err
	}
	digest := strings.TrimSpace(string(data))
	if !digestPattern.MatchString(digest) {
		return "", errors.New("invalid cache pointer")
	}
	return digest, nil
}

func (s *Store) loadDigest(digest string) (Snapshot, error) {
	if !digestPattern.MatchString(digest) {
		return Snapshot{}, errors.New("invalid snapshot digest")
	}
	if len(s.PublicKey) != ed25519.PublicKeySize {
		return Snapshot{}, errors.New("invalid intelligence verification key")
	}
	data, err := os.ReadFile(filepath.Join(s.Dir, "objects", digest+".json"))
	if err != nil {
		return Snapshot{}, err
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != digest {
		return Snapshot{}, errors.New("cached snapshot digest mismatch")
	}
	signature, err := os.ReadFile(filepath.Join(s.Dir, "objects", digest+".sig"))
	if err != nil {
		return Snapshot{}, err
	}
	if !ed25519.Verify(s.PublicKey, data, signature) {
		return Snapshot{}, errors.New("cached snapshot signature verification failed")
	}
	return decodeSnapshot(data)
}

func decodeSnapshot(data []byte) (Snapshot, error) {
	var snapshot Snapshot
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Snapshot{}, errors.New("decode snapshot: trailing JSON content")
	}
	versionParts := versionPattern.FindStringSubmatch(snapshot.SnapshotVersion)
	if len(versionParts) != 3 || versionParts[1] != snapshot.SnapshotDate || snapshotTime(snapshot).IsZero() {
		return Snapshot{}, errors.New("snapshot version or date is invalid")
	}
	if len(snapshot.Packages) == 0 || len(snapshot.FileHashes) == 0 || len(snapshot.Packages) > 100_000 || len(snapshot.FileHashes) > 100_000 {
		return Snapshot{}, errors.New("snapshot must contain package and file-hash indicators")
	}
	seenPackages := make(map[string]bool, len(snapshot.Packages))
	for _, p := range snapshot.Packages {
		key := strings.ToLower(p.Ecosystem + "\x00" + p.Name + "\x00" + p.AdvisoryID)
		if p.Ecosystem == "" || p.Name == "" || p.AdvisoryID == "" || p.Source == "" || !validHTTPSURL(p.SourceURL) || p.Description == "" || !validDate(p.Added) || p.SnapshotVersion != snapshot.SnapshotVersion || seenPackages[key] {
			return Snapshot{}, fmt.Errorf("invalid or duplicate package indicator %q", p.Name)
		}
		seenAliases := map[string]bool{p.AdvisoryID: true}
		for _, alias := range p.Aliases {
			if strings.TrimSpace(alias) == "" || seenAliases[alias] {
				return Snapshot{}, fmt.Errorf("invalid or duplicate advisory alias for %s", p.Name)
			}
			seenAliases[alias] = true
		}
		if p.Modified != "" && !validDate(p.Modified) {
			return Snapshot{}, fmt.Errorf("invalid modified date for package indicator %q", p.Name)
		}
		for _, reference := range p.References {
			if !validHTTPSURL(reference) {
				return Snapshot{}, fmt.Errorf("invalid reference for package indicator %q", p.Name)
			}
		}
		seenPackages[key] = true
	}
	seenHashes := make(map[string]bool, len(snapshot.FileHashes))
	for _, h := range snapshot.FileHashes {
		hash := strings.ToLower(h.SHA256)
		if !hashPattern.MatchString(hash) || h.Family == "" || !validHTTPSURL(h.Source) || h.SourceName == "" || h.Description == "" || !validDate(h.Added) || h.SnapshotVersion != snapshot.SnapshotVersion || seenHashes[hash] {
			return Snapshot{}, fmt.Errorf("invalid or duplicate file hash %q", h.SHA256)
		}
		for _, reference := range h.References {
			if !validHTTPSURL(reference) {
				return Snapshot{}, fmt.Errorf("invalid reference for file hash %q", h.SHA256)
			}
		}
		seenHashes[hash] = true
	}
	return snapshot, nil
}

func validDate(value string) bool {
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && !parsed.IsZero()
}

func validHTTPSURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

func snapshotTime(snapshot Snapshot) time.Time {
	t, _ := time.Parse("2006-01-02", snapshot.SnapshotDate)
	return t
}

func snapshotOlderThan(candidate, active Snapshot) bool {
	candidateTime, activeTime := snapshotTime(candidate), snapshotTime(active)
	if !candidateTime.Equal(activeTime) {
		return candidateTime.Before(activeTime)
	}
	candidateRevision, _ := strconv.Atoi(versionPattern.FindStringSubmatch(candidate.SnapshotVersion)[2])
	activeRevision, _ := strconv.Atoi(versionPattern.FindStringSubmatch(active.SnapshotVersion)[2])
	return candidateRevision < activeRevision
}

func statusFor(snapshot Snapshot, source string, verified bool, dir string, now time.Time, warning string) Status {
	return Status{
		Source:          source,
		SnapshotVersion: snapshot.SnapshotVersion,
		SnapshotDate:    snapshot.SnapshotDate,
		Packages:        len(snapshot.Packages),
		FileHashes:      len(snapshot.FileHashes),
		Stale:           now.After(snapshotTime(snapshot).AddDate(0, 0, 90)),
		Verified:        verified,
		CacheDirectory:  dir,
		Warning:         warning,
	}
}

func embeddedPublicKey() (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(publicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("decode embedded intelligence key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse embedded intelligence key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("embedded intelligence key is not Ed25519")
	}
	return key, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".repyy-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpName, path); err != nil {
		return fmt.Errorf("activate cached file: %w", err)
	}
	return nil
}
