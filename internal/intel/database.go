package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// PackageMatch describes why a declared dependency matched the snapshot.
type PackageMatch struct {
	Indicator       Package
	VersionMatched  bool
	DeclaredVersion string
}

// Database provides indexed access to a validated intelligence snapshot.
type Database struct {
	packages map[string][]Package
	hashes   map[string]FileHash
}

// Builtin indexes a copy of the embedded package and hash indicators.
func Builtin() *Database {
	return NewDatabase(Packages, FileHashes)
}

// NewDatabase indexes copies of validated package and file-hash indicators.
func NewDatabase(packages []Package, hashes []FileHash) *Database {
	d := &Database{packages: make(map[string][]Package), hashes: make(map[string]FileHash)}
	for _, p := range packages {
		key := strings.ToLower(p.Ecosystem + "\x00" + p.Name)
		d.packages[key] = append(d.packages[key], p)
	}
	for _, h := range hashes {
		d.hashes[strings.ToLower(h.SHA256)] = h
	}
	return d
}

// MatchPackage returns indicators for an ecosystem package declaration.
func (d *Database) MatchPackage(ecosystem, name, version string) []PackageMatch {
	if d == nil {
		return nil
	}
	entries := d.packages[strings.ToLower(ecosystem+"\x00"+name)]
	out := make([]PackageMatch, 0, len(entries))
	for _, p := range entries {
		out = append(out, PackageMatch{Indicator: p, VersionMatched: affected(version, p.Affected), DeclaredVersion: version})
	}
	return out
}

func affected(declared string, ranges []string) bool {
	declared = exactVersion(declared)
	if declared == "" {
		return false
	}
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "> 0" || r == ">= 0" || r == ">=0" {
			return true
		}
		if strings.HasPrefix(r, "=") && exactVersion(strings.TrimPrefix(r, "=")) == declared {
			return true
		}
		if !strings.ContainsAny(r, "<>=|,* ") && exactVersion(r) == declared {
			return true
		}
		for _, op := range []string{"<=", ">=", "<", ">"} {
			if strings.HasPrefix(r, op) {
				if cmp, ok := compareVersion(declared, strings.TrimSpace(strings.TrimPrefix(r, op))); ok && ((op == "<=" && cmp <= 0) || (op == ">=" && cmp >= 0) || (op == "<" && cmp < 0) || (op == ">" && cmp > 0)) {
					return true
				}
			}
		}
	}
	return false
}

func compareVersion(a, b string) (int, bool) {
	parse := func(v string) ([]int, bool) {
		v = strings.TrimPrefix(strings.TrimSpace(v), "v")
		parts := strings.Split(strings.SplitN(v, "-", 2)[0], ".")
		if len(parts) == 0 {
			return nil, false
		}
		out := make([]int, 3)
		for i := 0; i < len(parts) && i < 3; i++ {
			n, err := strconv.Atoi(parts[i])
			if err != nil {
				return nil, false
			}
			out[i] = n
		}
		return out, true
	}
	aa, okA := parse(a)
	bb, okB := parse(b)
	if !okA || !okB {
		return 0, false
	}
	for i := range aa {
		if aa[i] < bb[i] {
			return -1, true
		}
		if aa[i] > bb[i] {
			return 1, true
		}
	}
	return 0, true
}

func exactVersion(v string) string {
	v = strings.TrimSpace(v)
	if strings.ContainsAny(v, "*|, <>") {
		return ""
	}
	v = strings.TrimLeft(v, "=~^v ")
	if v == "" || strings.ContainsAny(v, "xX*") {
		return ""
	}
	return v
}

// MatchHash reports whether data exactly matches a published SHA-256 indicator.
func (d *Database) MatchHash(data []byte) (FileHash, bool) {
	if d == nil {
		return FileHash{}, false
	}
	sum := sha256.Sum256(data)
	h, ok := d.hashes[hex.EncodeToString(sum[:])]
	return h, ok
}
