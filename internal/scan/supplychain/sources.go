package supplychain

import (
	"path"
	"strings"
)

// repositoryDirectory reports whether a local dependency target, relative to its
// manifest, names a directory inside the scanned repository. That code is part of the
// scan, so the dependency adds no unreviewed source. Archives, absolute and home
// paths, and paths that climb out of the root do not count.
func repositoryDirectory(manifestPath, target string) bool {
	if strings.Contains(manifestPath, "!") || target == "" || strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") || strings.Contains(target, "\\") {
		return false
	}
	switch strings.ToLower(path.Ext(target)) {
	case ".tgz", ".tar", ".gz", ".zip", ".crate":
		return false
	}
	resolved := path.Clean(path.Join(path.Dir(manifestPath), target))
	return resolved != ".." && !strings.HasPrefix(resolved, "../")
}
