package scan

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

var errArchiveExpansionLimit = errors.New("archive expansion limit")

// archiveExpansionReader bounds bytes consumed by tar.Reader, including data it
// drains internally for unsupported entries and PAX/GNU metadata.
type archiveExpansionReader struct {
	ctx       context.Context
	source    io.Reader
	remaining int64
}

func (r *archiveExpansionReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining <= 0 {
		var probe [1]byte
		n, err := r.source.Read(probe[:])
		if n > 0 {
			return 0, errArchiveExpansionLimit
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.source.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func isArchive(path string, data []byte) bool {
	l := strings.ToLower(path)
	return len(data) >= 4 && (string(data[:4]) == "PK\x03\x04" || strings.HasSuffix(l, ".tar") || strings.HasSuffix(l, ".tar.gz") || strings.HasSuffix(l, ".tgz"))
}

func (s *Scanner) scanArchive(ctx context.Context, parent string, data []byte, depth int, add func(model.Finding), coverage *model.Coverage) {
	if depth > s.opts.Limits.MaxArchiveDepth {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, parent+" (archive-depth limit)")
		return
	}
	count, total := 0, int64(0)
	links := map[string]string{}
	flagUnsafe := func(name, reason string) {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, parent+"!"+name+" (unsafe archive entry)")
		add(s.finding("ARCHIVE-001", "archive-traversal", model.SeverityCritical, model.ConfidenceHigh, parent+"!"+name, 0, "Archive entry escapes its extraction root", reason, "Do not extract this archive."))
	}
	inspectNonFile := func(name string) bool {
		count++
		if count > s.opts.Limits.MaxArchiveFiles {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, parent+" (archive entry-count limit)")
			return false
		}
		if unsafeArchivePath(name) {
			flagUnsafe(name, "unsafe archive path")
		}
		return true
	}
	inspectLink := func(name, target string, hardlink bool) bool {
		if !inspectNonFile(name) {
			return false
		}
		name = strings.ReplaceAll(name, "\\", "/")
		target = strings.ReplaceAll(target, "\\", "/")
		if unsafeArchivePath(name) {
			return true
		}
		if strings.HasPrefix(target, "/") || windowsAbsPath.MatchString(target) {
			flagUnsafe(name, "unsafe archive link target")
			return true
		}
		resolved := target
		if !hardlink {
			resolved = pathpkg.Join(pathpkg.Dir(name), target)
		}
		if unsafeArchivePath(resolved) {
			flagUnsafe(name, "archive link escapes extraction root")
			return true
		}
		links[pathpkg.Clean(name)] = pathpkg.Clean(resolved)
		return true
	}
	consume := func(name string, size int64, mode os.FileMode, r io.Reader) bool {
		if ctx.Err() != nil {
			return false
		}
		count++
		total += size
		if count > s.opts.Limits.MaxArchiveFiles || total > s.opts.Limits.MaxArchiveBytes || size > s.opts.Limits.MaxFileBytes {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, parent+" (archive resource limit)")
			return false
		}
		if unsafeArchivePath(name) {
			flagUnsafe(name, "unsafe archive path")
			return true
		}
		portableName := pathpkg.Clean(strings.ReplaceAll(name, "\\", "/"))
		for ancestor := pathpkg.Dir(portableName); ancestor != "." && ancestor != "/"; ancestor = pathpkg.Dir(ancestor) {
			if _, linked := links[ancestor]; linked {
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, parent+"!"+name+" (entry traverses archive link)")
				return true
			}
		}
		entry, err := io.ReadAll(io.LimitReader(r, s.opts.Limits.MaxFileBytes+1))
		if err != nil || int64(len(entry)) > s.opts.Limits.MaxFileBytes {
			coverage.Complete = false
			return true
		}
		virtual := parent + "!" + filepath.ToSlash(name)
		s.scanContent(virtual, entry, mode, add, coverage)
		if isArchive(name, entry) {
			s.scanArchive(ctx, virtual, entry, depth+1, add, coverage)
		}
		return true
	}

	if len(data) >= 4 && string(data[:4]) == "PK\x03\x04" {
		zr, err := zip.NewReader(strings.NewReader(string(data)), int64(len(data)))
		if err != nil {
			coverage.Complete = false
			coverage.Warnings = append(coverage.Warnings, parent+": invalid or encrypted zip")
			return
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				if !inspectNonFile(f.Name) {
					return
				}
				continue
			}
			if f.Mode()&os.ModeSymlink != 0 {
				r, err := f.Open()
				if err != nil {
					coverage.Complete = false
					continue
				}
				target, err := io.ReadAll(io.LimitReader(r, 4097))
				r.Close()
				if err != nil || len(target) > 4096 {
					coverage.Complete = false
					coverage.Skipped = append(coverage.Skipped, parent+"!"+f.Name+" (unreadable archive link)")
					continue
				}
				if !inspectLink(f.Name, string(target), false) {
					return
				}
				continue
			}
			if !f.Mode().IsRegular() {
				if !inspectNonFile(f.Name) {
					return
				}
				coverage.Complete = false
				coverage.Skipped = append(coverage.Skipped, parent+"!"+f.Name+" (unsupported archive entry type)")
				continue
			}
			r, err := f.Open()
			if err != nil {
				coverage.Complete = false
				continue
			}
			ok := consume(f.Name, int64(f.UncompressedSize64), f.Mode(), r)
			r.Close()
			if !ok {
				return
			}
		}
		return
	}
	var expanded io.Reader
	if strings.HasSuffix(strings.ToLower(parent), ".gz") || strings.HasSuffix(strings.ToLower(parent), ".tgz") {
		gz, err := gzip.NewReader(strings.NewReader(string(data)))
		if err != nil {
			coverage.Complete = false
			return
		}
		defer gz.Close()
		expanded = gz
	} else {
		expanded = strings.NewReader(string(data))
	}
	tr := tar.NewReader(&archiveExpansionReader{ctx: ctx, source: expanded, remaining: s.opts.Limits.MaxArchiveBytes})
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			coverage.Complete = false
			if errors.Is(err, errArchiveExpansionLimit) {
				coverage.Skipped = append(coverage.Skipped, parent+" (archive expansion limit)")
			} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				coverage.Skipped = append(coverage.Skipped, parent+" (archive inspection canceled)")
			} else {
				coverage.Warnings = append(coverage.Warnings, parent+": unreadable archive entry")
			}
			break
		}
		if h.FileInfo().IsDir() {
			if !inspectNonFile(h.Name) {
				return
			}
			continue
		}
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
			if !inspectLink(h.Name, h.Linkname, h.Typeflag == tar.TypeLink) {
				return
			}
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			if !inspectNonFile(h.Name) {
				return
			}
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, parent+"!"+h.Name+" (unsupported archive entry type)")
			continue
		}
		if !consume(h.Name, h.Size, h.FileInfo().Mode(), tr) {
			return
		}
	}
}

func unsafeArchivePath(name string) bool {
	portable := strings.ReplaceAll(name, "\\", "/")
	clean := pathpkg.Clean(portable)
	return clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(portable, "/") || windowsAbsPath.MatchString(name)
}
