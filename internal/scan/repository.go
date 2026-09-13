package scan

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func (s *Scanner) scanRepositoryHygiene(root string, add func(model.Finding)) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	hasREADME, hasLicense := false, false
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		hasREADME = hasREADME || name == "readme" || strings.HasPrefix(name, "readme.")
		hasLicense = hasLicense || name == "license" || strings.HasPrefix(name, "license.") || name == "copying"
	}
	if !hasREADME {
		f := s.finding("REPO-001", "repository-hygiene", model.SeverityLow, model.ConfidenceHigh, ".", 0, "Repository has no top-level README", "README not found", "Ask the repository owner for setup, provenance, and execution instructions.")
		f.Context = "metadata"
		add(f)
	}
	if !hasLicense {
		f := s.finding("REPO-002", "repository-hygiene", model.SeverityLow, model.ConfidenceHigh, ".", 0, "Repository has no top-level license", "license file not found", "Clarify the code's origin and permitted use before redistributing it.")
		f.Context = "metadata"
		add(f)
	}
}

func (s *Scanner) scanSymlink(root, path, rel string, add func(model.Finding)) {
	target, err := os.Readlink(path)
	if err != nil {
		return
	}
	resolved := target
	if !filepath.IsAbs(target) {
		resolved = filepath.Join(filepath.Dir(path), target)
	}
	resolved, err = filepath.Abs(resolved)
	rootAbs, _ := filepath.Abs(root)
	if err != nil || resolved != rootAbs && !strings.HasPrefix(resolved, rootAbs+string(os.PathSeparator)) {
		add(s.finding("SYMLINK-001", "escaping-symlink", model.SeverityHigh, model.ConfidenceHigh, rel, 0, "Symbolic link escapes the repository", "target redacted", "Remove or replace the escaping symbolic link."))
		return
	}
	if _, err := os.Stat(resolved); err != nil {
		add(s.finding("SYMLINK-002", "broken-symlink", model.SeverityMedium, model.ConfidenceMedium, rel, 0, "Broken symbolic link", "target unavailable", "Review the link target and repository packaging."))
	}
}

func (s *Scanner) scanGitMetadata(ctx context.Context, root, gitRel string, add func(model.Finding), coverage *model.Coverage) {
	confined, err := os.OpenRoot(root)
	if err != nil {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, gitRel+": cannot confine Git metadata")
		return
	}
	defer confined.Close()
	read := func(rel string, hook bool) {
		path := filepath.ToSlash(filepath.Join(gitRel, rel))
		if ctx.Err() != nil {
			coverage.Complete = false
			return
		}
		info, err := confined.Lstat(path)
		if os.IsNotExist(err) {
			return
		}
		if err != nil || !info.Mode().IsRegular() {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (unreadable or non-regular Git metadata)")
			return
		}
		if coverage.FilesScanned >= s.opts.Limits.MaxFiles {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (file-count limit)")
			return
		}
		coverage.FilesScanned++
		if info.Size() > s.opts.Limits.MaxFileBytes {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (file-size limit)")
			return
		}
		file, err := openConfinedNonblocking(confined, path)
		if err != nil {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (cannot open Git metadata)")
			return
		}
		defer file.Close()
		openedInfo, err := file.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (Git metadata changed while scanning)")
			return
		}
		data, err := io.ReadAll(io.LimitReader(file, s.opts.Limits.MaxFileBytes+1))
		if err != nil || int64(len(data)) > s.opts.Limits.MaxFileBytes || ctx.Err() != nil {
			coverage.Complete = false
			coverage.Skipped = append(coverage.Skipped, path+" (Git metadata read or size limit)")
			return
		}
		coverage.BytesScanned += int64(len(data))
		mode := os.FileMode(0)
		if hook {
			mode = 0o700
			if suspiciousHook(data) {
				f := s.finding("GITHOOK-002", "git-hook", model.SeverityCritical, model.ConfidenceHigh, path, 0, "Active Git hook contains execution or remote-fetch behavior", "suspicious behavior in active hook", "Disable the hook and review its complete data flow before running Git commands.")
				f.Context = "git-hook"
				add(f)
			}
		}
		s.scanContent(path, data, mode, add, coverage)
	}
	for _, rel := range []string{"config", "config.worktree", filepath.Join("info", "attributes")} {
		read(rel, false)
	}
	hooksPath := filepath.ToSlash(filepath.Join(gitRel, "hooks"))
	info, err := confined.Lstat(hooksPath)
	if os.IsNotExist(err) {
		return
	}
	if err != nil || !info.IsDir() {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, hooksPath+" (unreadable or non-directory hooks)")
		return
	}
	hooksDir, err := confined.Open(hooksPath)
	if err != nil {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, hooksPath+" (cannot open hooks)")
		return
	}
	defer hooksDir.Close()
	hooks, err := hooksDir.ReadDir(-1)
	if err != nil {
		coverage.Complete = false
		coverage.Skipped = append(coverage.Skipped, hooksPath+" (cannot list hooks)")
		return
	}
	for _, hook := range hooks {
		if strings.HasSuffix(strings.ToLower(hook.Name()), ".sample") {
			continue
		}
		read(filepath.Join("hooks", hook.Name()), true)
	}
}

func suspiciousHook(data []byte) bool {
	l := strings.ToLower(string(data))
	for _, needle := range []string{"curl ", "wget ", "eval ", "node -e", "python -c", "bash -c", "powershell", "/dev/tcp/", "base64 -d"} {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}
