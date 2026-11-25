package scan

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/Kevin-Umali/repyy/internal/manifest"
	"github.com/Kevin-Umali/repyy/internal/model"
	"golang.org/x/sync/semaphore"
)

// walkStep is everything one walk event contributes to a scan. Steps are produced
// concurrently and applied in walk order, so a parallel scan reports exactly what a
// serial scan would.
type walkStep struct {
	findings  []model.Finding
	coverage  model.Coverage
	cargoPath string
	cargoData []byte
	manifest  *declaredManifest
	progress  bool
	done      chan struct{}
}

func newWalkStep() *walkStep {
	return &walkStep{coverage: model.Coverage{Complete: true}, done: make(chan struct{})}
}

func (step *walkStep) add(f model.Finding) {
	step.findings = append(step.findings, f)
}

func (step *walkStep) skip(reason string) {
	step.coverage.Complete = false
	step.coverage.Skipped = append(step.coverage.Skipped, reason)
}

func (step *walkStep) warn(warning string) {
	step.coverage.Complete = false
	step.coverage.Warnings = append(step.coverage.Warnings, warning)
}

func mergeCoverage(into *model.Coverage, from model.Coverage) {
	into.Complete = into.Complete && from.Complete
	into.FilesScanned += from.FilesScanned
	into.BytesScanned += from.BytesScanned
	into.Skipped = append(into.Skipped, from.Skipped...)
	into.Warnings = append(into.Warnings, from.Warnings...)
}

// declaredManifest is what a manifest file contributes to the dependency ledger.
type declaredManifest struct {
	path         string
	ownName      string
	dependencies []manifest.Dependency
}

var errLimitFiles = errors.New("file-count limit reached")

// readBudget caps the bytes of file content held by in-flight jobs, so a tree of large
// files cannot multiply peak memory by the worker count.
const readBudget = 128 << 20

type fileJob struct {
	rel    string
	info   os.FileInfo
	step   *walkStep
	weight int64
}

// walk visits root, scans regular files on a worker pool, and calls apply for each
// step in walk order from the calling goroutine.
func (s *Scanner) walk(ctx context.Context, root string, confined *os.Root, apply func(*walkStep)) error {
	workers := runtime.GOMAXPROCS(0)
	ordered := make(chan *walkStep, workers*4)
	jobs := make(chan fileJob, workers*4)
	budget := semaphore.NewWeighted(readBudget)

	var pool sync.WaitGroup
	for range workers {
		pool.Add(1)
		go func() {
			defer pool.Done()
			for job := range jobs {
				s.scanFile(ctx, confined, job.rel, job.info, job.step)
				budget.Release(job.weight)
				close(job.step.done)
			}
		}()
	}

	var walkErr error
	go func() {
		defer close(ordered)
		defer close(jobs)
		files := 0
		emit := func(step *walkStep) {
			ordered <- step
			close(step.done)
		}
		walkErr = filepath.WalkDir(root, func(path string, d os.DirEntry, entryErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if entryErr != nil {
				step := newWalkStep()
				step.warn(rel + ": " + entryErr.Error())
				emit(step)
				return nil
			}
			if rel == "." {
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					step := newWalkStep()
					s.scanGitMetadata(ctx, root, rel, s.opts.Limits.MaxFiles-files, step.add, &step.coverage)
					files += step.coverage.FilesScanned
					step.progress = true
					emit(step)
					return filepath.SkipDir
				}
				if !s.opts.IncludeDependencies && dependencyDirs[d.Name()] {
					step := newWalkStep()
					step.coverage.Skipped = append(step.coverage.Skipped, rel+" (dependency/cache tree)")
					emit(step)
					return filepath.SkipDir
				}
				return nil
			}
			info, err := d.Info()
			if err != nil {
				step := newWalkStep()
				step.warn(rel + ": " + err.Error())
				emit(step)
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				step := newWalkStep()
				s.scanSymlink(root, path, rel, step.add)
				if d.Name() == ".git" {
					step.skip(rel + " (linked Git metadata directory)")
				}
				emit(step)
				return nil
			}
			if !info.Mode().IsRegular() {
				step := newWalkStep()
				step.skip(rel + " (non-regular file)")
				emit(step)
				return nil
			}
			if files >= s.opts.Limits.MaxFiles {
				return errLimitFiles
			}
			files++
			step := newWalkStep()
			step.coverage.FilesScanned = 1
			step.progress = true
			if info.Size() > s.opts.Limits.MaxFileBytes {
				step.skip(rel + " (file-size limit)")
				emit(step)
				return nil
			}
			weight := min(info.Size(), readBudget)
			if err := budget.Acquire(ctx, weight); err != nil {
				return err
			}
			ordered <- step
			jobs <- fileJob{rel: rel, info: info, step: step, weight: weight}
			return nil
		})
	}()

	for step := range ordered {
		<-step.done
		apply(step)
	}
	pool.Wait()
	return walkErr
}

// scanFile reads one confined regular file and runs every content detector on it.
func (s *Scanner) scanFile(ctx context.Context, confined *os.Root, rel string, info os.FileInfo, step *walkStep) {
	file, err := openConfinedNonblocking(confined, rel)
	if err != nil {
		step.warn(rel + ": cannot open confined file")
		return
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		file.Close()
		step.skip(rel + " (file changed while scanning)")
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, s.opts.Limits.MaxFileBytes+1))
	file.Close()
	if err != nil || int64(len(data)) > s.opts.Limits.MaxFileBytes || ctx.Err() != nil {
		step.skip(rel + " (file read or size limit)")
		return
	}
	step.coverage.BytesScanned += int64(len(data))
	if looksText(data) {
		switch strings.ToLower(filepath.Base(rel)) {
		case "cargo.toml", "build.rs":
			step.cargoPath, step.cargoData = rel, data
		}
	}
	dependencies := s.scanContent(rel, data, info.Mode(), step.add, &step.coverage)
	if s.opts.Registry != nil {
		if ownName := npmPackageName(rel, data); ownName != "" || len(dependencies) > 0 {
			step.manifest = &declaredManifest{path: rel, ownName: ownName, dependencies: dependencies}
		}
	}
	if isArchive(rel, data) {
		s.scanArchive(ctx, rel, data, 1, step.add, &step.coverage)
	}
	corroborateCapabilities(step.findings)
}
