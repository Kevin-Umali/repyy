package app

import (
	"fmt"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/output"
	"io"
	"sort"
	"sync"
	"time"
)

type scanProgressState struct {
	target  string
	started time.Time
	files   int
	bytes   int64
}

type scanProgress struct {
	mu      sync.Mutex
	w       io.Writer
	mode    string
	active  map[int]*scanProgressState
	stop    chan struct{}
	stopped chan struct{}
}

func newScanProgress(w io.Writer, mode string) *scanProgress {
	p := &scanProgress{w: w, mode: mode, active: map[int]*scanProgressState{}}
	if mode != "quiet" {
		p.stop = make(chan struct{})
		p.stopped = make(chan struct{})
		go p.loop()
	}
	return p
}

func (p *scanProgress) loop() {
	defer close(p.stopped)
	interval := 2 * time.Second
	if p.mode == "interactive" {
		interval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.printUpdates()
		case <-p.stop:
			return
		}
	}
}

func (p *scanProgress) start(index int, target string) {
	if p.mode == "quiet" {
		return
	}
	target = output.SanitizeSourceText(target)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active[index] = &scanProgressState{target: target, started: time.Now()}
	if p.mode == "interactive" {
		p.renderInteractive()
	} else {
		fmt.Fprintf(p.w, "repyy: scanning %s...\n", target)
	}
}

func (p *scanProgress) update(index, files int, bytes int64) {
	if p.mode == "quiet" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if state := p.active[index]; state != nil {
		state.files = files
		state.bytes = bytes
	}
}

func (p *scanProgress) finish(index int, result model.RepoResult) {
	if p.mode == "quiet" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.active[index]
	delete(p.active, index)
	if state == nil {
		return
	}
	if p.mode == "interactive" {
		fmt.Fprint(p.w, "\r\x1b[2K")
	}
	if result.Error != "" {
		fmt.Fprintf(p.w, "repyy: scan failed for %s after %s\n", state.target, formatDuration(result.Duration))
		return
	}
	fmt.Fprintf(p.w, "repyy: scanned %s (%d files, %s) in %s\n", state.target, result.Coverage.FilesScanned, formatBytes(result.Coverage.BytesScanned), formatDuration(result.Duration))
	if p.mode == "interactive" && len(p.active) > 0 {
		p.renderInteractive()
	}
}

func (p *scanProgress) printUpdates() {
	p.mu.Lock()
	defer p.mu.Unlock()
	indexes := make([]int, 0, len(p.active))
	for index := range p.active {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	if p.mode == "interactive" {
		p.renderInteractive()
		return
	}
	for _, index := range indexes {
		state := p.active[index]
		fmt.Fprintf(p.w, "repyy: scanning %s (%d files, %s, %s elapsed)\n", state.target, state.files, formatBytes(state.bytes), formatDuration(time.Since(state.started)))
	}
}

func (p *scanProgress) renderInteractive() {
	if len(p.active) == 0 {
		return
	}
	if len(p.active) == 1 {
		for _, state := range p.active {
			fmt.Fprintf(p.w, "\r\x1b[2Krepyy: scanning %s · %d files · %s · %s", state.target, state.files, formatBytes(state.bytes), formatDuration(time.Since(state.started)))
		}
		return
	}
	files, bytes := 0, int64(0)
	oldest := time.Now()
	for _, state := range p.active {
		files += state.files
		bytes += state.bytes
		if state.started.Before(oldest) {
			oldest = state.started
		}
	}
	fmt.Fprintf(p.w, "\r\x1b[2Krepyy: scanning %d repositories · %d files · %s · %s", len(p.active), files, formatBytes(bytes), formatDuration(time.Since(oldest)))
}

func (p *scanProgress) close() {
	if p.mode == "quiet" {
		return
	}
	close(p.stop)
	<-p.stopped
	if p.mode == "interactive" {
		fmt.Fprint(p.w, "\r\x1b[2K")
	}
}

func formatBytes(bytes int64) string {
	const unit = int64(1024)
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	value := float64(bytes)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, name := range units {
		value /= float64(unit)
		if value < float64(unit) || name == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", value, name)
		}
	}
	return fmt.Sprintf("%d B", bytes)
}

func formatDuration(duration time.Duration) string {
	if duration < time.Second {
		return duration.Round(time.Millisecond).String()
	}
	return duration.Round(time.Second).String()
}

func resolveProgressMode(opts scanArgs, writer io.Writer) string {
	if opts.progress == "quiet" {
		return "quiet"
	}
	if opts.progress == "plain" {
		return "plain"
	}
	if isTerminalWriter(writer) && (opts.format == "terminal" || opts.output != "") {
		return "interactive"
	}
	if opts.format == "terminal" {
		return "plain"
	}
	return "quiet"
}
