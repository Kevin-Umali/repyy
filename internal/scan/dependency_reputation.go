package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Kevin-Umali/repyy/internal/manifest"
	"github.com/Kevin-Umali/repyy/internal/model"
	"github.com/Kevin-Umali/repyy/internal/registry"
)

// Registry lookups are opt-in network requests made after the local walk.
// These bounds keep one scan from issuing an unbounded request fan-out.
const (
	maxRegistryPackages = 200
	registryWorkers     = 4
	registryBudget      = 90 * time.Second
	maxRegistryWarnings = 5
)

// Thresholds for the reputation policy. A package is "new" inside
// newPackageAge, "recent" inside recentPackageAge, "few versions" at or below
// fewVersions, and "rarely used" below rareWeeklyDownloads on npm.
const (
	newPackageAge       = 30 * 24 * time.Hour
	recentPackageAge    = 90 * 24 * time.Hour
	fewVersions         = 2
	rareWeeklyDownloads = 100
	tinyWeeklyDownloads = 1000
)

type dependencyDeclaration struct {
	path    string
	line    int
	name    string
	version string
}

// dependencyLedger gathers registry-resolvable declarations during one scan so each
// unique package is looked up once after the walk. Only the walk's merge step writes
// it, in walk order.
type dependencyLedger struct {
	declared map[registry.Package][]dependencyDeclaration
	// local holds npm package names defined by the repository's own
	// package.json files; workspace siblings are not registry packages.
	local map[string]bool
}

func newDependencyLedger() *dependencyLedger {
	return &dependencyLedger{declared: map[registry.Package][]dependencyDeclaration{}, local: map[string]bool{}}
}

// observe records direct declarations from a repository manifest. ownName is the
// npm package the manifest itself defines, if any. Lockfile entries (transitive),
// archive members, and vendored dependency trees are left out: the check targets what
// this repository itself asks to install.
func (l *dependencyLedger) observe(path, ownName string, dependencies []manifest.Dependency) {
	if l == nil || strings.Contains(path, "!") || insideDependencyDir(path) {
		return
	}
	if ownName != "" {
		l.local[ownName] = true
	}
	for _, dependency := range dependencies {
		if dependency.Scope == "lockfile" {
			continue
		}
		pkg, ok := registry.Normalize(dependency.Ecosystem, dependency.Name, dependency.Version)
		if !ok {
			continue
		}
		l.declared[pkg] = append(l.declared[pkg], dependencyDeclaration{path: path, line: dependency.Line, name: dependency.Name, version: dependency.Version})
	}
}

func (l *dependencyLedger) external() map[registry.Package][]dependencyDeclaration {
	declared := make(map[registry.Package][]dependencyDeclaration, len(l.declared))
	for pkg, declarations := range l.declared {
		if pkg.Ecosystem == registry.NPM && l.local[pkg.Name] {
			continue
		}
		declared[pkg] = declarations
	}
	return declared
}

// npmPackageName returns the name a package.json defines, or "" for other files.
func npmPackageName(path string, data []byte) string {
	if filepath.Base(path) != "package.json" {
		return ""
	}
	var own struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &own) != nil {
		return ""
	}
	return own.Name
}

func insideDependencyDir(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if dependencyDirs[segment] {
			return true
		}
	}
	return false
}

type registryOutcome struct {
	record registry.Record
	err    error
}

// reportDependencyReputation looks up every collected package and emits
// PKG-010/PKG-011 findings. A lookup that fails marks coverage incomplete so an
// unreachable registry is never reported as a clean result.
func (s *Scanner) reportDependencyReputation(ctx context.Context, ledger *dependencyLedger, add func(model.Finding), coverage *model.Coverage) {
	if ledger == nil {
		return
	}
	declared := ledger.external()
	if len(declared) == 0 {
		return
	}
	packages := make([]registry.Package, 0, len(declared))
	for pkg := range declared {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Ecosystem != packages[j].Ecosystem {
			return packages[i].Ecosystem < packages[j].Ecosystem
		}
		return packages[i].Name < packages[j].Name
	})
	if len(packages) > maxRegistryPackages {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, fmt.Sprintf("registry check limited to %d of %d declared packages", maxRegistryPackages, len(packages)))
		packages = packages[:maxRegistryPackages]
	}

	ctx, cancel := context.WithTimeout(ctx, registryBudget)
	defer cancel()
	outcomes := make([]registryOutcome, len(packages))
	next := make(chan int)
	var wg sync.WaitGroup
	for range registryWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				outcomes[i] = s.lookupReputation(ctx, packages[i])
			}
		}()
	}
	for i := range packages {
		next <- i
	}
	close(next)
	wg.Wait()

	now := time.Now().UTC()
	var failed []string
	for i, pkg := range packages {
		outcome := outcomes[i]
		if outcome.err != nil {
			failed = append(failed, string(pkg.Ecosystem)+" "+pkg.Name+" ("+outcome.err.Error()+")")
			continue
		}
		signal, ok := assessReputation(outcome.record, now)
		if !ok {
			continue
		}
		for _, declaration := range declared[pkg] {
			f := s.finding(signal.ruleID, "dependency-reputation", signal.severity, signal.confidence, declaration.path, declaration.line, signal.message, declaration.name+" "+safeEvidence([]byte(declaration.version)), signal.remediation)
			f.Context = signal.context
			add(f)
		}
	}
	if len(failed) > 0 {
		coverage.Complete = false
		shown := failed
		if len(shown) > maxRegistryWarnings {
			shown = shown[:maxRegistryWarnings]
		}
		warning := fmt.Sprintf("registry check failed for %d of %d packages: %s", len(failed), len(packages), strings.Join(shown, "; "))
		if len(failed) > len(shown) {
			warning += fmt.Sprintf("; and %d more", len(failed)-len(shown))
		}
		coverage.Warnings = append(coverage.Warnings, warning)
	}
}

func (s *Scanner) lookupReputation(ctx context.Context, pkg registry.Package) registryOutcome {
	if err := ctx.Err(); err != nil {
		return registryOutcome{err: fmt.Errorf("time budget exhausted")}
	}
	record, err := s.opts.Registry.Lookup(ctx, pkg)
	if err != nil {
		return registryOutcome{err: err}
	}
	if needsDownloadCount(record, time.Now().UTC()) {
		downloads, err := s.opts.Registry.WeeklyDownloads(ctx, pkg)
		if err != nil {
			return registryOutcome{err: err}
		}
		record.WeeklyDownloads = downloads
	}
	return registryOutcome{record: record}
}

// needsDownloadCount limits the second npm request to packages whose
// assessment can change with it.
func needsDownloadCount(record registry.Record, now time.Time) bool {
	return record.Ecosystem == registry.NPM && record.Status == registry.Published &&
		(record.Versions <= fewVersions || now.Sub(record.FirstPublished) < recentPackageAge)
}

type reputationSignal struct {
	ruleID      string
	context     string
	severity    model.Severity
	confidence  model.Confidence
	message     string
	remediation string
}

// assessReputation is the PKG-010/PKG-011 policy. Age alone is weak evidence,
// so only the combination of a brand-new package, almost no release history,
// and almost no downloads reaches high severity.
func assessReputation(record registry.Record, now time.Time) (reputationSignal, bool) {
	label := string(record.Ecosystem) + " package " + record.Name
	switch record.Status {
	case registry.SecurityHold:
		return reputationSignal{"PKG-011", "confirmed-ioc", model.SeverityCritical, model.ConfidenceHigh,
			label + " has been replaced by npm's security placeholder, which npm publishes after removing malware",
			"Do not install dependencies. Remove the dependency and treat any machine that installed it as compromised."}, true
	case registry.Unpublished:
		return reputationSignal{"PKG-011", "manifest-review", model.SeverityHigh, model.ConfidenceMedium,
			label + " exists on the public registry but all of its releases were removed",
			"Do not install dependencies until the package's removal is explained; removed packages are often taken down for malware."}, true
	case registry.Missing:
		if strings.HasPrefix(record.Name, "@") {
			return reputationSignal{"PKG-011", "manifest-review", model.SeverityMedium, model.ConfidenceLow,
				label + " is not on the public registry; it may come from a private registry",
				"Confirm which registry serves this scope before installing; an unclaimed public name can be registered by anyone."}, true
		}
		return reputationSignal{"PKG-011", "manifest-review", model.SeverityHigh, model.ConfidenceMedium,
			label + " does not exist on the public registry",
			"Do not install dependencies until the package source is confirmed; a missing public name can be registered by an attacker or was removed as malware."}, true
	}

	age := now.Sub(record.FirstPublished)
	facts := fmt.Sprintf("first published %s; %d version%s", describeAge(age), record.Versions, plural(record.Versions))
	if record.WeeklyDownloads >= 0 {
		facts += fmt.Sprintf("; %d downloads last week", record.WeeklyDownloads)
	}
	remediation := "Review the package source, publisher, and install scripts before installing; new or rarely used packages are a common malware delivery path."
	knownTiny := record.WeeklyDownloads >= 0 && record.WeeklyDownloads < tinyWeeklyDownloads
	knownRare := record.WeeklyDownloads >= 0 && record.WeeklyDownloads < rareWeeklyDownloads
	switch {
	case age < newPackageAge && record.Versions <= fewVersions && knownTiny:
		return reputationSignal{"PKG-010", "manifest-review", model.SeverityHigh, model.ConfidenceMedium, label + " is newly published with almost no history or usage: " + facts, remediation}, true
	case age < newPackageAge:
		return reputationSignal{"PKG-010", "manifest-review", model.SeverityMedium, model.ConfidenceMedium, label + " is newly published: " + facts, remediation}, true
	case age < recentPackageAge:
		return reputationSignal{"PKG-010", "manifest-review", model.SeverityMedium, model.ConfidenceLow, label + " was published recently: " + facts, remediation}, true
	case record.Versions <= fewVersions && knownRare:
		return reputationSignal{"PKG-010", "manifest-review", model.SeverityMedium, model.ConfidenceLow, label + " is rarely used: " + facts, remediation}, true
	}
	return reputationSignal{}, false
}

func describeAge(age time.Duration) string {
	days := int(age.Hours() / 24)
	switch {
	case days < 1:
		return "less than a day ago"
	case days == 1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", days)
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
