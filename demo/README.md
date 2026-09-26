# Inert take-home assignment demonstration

Inspect before you execute. Repyy identifies risks; it cannot prove that a repository is safe.

`cases.json` stores eight risky fixture descriptions and eight paired controls as data. The
benchmark materializes them in temporary directories, invokes only Repyy, and removes them
afterward. It never installs packages, starts the project, opens an IDE, runs hooks or starts
Compose. Do not run assignment-controlled commands or open materialized fixtures in a task-enabled
IDE.

Reviewed: 2026-09-15. Benchmark 1.1.0; see the generated results for the scanner build.

## Safety design

JavaScript examples use inert strings or harmless local configuration. The startup example imports
only its local marker module; reproduction never executes it. The lifecycle and hook examples
only print markers. The IDE command names a nonexistent marker. The Docker image uses a nonexistent
image on a reserved `.invalid` registry. Credential references are fake path strings; no file read
or credential collection exists. Network/evaluation examples are quoted text, with no callable
downloader or execution chain. Fixtures are created without executable permissions.

The standalone [repyy-demo repository](https://github.com/Kevin-Umali/repyy-demo) publishes this
inert corpus as benchmark [v1.1.0](https://github.com/Kevin-Umali/repyy-demo/tree/v1.1.0).
Its checked-in reports were generated with the verified official Repyy v0.5.1 Linux binary from
commit `261cc64bde67b9c73ba23021e052c330f64bbd05`. The same samples are available on this site.

## Observed corpus evidence

The site's [real-corpus example](https://repyy.dev/demo/#real-corpus) is separate from this inert benchmark. An earlier scan reviewed the [malicious-repositories corpus](https://github.com/xndbogdan/malicious-repositories/tree/dc82f332dae0f4e9ea6bdc1d8341c7743c59913f) at commit `dc82f332dae0f4e9ea6bdc1d8341c7743c59913f` with Repyy rules `2026.09.19`. It observed a missed `process-log` package indicator, an Axios response passed to `eval` without source-to-sink correlation, and three skipped DEX locale files that kept coverage incomplete. Rules `2026.09.26` add the relevant package record and bounded Axios correlation. A local replay was run, but its results have not yet been reviewed and published as the demo. These are example review paths, not a published measurement of the new rules or an accuracy score.

[OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) publishes package advisory reports. It is an intelligence source, distinct from the repository sample corpus. Neither source establishes remote payload contents or a common actor.

## Reproduce

From the Repyy source checkout, build Repyy itself and run its trusted benchmark runner:

```sh
go build -o /tmp/repyy ./cmd/repyy
python3 scripts/benchmark.py --binary /tmp/repyy --output /tmp/repyy-demo --check
```

The runner invokes only that binary. It writes `results.json`, `results.md`, `sample.json`,
`sample.txt` and `sample.html`. Open the HTML report locally, or inspect the checked-in
[sample report](https://repyy.dev/demo/sample/sample.html) without installing anything. Generated timestamps
identify the run; scan durations and temporary root names are normalized for publication. Samples
use local fixture identities, not a fabricated remote commit.

## Expected outcomes and controls

| Fixture                                                                                                                                   | Rule evidence                                                                                | Regression check                                                                          | Paired control                           |
| ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------- |
| [Install lifecycle script](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/demo/cases.json#L5)                                           | [PKG-001](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/catalog.go#L158)    | [Benchmark runner](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/scripts/benchmark.py) | Ordinary test script                     |
| [Startup configuration dynamically imports a harmless local module](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/demo/cases.json#L18) | [IMPORT-001](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/builtin.go#L44)  | [Benchmark runner](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/scripts/benchmark.py) | Static harmless PostCSS configuration    |
| [Executable-looking text in an image filename](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/demo/cases.json#L32)                      | [EXEC-001](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/builtin.go#L14)    | [Benchmark runner](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/scripts/benchmark.py) | SVG with only image markup               |
| [IDE folder-open task](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/demo/cases.json#L45)                                              | [IDE-001](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/builtin.go#L47)     | [Benchmark runner](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/scripts/benchmark.py) | Manual task without automatic run option |
| [Git commit hook](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/demo/cases.json#L58)                                                   | [GITHOOK-001](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/builtin.go#L60) | [Benchmark runner](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/scripts/benchmark.py) | Inactive sample hook                     |
| [Encoded download-and-execute indicators](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/demo/cases.json#L71)                           | [CHAIN-001](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/builtin.go#L27)   | [Benchmark runner](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/scripts/benchmark.py) | Normal display string                    |
| [Credential path reference](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/demo/cases.json#L84)                                         | [CRED-001](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/builtin.go#L30)    | [Benchmark runner](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/scripts/benchmark.py) | Specific benign environment variable     |
| [Docker socket mount](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/demo/cases.json#L97)                                               | [DOCKER-001](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/builtin.go#L57)  | [Benchmark runner](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/scripts/benchmark.py) | Ordinary read-only data volume           |

Benchmark 1.1.0 detects all eight expected indicators. This is a small synthetic regression result,
not proof of malware detection accuracy or safe repositories. The runner fails on changes to the
declared baseline; future misses must remain visible.

Every observed rule, including lower-severity control findings, is retained in `results.json`. A
control counts as incorrectly flagged in the headline metric when it receives a high/critical
finding. This narrow metric does not hide its other findings; read the case details.
Unsupported/skipped and incomplete scans are counted separately. All eight cases currently complete
without skipped content.

## Benchmark versioning

Version this corpus separately from Repyy. Add a paired control with every new risky case. Preserve
difficult cases and known misses. Change expectations explicitly and explain why. This is a small
synthetic regression corpus, not a representative malware dataset or a universal accuracy score. The
benchmark runner is the cross-package regression check; use `repyy rules explain RULE-ID` to inspect
each linked rule's evidence and guidance.

## Changes from benchmark 1.0.0

The original startup fixture placed `require(computedModule)` inside a string. Its absence from the
findings did not demonstrate missed startup behavior. Version 1.1.0 preserves that marker file and
uses a real dynamic import of this harmless local file in the startup configuration. IMPORT-001 now
measures the observable import indicator; complete startup call-graph analysis remains unsupported.

The folder-open fixture is unchanged. Repyy v0.5.1 corrects IDE-001 to recognize the quoted JSON
`"runOn"` key. Its [paired scanner regression](https://github.com/Kevin-Umali/repyy/blob/v0.5.1/internal/scan/ide_test.go)
checks that automatic execution is flagged and the manual-task control is not. No difficult fixture
was removed to improve the result. Prior 1.0.0 fixtures and results remain in Git history.

Intentional exception to the usual contribution rule against generated reports: the reviewed public
samples under `site/public/demo/sample/` are product artifacts. Never commit reports from private
repositories.
