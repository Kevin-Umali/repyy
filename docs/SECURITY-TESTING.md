# Security Testing

Reviewed: 2026-10-27. Describes current source tests and bounded CI fuzzing.

Repyy processes hostile input. Tests exercise the scanner itself; no fixture is intentionally
executed as an assignment. Passing tests do not establish that a repository or Repyy is free of
vulnerabilities.

## Behavioral test coverage

Unit tests cover rule matching, severity/context, configuration and suppressions, report fields and
exit policy. Integration tests invoke the built CLI against inert local fixtures. Source tests
verify URL rejection and sanitized Git configuration. Docker unit tests use a fake Docker executable
to test invocation and hostile JSON handling; they are not live isolation-escape tests. CI
separately builds and starts the worker image for a version smoke check.

Focused inert fixtures also cover advisory version semantics, bounded JavaScript
literal recovery, unsupported/limited decode coverage, same-function Axios
response-to-execution with ordinary request controls, and generated vendor
bundle noise. The four skipped corpus paths were traced to invalid UTF-8 in
their first 8 KiB; unsupported text remains visible as incomplete coverage.

Python startup-hook fixtures cover executable `.pth` import lines, BOM and line
ending handling, benign path
entries and comments, customization modules, local wheel entries, context
downgrades, and undecodable startup files. Python remote-response fixtures check
connected execution paths, direct nested calls, overwritten values, unrelated
functions and benign comments. Package indicators distinguish exact compromised
releases from other resolved versions and unlocked ranges.

`internal/scan/repository_test.go` covers Git metadata and symlink behavior; `archive_test.go` covers
archive traversal, ZIP64 size bounds and nested inspection; `active_content_test.go` covers staged execution, active document content, and VSIX packages;
`context_test.go` checks prompt-injection context; and `scanner_test.go` exercises cross-surface
acceptance. `internal/output/output_test.go` checks terminal control neutralization,
HTML escaping, source-link validation, redaction and report integrity.
`internal/intel/update_test.go` covers signed updates and failure behavior.

Tests use fixed inert examples with expected findings and benign controls. A test that derives its
expected match from the production regex can pass when the regex changes incorrectly. Catalog ID
lists and snapshots can catch edits but do not prove detection. New bug tests must cover a behavior
that existing tests miss; expand an existing test when it already covers that path.

## Fuzz targets and properties

| Target                 | Input surface                            | Property / bounds                                                                                                     |
| ---------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| FuzzArchiveInspection  | ZIP, TAR and gzip bytes                  | No crash or unbounded diagnostics; 64 KiB input, 32 entries, 64 KiB expansion, 16 KiB file, depth 2, context deadline |
| FuzzArchivePaths       | Portable archive paths                   | Accepted paths cannot normalize outside the root; 4 KiB input; Windows and POSIX seeds                                |
| FuzzSymlinkConfinement | Symbolic-link targets                    | Scanner reads no bytes through repository symlinks; 4 KiB target, controlled external sentinel                        |
| FuzzGitMetadata        | `.git/config`                            | Metadata includes are data and cannot add external file bytes; 8 KiB input in an isolated temp root                   |
| FuzzConfiguration      | Explicit trusted YAML                    | Parse/validation handles malformed input and rejects unsupported versions; 8 KiB input                                |
| FuzzManifests          | Eight manifest formats                   | No panic and no negative source locations; 8 KiB input; no package-manager execution                                  |
| FuzzHumanOutput        | Repository-controlled filenames/messages | Terminal controls neutralized and injected script markup escaped in HTML; 4 KiB string                                |
| FuzzJSONReports        | Serialized report objects                | Accepted input re-renders as valid JSON; 16 KiB input                                                                 |

Archive seeds include valid ZIP, TAR and TAR.GZ files, nested ZIPs, traversal paths, expansion
limits and entry-count limits, alongside malformed inputs. These are bounded starting targets, not
exhaustive coverage. Context cancellation is cooperative,
not a hard CPU/memory guarantee. CI supplies a 30-minute package-job timeout and two workers per target. Concurrent
symlink replacement, full Git transport/SSH behavior, live Docker isolation and every report field
still need broader testing and independent review.

## Run and reproduce

```sh
make check
make security
go test ./internal/scan -run '^$' -fuzz '^FuzzArchiveInspection$' -fuzztime 50000x -parallel 2
```

Use the corresponding package and target name for the remaining targets. Ordinary `go test` runs the
seed corpus. CI uses fixed execution counts per target on relevant changes and all main pushes. The daily
Security evidence workflow runs ten times those counts. The [fuzz workflow](../.github/workflows/fuzz.yml) defines the budgets. Fixed execution budgets avoid a
possible Go fuzz-coordinator duration deadline race. The archive limits remain unchanged. Read the workflow run rather than assuming a scheduled run happened.
Fuzz logs and available failing inputs are uploaded even if a target fails.

For a failure, preserve the generated corpus input under the package's `testdata/fuzz/TARGET/` and
minimize it. Fix the violated property and rerun both the seed and fuzz target. Add a named
behavioral test when existing coverage cannot express that property; otherwise expand the relevant
test. Do not replace the input with live malware or remove it to obtain a passing run.

## Public benchmark

The [inert sample benchmark](https://repyy.dev/demo/sample/results.json) and its versioned paired controls are a separate behavioral check.
Per-release results are attached by the release workflow. Known misses and all observed rules remain
public; a synthetic benchmark does not establish general accuracy.

## Known gaps and independent review

Short fuzz runs cannot exhaust the input space. Tests using fake host tools cannot prove the
behavior of every installed Git/Docker version. OS-specific permission and symlink behavior requires
platform CI. Resource limits do not provide dedicated-VM isolation. Best-effort cleanup can leave
temporary data after failures.

The [external-review brief](EXTERNAL-REVIEW.md) identifies the required independent scope. Until a
reviewer publishes their identity, exact reviewed commit, findings and retest outcome, the project
must not claim an independent audit.

Report newly found vulnerabilities using
[private reporting](https://github.com/Kevin-Umali/repyy/security/advisories/new).
