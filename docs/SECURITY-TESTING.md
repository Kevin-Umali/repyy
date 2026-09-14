# Security Testing

Reviewed: 2026-09-15. Describes the trust-roadmap changes; unreleased features are identified
explicitly.

Repyy processes hostile input. Tests exercise the scanner itself; no fixture is intentionally
executed as an assignment. Passing tests do not establish that a repository or Repyy is free of
vulnerabilities.

## Existing regression coverage

Unit tests cover rule matching, severity/context, configuration and suppressions, report fields and
exit policy. Integration tests invoke the built CLI against inert local fixtures. Source tests
verify URL rejection and sanitized Git configuration. Docker unit tests use a fake Docker executable
to test invocation and hostile JSON handling; they are not live isolation-escape tests. CI
separately builds and starts the worker image for a version smoke check.

`internal/scan/security_regression_test.go`, `scanner_test.go`, and `adversarial_test.go` cover
traversal, symlinks, archive limits, malformed content, unusual encodings, Git metadata and
deceptive source patterns. `internal/output/output_test.go` checks terminal control neutralization,
HTML escaping, source-link validation, redaction and report integrity.
`internal/intel/update_test.go` covers signed updates and failure behavior.

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

These are bounded starting targets, not exhaustive coverage. Context cancellation is cooperative,
not a hard CPU/memory guarantee. CI supplies a 10-minute job timeout and two workers. Concurrent
symlink replacement, full Git transport/SSH behavior, live Docker isolation and every report field
still need broader testing and independent review.

## Run and reproduce

```sh
make check
make security
go test ./internal/scan -run '^$' -fuzz '^FuzzArchiveInspection$' -fuzztime 30s -parallel 2
```

Use the corresponding package and target name for the remaining targets. Ordinary `go test` runs the
seed corpus. The Security evidence workflow runs each target for 10 seconds on changes and 120
seconds on a daily schedule. Read the workflow run rather than assuming a scheduled run happened.
Fuzz failures are uploaded as artifacts when available.

For a failure, preserve the generated corpus input under the package's `testdata/fuzz/TARGET/`,
minimize it, add a named regression test explaining the violated property, fix the bug and rerun
both the seed and fuzz target. Do not replace it with live malware or remove it to obtain a passing
run.

## Public benchmark

The [demo](../demo/README.md) and its versioned paired controls are a separate behavioral check.
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
