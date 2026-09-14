# CLI reference

This page is a practical reference for the commands and flags exposed by `repyy`. Run `repyy help`
to print the same top-level summary.

## Command shape

```text
repyy scan [options] <path-or-git-url>...
repyy report [options] <report.json|->
repyy rules validate <rules.yaml>
repyy rules check
repyy rules list [--format terminal|json]
repyy rules explain <rule-id> [--format terminal|json]
repyy intel status [--format terminal|json]
repyy intel update
repyy intel rollback
repyy version
```

Targets can be local paths or Git URLs. Scan several targets in one run:

```sh
repyy scan ./project ../another-project https://github.com/org/repo
```

The scanner reads targets as data. It does not import, build, test, or execute their code. Local
scans do not need network access. Remote host scans clone the requested repository; Docker remote
scans use a temporary networked fetch stage.

## `scan` options

| Option                   | Values/default      | What it does                                                                                                                |
| ------------------------ | ------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `--file PATH`            | one target per line | Appends targets from a text file after command-line targets. Blank and `#` comment lines are ignored.                       |
| `--format`               | `terminal`          | Selects `terminal`, `json`, `sarif`, or `html` output.                                                                      |
| `--output PATH`          | stdout              | Writes the report to a file. HTML and JSON are useful for saving; SARIF is suitable for code scanning tools.                |
| `--jobs N`               | `4`                 | Maximum concurrent repositories; must be 1–128.                                                                             |
| `--config PATH`          | none                | Loads a trusted version-1 YAML file containing extra rules and suppressions.                                                |
| `--include-dependencies` | off                 | Scans dependency/cache trees such as `node_modules`, `.venv`, `vendor`, `target`, and `Pods`. These are skipped by default. |
| `--history N\|all`       | `1`                 | Remote Git history depth. `all` requests the full history.                                                                  |
| `--keep-workdir`         | off                 | Keeps host-mode remote checkouts for follow-up review. Unsupported with Docker.                                             |
| `--sandbox`              | `host`              | Uses `host` or the opt-in `docker` analysis backend. `vm` and `auto` are not available.                                     |
| `--fail-on LEVEL`        | `high`              | Exit code becomes 1 when a finding at or above `low`, `medium`, `high`, or `critical` exists.                               |
| `--timeout DURATION`     | `10m`               | Per-repository timeout, for example `30s`, `5m`, or `1h`. Must be positive.                                                 |
| `--max-files N`          | `100000`            | Maximum files scanned per repository.                                                                                       |
| `--max-file-size BYTES`  | `52428800`          | Maximum bytes read from one file (50 MiB).                                                                                  |
| `--detail`               | `review`            | `summary`, `review`, or `all` controls how much detail is printed.                                                          |
| `--progress`             | `auto`              | `auto`, `plain`, or `quiet` controls progress output.                                                                       |
| `--color`                | `auto`              | `auto`, `always`, or `never` controls terminal color. `NO_COLOR` is also respected.                                         |
| `--min-severity LEVEL`   | `low`               | Display filter for `low`, `medium`, `high`, or `critical`; it does not alter the verdict.                                   |
| `--min-confidence LEVEL` | `low`               | Display filter for `low`, `medium`, or `high`; it does not alter the verdict.                                               |
| `--group-by`             | `severity`          | Groups presentation by `severity`, `file`, or `rule`.                                                                       |

The default resource limits also bound archive work: 10,000 archive entries, 1 GiB of archive bytes,
and archive nesting depth 3. A limit or read error is reported as `SCAN INCOMPLETE`; do not treat an
incomplete result as clean. Flags may appear before or after targets. Value flags accept a space or
`=`, such as `--format html` and `--format=html`.

For `--file targets.txt`, create a UTF-8 text file like this:

```text
# Review queue
./assignment-a
https://github.com/org/assignment-b
```

### Common scan recipes

```sh
# Review a local checkout and save an HTML report.
repyy scan ./checkout --format html --output review.html

# Scan a remote repository with a pinned Docker image.
repyy scan https://github.com/org/repo --sandbox docker --format json --output scan.json

# CI-friendly SARIF output; fail for medium and above.
repyy scan . --format sarif --output repyy.sarif --fail-on medium --progress quiet --color never

# Include generated dependency trees and show only high-confidence critical findings.
repyy scan . --include-dependencies --min-severity critical --min-confidence high

# Read targets from a file (one path or URL per line).
repyy scan --file targets.txt

# Give a large repository more time and a higher per-file byte limit.
repyy scan ./large-repo --timeout 20m --max-file-size 104857600

# See every finding grouped by file without changing the exit threshold.
repyy scan ./repo --detail all --group-by file --fail-on high
```

### Exit codes and verdicts

`0` means no finding reached `--fail-on`. `1` means the threshold was reached. `2` means a target
could not be fully scanned or another runtime failure occurred. `3` means the command, flag, or
configuration is invalid. A `NO FINDINGS` result is not proof that a repository is safe. In a mixed
multi-target scan, code `2` takes priority over code `1`, while successful targets remain visible in
the report.

## `report`

Render a previously generated JSON report without rescanning:

```sh
repyy report scan.json --format html --output review.html
repyy report scan.json --format terminal --detail summary
cat scan.json | repyy report - --format sarif --output results.sarif
```

It accepts `--format terminal|html|sarif`, `--output PATH`, `--detail summary|review|all`,
`--color auto|always|never`, `--min-severity`, `--min-confidence`, and `--group-by`. The filters
affect presentation only; they do not change the scan's recorded verdict or exit policy. The default
format is HTML. The input must be a valid repyy JSON scan of at most 64 MiB. repyy rejects a verdict
that conflicts with the findings or coverage. For a valid saved report, rendering returns `2` for
incomplete coverage, `1` when a high or critical finding exists, and `0` otherwise. Invalid input
returns `3`. Display filters do not change these codes. Only render JSON produced by a scan you
trust. Verdict validation catches contradictions within a report; JSON is not signed and cannot
reveal findings that someone removed before sharing it.

## Rules and intelligence commands

“Intel” means offline threat intelligence: a dated snapshot of sourced malicious-package advisories,
affected versions, and published SHA-256 file indicators. It is separate from the scanner’s
behavioral rules and is not AI or a cloud scan. A package-name match alone is a review signal;
compare the resolved version with the advisory before treating it as confirmed. `repyy intel status`
shows whether the scan will use the embedded snapshot or a verified cached one.

Use these offline inspection commands when a finding needs context:

```sh
repyy rules list
repyy rules list --format json
repyy rules explain EXEC-001
repyy rules check
repyy intel status
repyy intel status --format json
```

`repyy intel update` explicitly downloads and verifies a public intelligence snapshot.
`repyy intel rollback` restores the previous verified cached snapshot. Scans never update
intelligence automatically.

## Human status and build identity

Terminal and HTML reports display “Findings detected”, “Review required”, “No relevant findings
detected”, or “Scan incomplete”. Schema-1 JSON retains its existing `DO NOT RUN`, `REVIEW REQUIRED`,
`NO FINDINGS`, and `SCAN INCOMPLETE` values for consumers. See [the full status mapping](TRUST.md).

`repyy version` includes commit, builder, source, Go version and build date. Local builds identify
their builder as development. Reports retain the scanner's `tool_commit` and an explicit
static-analysis limitation. A missing original commit remains unknown; converting an old report does
not invent one.

Temporary checkout deletion failures preserve findings, add a warning and select incomplete
status/exit 2. Authentication-file cleanup failures and failed forced container removal also return
errors. Abrupt termination can still leave data behind before cleanup runs.

### Recorded scan context

Reports from v0.5.1 include `scan_mode` (`host` or `docker`) per repository. HTML displays this
alongside repository identity. Legacy reports with no recorded mode show unknown; an existing Docker
isolation record can identify its mode. A local scan does not run Git to discover a commit, so HTML
explicitly marks its commit as unavailable. Remote scans retain the fetched commit for source links.
