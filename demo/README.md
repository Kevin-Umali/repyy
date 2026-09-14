# Inert take-home assignment demonstration

Inspect before you execute. Repyy identifies risks; it cannot prove that a repository is safe.

`cases.json` stores eight risky fixture descriptions and eight paired controls as data. The
benchmark materializes them in temporary directories, invokes only Repyy, and removes them
afterward. It never installs packages, starts the project, opens an IDE, runs hooks or starts
Compose. Do not run assignment-controlled commands or open materialized fixtures in a task-enabled
IDE.

Reviewed: 2026-09-15. Benchmark 1.0.0; see the generated results for the scanner build.

## Safety design

All JavaScript indicators are strings or harmless configuration. The lifecycle and hook examples
only print markers. The IDE command names a nonexistent marker. The Docker image uses a nonexistent
image on a reserved `.invalid` registry. Credential references are fake path strings; no file read
or credential collection exists. Network/evaluation examples are quoted text, with no callable
downloader or execution chain. Fixtures are created without executable permissions.

The public source is designed to be copied into a standalone demo repository after review. This
branch does not claim that separate repository has already been published.

## Reproduce

From the Repyy source checkout, build Repyy itself and run its trusted benchmark runner:

```sh
go build -o /tmp/repyy ./cmd/repyy
python3 scripts/benchmark.py --binary /tmp/repyy --output /tmp/repyy-demo --check
```

The runner invokes only that binary. It writes `results.json`, `results.md`, `sample.json`,
`sample.txt` and `sample.html`. Open the HTML report locally, or inspect the checked-in
[sample report](../site/demo/sample/sample.html) without installing anything. Generated timestamps
identify the run; scan durations and temporary root names are normalized for publication. Samples
use local fixture identities, not a fabricated remote commit.

## Expected outcomes and controls

| Case                  | Expected rule | Paired control                           |
| --------------------- | ------------- | ---------------------------------------- |
| Lifecycle             | PKG-001       | Ordinary test script                     |
| Startup configuration | IMPORT-001    | Normal PostCSS configuration             |
| Disguised image       | EXEC-001      | SVG with only image markup               |
| Folder-open task      | IDE-001       | Manual task without automatic run option |
| Git hook              | GITHOOK-001   | Inactive sample hook                     |
| Obfuscated download   | CHAIN-001     | Normal display string                    |
| Credential reference  | CRED-001      | Specific benign environment variable     |
| Docker socket         | DOCKER-001    | Ordinary read-only data volume           |

Benchmark 1.0.0 detects six of eight expected signals. The inert startup marker and JSON folder-open
task remain known misses. Their expected rules and reasons remain in `cases.json`; the runner fails
on changes from that declared baseline so improvements also require deliberate baseline review. No
new detection family was added to improve the score.

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

Intentional exception to the usual contribution rule against generated reports: the reviewed public
samples under `site/demo/sample/` are product artifacts. Never commit reports from private
repositories.
