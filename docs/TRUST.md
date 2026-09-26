# Trust and Limitations

Reviewed: 2026-09-15. Describes the trust-roadmap changes; unreleased features are identified
explicitly.

Repyy reviews unfamiliar take-home assignments before installing dependencies, starting the project,
or opening it in an IDE. Inspect before you execute.

Repyy identifies risks. It cannot prove that a repository is safe.

## Security model

Repository files, filenames, configuration, archives, Git metadata and source-derived report values
are untrusted input. The scanner reads them as data. It does not intentionally import, install,
build, test or run assignment code. It does not compute a complete runtime call graph. Findings
describe observable patterns, not proof that a behavior occurred.

The trusted computing base includes the Repyy executable, its dependencies, operating system,
explicitly supplied rules, and tools used for retrieval or isolation. Host Git, SSH and Docker are
capabilities with their own attack surfaces. A malicious repository may attack parsers, consume
resources, disguise content, exploit race conditions, or attempt output injection. Review tests and
known limitations below before relying on this boundary.

## What Repyy reads

Repyy inspects regular files within the selected repository, selected Git metadata and bounded
archive entries. It reads manifests without invoking package managers. Dependency/cache directories
are excluded by default; `--include-dependencies` expands that scope. Explicit trusted configuration
can add rules and suppressions. Do not use a rules file supplied by the assignment as trusted
configuration.

The local target root is resolved before inspection and file reads use a confined filesystem root.
Symlinks and archive paths receive additional checks. Archive contents are inspected in memory
rather than extracted into a working installation. These controls reduce exposure; they do not prove
every parser or operating-system boundary is flawless.

## What Repyy does not execute

Normal scan paths do not invoke target scripts, hooks, build systems, test runners, Docker Compose,
package managers or IDEs. Host remote scans invoke Git clone and revision lookup; Docker mode
invokes the Docker client, container Git and the Repyy worker. Windows report-file permission setup
may invoke `icacls`. These are trusted host tools, not assignment commands.

Source:
[repository preparation](https://github.com/Kevin-Umali/repyy/blob/main/internal/source/source.go),
[scanner](https://github.com/Kevin-Umali/repyy/blob/main/internal/scan/scanner.go),
[Docker boundary](https://github.com/Kevin-Umali/repyy/blob/main/internal/sandbox/docker.go).

## Network behavior

This table describes implementation behavior, not a firewall guarantee for the host process. No scan
feature uploads assignment contents or scan reports to a Repyy service.

| Feature                                       | Default / trigger                                   | Destination and data sent                                                                                                                   | Authentication                                                                  | Failure and boundary                                                                                            |
| --------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Local scan and rules/report commands          | Local scan default; no intentional network request  | None; embedded or verified cached intelligence is read locally                                                                              | None                                                                            | File/parser failures are reported; host mode has no network sandbox                                             |
| Host remote scan                              | Only when a remote target is supplied               | Requested HTTPS or SSH Git host; repository path, Git negotiation and connection metadata                                                   | Provider token for GitHub/GitLab/Bitbucket HTTPS; host SSH capabilities for SSH | Clone failure is visible; host Git handles retrieval; no redirects, submodules or local-file Git protocol       |
| Docker remote fetch                           | Opt-in Docker mode with HTTPS remote                | Requested Git host; path, Git negotiation, connection metadata                                                                              | Matching provider token in a temporary mode-0600 env file                       | Bridge network during fetch; not restricted to a destination allowlist; fetch error is visible; SSH unsupported |
| Docker scan stage                             | Every Docker scan                                   | None through container network; `--network none`                                                                                            | No provider token passed to scan worker                                         | Worker errors, oversized/malformed reports and inconsistent exit codes are rejected                             |
| Intelligence update                           | Explicit `repyy intel update` only                  | Official GitHub release snapshot and signature URLs, including HTTP-client redirects to release storage; user-agent and connection metadata | No provider token added by updater                                              | Download/validation failure leaves existing intelligence usable; host-side operation; 30-second HTTP timeout    |
| Sandbox image retrieval                       | Explicit user `docker pull`; never implicit in scan | Container registry and its backing storage; image digest and connection metadata                                                            | Docker's configured registry credentials                                        | Missing image fails preflight; Docker daemon retrieves image                                                    |
| Offline HTML report                           | Rendering is local; user may click a source link    | No remote assets loaded; a click opens the supported source provider at a pinned revision                                                   | Browser session when following a link                                           | Network is outside report rendering; link may fail or require login                                             |
| Installation / optional agent-skill installer | Explicit user installation command                  | GitHub, package registries or package-manager sources; requested package metadata                                                           | Installer's configured credentials                                              | Outside normal scan; source and reports are not installer inputs                                                |
| Maintainer intelligence generation            | Explicit `make intel`                               | GitHub advisory API; advisory identifiers                                                                                                   | Maintainer's authenticated `gh`                                                 | Failure stops generation; never a normal scan path                                                              |
| CI / release / security evidence workflows    | Repository events or scheduled workflows            | GitHub, registries, Go modules, signing and Scorecard services; public project source/build/security metadata                               | Scoped Actions tokens; existing release secrets where required                  | Workflow failure remains visible; these workflows do not process users' private assignments                     |

The website links to third-party evidence. Opening those links contacts their operators. CLI privacy
claims do not describe those external sites.

## Local data handling

Local scans keep source in place. Reports go to stdout or the requested output path and can contain
sensitive filenames, repository identity and redacted evidence. Redaction is pattern-based, not a
guarantee that arbitrary secrets are removed. Treat reports as sensitive and review before sharing.
No telemetry client or report-upload path is implemented in the normal scanner.

Intelligence snapshots and active/previous pointers are stored in the local cache. Invalid or older cached
intelligence falls back to embedded data with a warning. Updates require a valid signature and
schema; rollback uses previously verified local snapshots. See the
[intelligence guide](https://repyy.dev/intelligence/).

## Temporary repositories and cleanup

Host remotes use a private `repyy-clone-*` temporary directory. Git hooks/templates, recursive
submodules, redirects, system/global Git configuration and unrequested Git protocols are disabled.
Default history depth is one. `--keep-workdir` deliberately retains host checkouts. Otherwise
cleanup is deferred; clone/revision failures also attempt removal.

Git acquisition has a context timeout but no byte, pack, checkout-file-count,
or disk-space cap before scanner traversal. Scanner file and archive limits
cannot bound temporary checkout storage. A clone failure is reported as an
incomplete target; this remains a resource boundary to address separately.

Docker remotes use a private `repyy-sandbox-*` parent with a writable fetch child, followed by a
read-only scan mount. Provider tokens use a separate mode-0600 temporary env file. Timed-out
containers receive a bounded forced-removal attempt.

Checkout deletion failures are reported: successful host/Docker scans retain their findings but
become incomplete with a cleanup warning; preparation failures include a cleanup error when deletion
also fails. Token-file deletion and forced-container removal failures also return errors. Remaining
boundary: abrupt termination or a Docker daemon failure can leave files or containers behind before
those errors can be reported. Cleanup is best effort, not secure erasure. Review temporary storage
after an interrupted private scan.

## Host-mode boundaries

Host mode is the default. Remote scans use installed Git and, for SSH, host SSH
configuration/agents. Git configuration is filtered, but the process still inherits other host
environment and OS capabilities. Updating Git and SSH and choosing an appropriate isolation
environment remain the user's responsibility. A local static scan does not turn the host into a
malware sandbox.

## Docker-mode boundaries

The image must be digest-pinned and explicitly available locally. The worker uses read-only
input/root filesystem, dropped capabilities, no-new-privileges, process/memory/CPU limits and
bounded temporary storage. Remote fetch and scan are separate stages. Docker daemon access itself is
a powerful host capability. Containers share a kernel and are not equivalent to a dedicated virtual
machine. See [isolation](SANDBOX.md).

## Incomplete scans and exit codes

| Human status                              | Meaning                                                                         | Schema-1 verdict compatibility                                                      |
| ----------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Findings detected                         | Findings warrant review before execution                                        | `DO NOT RUN` remains the legacy machine value                                       |
| Review required                           | Review observed findings and their context                                      | `REVIEW REQUIRED`                                                                   |
| No relevant findings detected             | No enabled rule matched in completed coverage                                   | `NO FINDINGS`                                                                       |
| Scan incomplete                           | Error, limit or reduced coverage prevents a completed result                    | `SCAN INCOMPLETE`                                                                   |
| Unsupported or unresolved content present | Read the skipped-content and warning details; not an additional machine verdict | Represented in coverage details; some deliberate exclusions remain outside coverage |

Exit 0 means completed without a finding at the selected failure threshold. It can include
lower-severity findings. Exit 1 means the threshold was reached. Exit 2 means an operational failure
or incomplete scan and takes priority over findings. Exit 3 means invalid invocation/input. Display
filters do not change the exit policy. See [CLI reference](CLI.md).

Unsupported formats, deliberate exclusions and static resolution limits differ from operational
incompleteness. Review coverage warnings and exclusions even when the scan completes. Never
interpret an empty result or exit 0 as proof of safety.

## Static-analysis limitations

Static analysis can miss malicious behavior and flag legitimate code. Dynamic imports, generated
code, encrypted content and runtime state may be unresolved. A filename, signature or suspicious
string alone does not establish malicious intent. Inspect the evidence and ask the sender for
context. The demo benchmark versions its expectations and keeps misses and expectation corrections visible.

## Claim-to-evidence map

| Claim                                        | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Status / limits                                                            |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Normal scans read assignment code as data    | [internal/scan/scanner.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/scan/scanner.go), [internal/source/source.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/source/source.go), [test/integration/cli_test.go](https://github.com/Kevin-Umali/repyy/blob/main/test/integration/cli_test.go)                                                                                                                                  | Implementation and behavioral tests; no universal non-execution proof      |
| Local report rendering needs no network      | [internal/output/html.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/output/html.go), `TestHTMLIsSelfContainedAndEscapesFindings`                                                                                                                                                                                                                                                                                                           | Self-contained HTML; deliberate clicks open external providers             |
| Docker scan network is disabled              | [internal/sandbox/docker.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/sandbox/docker.go), [internal/sandbox/docker_test.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/sandbox/docker_test.go)                                                                                                                                                                                                                               | Fetch stage has bridge access; daemon boundary remains                     |
| Incomplete scans stay visible                | [internal/app/app_test.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/app/app_test.go), `TestRunContainerPreservesIncompleteFindings`                                                                                                                                                                                                                                                                                                       | Review deliberate exclusions separately                                    |
| Repository values are escaped                | `TestHumanReportsNeutralizeControlCharacters`, `TestSourceDerivedSecretsAreRedactedAcrossFormats`, `FuzzHumanOutput`                                                                                                                                                                                                                                                                                                                                     | Pattern redaction is not a complete secret classifier                      |
| Releases identify source                     | [internal/buildinfo](https://github.com/Kevin-Umali/repyy/tree/main/internal/buildinfo), [.github/workflows/release.yml](https://github.com/Kevin-Umali/repyy/blob/main/.github/workflows/release.yml)                                                                                                                                                                                                                                                   | New attestations require a successful tagged run and download verification |
| Dependencies are disclosed                   | `.goreleaser.yaml`, release SBOM assets                                                                                                                                                                                                                                                                                                                                                                                                                  | Component inventory does not establish harmlessness                        |
| Detection behavior is measurable             | `demo/cases.json`, `scripts/benchmark.py`                                                                                                                                                                                                                                                                                                                                                                                                                | Eight inert paired cases; not representative global accuracy               |
| Hostile inputs receive behavioral/fuzz tests | [internal/scan/repository_test.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/scan/repository_test.go), [archive_test.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/scan/archive_test.go), [context_test.go](https://github.com/Kevin-Umali/repyy/blob/main/internal/scan/context_test.go), [.github/workflows/security-evidence.yml](https://github.com/Kevin-Umali/repyy/blob/main/.github/workflows/security-evidence.yml) | Bounded test runs; no exhaustive assurance                                 |
| External review                              | `docs/EXTERNAL-REVIEW.md`                                                                                                                                                                                                                                                                                                                                                                                                                                | Prepared scope only; no independent review completed by this work          |

Evidence files and named tests are browsable in the
[public source tree](https://github.com/Kevin-Umali/repyy). Check the release tag or exact commit
when assessing an older binary.

## Releases, security testing and reviews

Read [release verification](VERIFICATION.md), [security testing](SECURITY-TESTING.md), and the
[external-review brief](EXTERNAL-REVIEW.md). See the verification guide for current CodeQL,
Scorecard and attestation evidence status. No independent-audit badge is claimed.

Report vulnerabilities privately using
[GitHub vulnerability reporting](https://github.com/Kevin-Umali/repyy/security/advisories/new).
Include version, OS, impact and the smallest inert reproduction. Do not send working credentials or
private assignment source. See [security policy](../SECURITY.md).
