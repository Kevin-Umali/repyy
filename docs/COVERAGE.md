# Detection coverage

This map documents repyy's built-in static checks. It is an acceptance map, not
a claim that every malicious program can be detected. Exact indicators age;
heuristics can produce both false positives and false negatives.

| Detection area                | Representative coverage                                                                                                                                                                                                                                                                            | Rule IDs or scanner checks                                                                                                                                                            |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dynamic execution             | `eval`, Function constructors, VM execution, string timers, browser execution APIs, OS process spawning                                                                                                                                                                                            | `EXEC-*`, `COMBO-002`                                                                                                                                                                 |
| Axios response to execution   | Same-function Axios response data flowing through simple aliases into `eval`, Function, or qualified `child_process` execution; source and sink lines retained                                                                                                                                    | `FLOW-001`                                                                                                                                                                           |
| Decoded literal indicators    | Bounded JavaScript escape, Base64/hex literal, character-code, byte-array, and constant string-table lookup recovery rescanned for selected strong indicators                                                                                                                                  | `DECODE-001`                                                                                                                                                                         |
| Obfuscation                   | Base64/hex/Unicode decoding, dense escapes, string reversal, computed globals, character shufflers, long/high-entropy lines                                                                                                                                                                        | `OBFS-*`, `UNICODE-001`                                                                                                                                                               |
| Package lifecycle             | npm and Composer hooks; Python, Cargo, Go, JVM, and MSBuild build-time execution                                                                                                                                                                                                                   | `PKG-001`, `PY-001`, `PHP-001`, `RUST-001`, `RUST-002`, `GO-001`, `JVM-001`, `DOTNET-001`                                                                                             |
| Malicious dependencies        | Attributed package/version IOCs across eight ecosystems, typosquat review signals, unusual versions, URL/VCS dependencies                                                                                                                                                                          | `IOC-PKG-*`, `TYPOSQUAT-001`, `PKG-002`, `PKG-003`, `PKG-005`                                                                                                                         |
| Package-manager integrity     | Registry credentials, alternate sources, overrides and aliases, nonstandard lockfile URLs, package-manager executables/plugins, wrapper URLs and checksums, unsafe package `bin` targets                                                                                                           | `NPMRC-*`, `LOCK-001`, `PKG-004`, `PKG-006`, `PKG-008`, `PKG-009`, `PY-003`, `RUBY-002`, `RUST-003`, `RUST-004`, `RUST-005`, `PHP-002`, `PHP-003`, `NUGET-001`, `YARN-*`, `JVMWRAP-*` |
| Download and execution        | Pipe-to-shell, decode-to-execute, downloaded executable launch, remote imports                                                                                                                                                                                                                     | `CHAIN-*`, `IMPORT-002`, `DOCKER-002`                                                                                                                                                 |
| Backdoors                     | Request-controlled command execution, runtime-computed imports, Node require bypasses, hardcoded authentication bypasses                                                                                                                                                                           | `BACKDOOR-*`, `IMPORT-001`, `IMPORT-003`                                                                                                                                              |
| Credential and wallet access  | SSH/cloud/container credentials, browser databases, wallets, clipboard, cookies, keylogging, forms, sensitive file reads                                                                                                                                                                           | `CRED-*`, `EXFIL-002`, `ENV-001`                                                                                                                                                      |
| Secrets                       | Private keys, AWS/GitHub/Stripe/Slack-style tokens, generic API credentials with redacted evidence                                                                                                                                                                                                 | `SECRET-*`                                                                                                                                                                            |
| Suspicious network            | Discord/Telegram/Pastebin/ngrok endpoints, public raw-IP URLs, WebSockets, DNS transfer primitives                                                                                                                                                                                                 | `NET-*`, `IPURL-001`, `EXFIL-001`                                                                                                                                                     |
| Collection and exfiltration   | Host fingerprinting or environment collection correlated with outbound transfer                                                                                                                                                                                                                    | `FINGERPRINT-001`, `COMBO-001`                                                                                                                                                        |
| Reverse and bind shells       | Shell, netcat/ncat, socat, FIFO, Python, Perl, Ruby, PowerShell, and socket/dup patterns                                                                                                                                                                                                           | `REVSHELL-*`                                                                                                                                                                          |
| Cryptomining                  | XMRig, CoinHive, CryptoNight, stratum TCP/TLS, pool names, and corroborated mining ports                                                                                                                                                                                                           | `MINER-001`                                                                                                                                                                           |
| Sandbox/CI evasion            | VM/container/CI probes, with an elevated correlated execution finding                                                                                                                                                                                                                              | `EVADE-001`, `COMBO-003`                                                                                                                                                              |
| CI/CD integrity               | Untrusted GitHub event interpolation, privileged checkout, mutable action references, secret egress, low-trust cache writes, artifact use in privileged `workflow_run` jobs, pull requests on self-hosted runners, and common non-GitHub CI variable injection                                     | `CICD-*`                                                                                                                                                                              |
| Editor/agent execution        | VS Code folder-open and manual task/debug commands, JSONC extension recommendations, devcontainer/CLI extension installation, packaged VSIX files, devcontainer features/lifecycle commands, editor trust overrides, and multiline AI-agent or MCP hooks                                           | `IDE-*`, `AGENT-*`                                                                                                                                                                    |
| Host installation and startup | Host package/global-tool installers, scripted font registration, binary-font provenance/integrity, direnv and Nix shell hooks, pre-commit hook installers, shell profiles, scheduled tasks, launch agents/daemons, systemd services/timers, Windows services/WMI, login items, and startup folders | `INSTALL-001`, `FONT-*`, `AUTORUN-*`, `GITHOOK-*`, `GITMETA-*`, `SHELL-001`, `PERSIST-*`                                                                                              |
| Encoded and staged execution  | Encoded PowerShell commands, Windows proxy-execution/download utilities, and bounded cross-line download-then-execute chains                                                                                                                                                                       | `EXEC-005`, `EXEC-006`, `CHAIN-004`                                                                                                                                                   |
| Active documents              | PDF action and embedded-file markers; Office Open XML macro projects, external relationships, and DDE fields                                                                                                                                                                                       | `DOC-*`                                                                                                                                                                               |
| Build hooks                   | CMake external commands, Meson run/custom targets, Bazel shell commands, and Make shell evaluation                                                                                                                                                                                                 | `BUILD-*`                                                                                                                                                                             |
| Extension packages            | VSIX inventory plus activation/contribution capabilities, lifecycle scripts, archive contents, and bundled executable signatures                                                                                                                                                                   | `IDE-007`–`IDE-009`, `BINARY-001`                                                                                                                                                     |
| Image active content          | Executable SVG script elements, event handlers, and JavaScript links                                                                                                                                                                                                                               | `IMAGE-001`                                                                                                                                                                           |
| Containers                    | Download-to-execute, remote `ADD`, privileged/host namespaces, Docker socket, capabilities, sensitive host mounts                                                                                                                                                                                  | `DOCKER-*`                                                                                                                                                                            |
| Git metadata                  | Active hook contents, hooks-path changes, executable filters/helpers, unsafe protocol configuration                                                                                                                                                                                                | `GITHOOK-*`, `GITMETA-001`                                                                                                                                                            |
| File/repository integrity     | Known malicious SHA-256, compiled binaries, executable bits, escaping symlinks, archive traversal/resource bounds, missing README/license                                                                                                                                                          | `IOC-HASH-SHA256`, `BINARY-001`, `EXECBIT-001`, `SYMLINK-*`, `ARCHIVE-001`, `REPO-*`                                                                                                  |
| Social engineering            | Urgency plus interview pressure, instructions to disable security or elevate privileges                                                                                                                                                                                                            | `SOCIAL-*`, `APT-001`                                                                                                                                                                 |

## Supply-chain files by ecosystem

These are static review signals in repository files. An alternate source or
build hook may be legitimate; the scanner does not install, resolve, or execute
it.

| Ecosystem            | Files and review signals                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node/npm, Yarn, pnpm | `package.json` lifecycle scripts, URL/Git/file dependencies in all four dependency scopes, registry aliases checked by their actual package name, nested `overrides`/`resolutions`, and package binaries; `.npmrc`/`.yarnrc.yml` registry settings and Yarn executable/plugins; npm/Yarn/pnpm lockfile URLs. [npm package spec](https://docs.npmjs.com/cli/v11/using-npm/package-spec/), [Yarn `yarnPath`](https://yarnpkg.com/configuration/yarnrc).                                                                  |
| Python               | `requirements*.txt`, `pip.conf`, `pip.ini`, `Pipfile`, `pyproject.toml`, and `uv.toml` alternate indexes or unsafe uv index strategy; `setup.py`/`setup.cfg` install hooks and direct URL/VCS sources. [pip requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/), [uv indexes](https://docs.astral.sh/uv/concepts/indexes/).                                                                                                                                                        |
| Ruby                 | `Gemfile` and `.bundle/config` alternate gem sources or mirrors and inline Git/path gems. `Gemfile.lock` receives generic text checks but no independent source-resolution audit. [Bundler Gemfile](https://bundler.io/guides/gemfile.html).                                                                                                                                                                                                                                                                           |
| Go                   | `go.mod` and `go.work` replacements, including block form; `//go:generate` in Go source. `go.sum` is scanned as text but its hashes are not independently audited. [Go module replacements](https://go.dev/doc/modules/gomod-ref).                                                                                                                                                                                                                                                                                     |
| Rust                 | `Cargo.toml` declared build script, non-default Git/path/registry dependencies, and dependency overrides; sibling `build.rs` auto-execution; `.cargo/config.toml` source/registry replacement. `Cargo.lock` is scanned as text but not resolved. [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html), [source replacement](https://doc.rust-lang.org/cargo/reference/source-replacement.html).                                                                                         |
| Java/JVM             | `pom.xml` and Gradle build/repository rules; Gradle/Maven wrapper distribution URLs and SHA-256 settings. [Gradle Wrapper](https://docs.gradle.org/current/userguide/wrapper_plugin.html), [Maven Wrapper](https://maven.apache.org/tools/wrapper/index.html).                                                                                                                                                                                                                                                         |
| PHP                  | `composer.json` install/update scripts, alternate repositories, and unrestricted plugin permission. `composer.lock` receives generic text checks but no independent source-resolution audit. [Composer repositories](https://getcomposer.org/doc/04-schema.md#repositories), [plugin permissions](https://getcomposer.org/doc/06-config.md#allow-plugins).                                                                                                                                                             |
| .NET                 | `NuGet.Config` package sources and wildcard source mappings, `packages.config` and project references, centrally managed `Directory.Packages.props` versions, and MSBuild `Exec` in projects or imported `.props`/`.targets`. [NuGet configuration](https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file), [central versions](https://learn.microsoft.com/en-us/nuget/consume-packages/central-package-management), [MSBuild `Exec`](https://learn.microsoft.com/en-us/visualstudio/msbuild/exec-task). |

## Precision controls

- Every finding retains its matched locations, while bounded report-detail
  limits prevent hostile input from exhausting memory.
- Rules declare whether they inspect raw content, executable code, or a
  structured format. Code-scoped matching distinguishes definite comments and
  literals from executable tokens across common language families.
- File roles distinguish executable code, CI and install hooks, manifests,
  documentation, examples, tests, evidence, generated output, dependencies,
  detection definitions, metadata, and archive entries. Confirmed IOCs are
  never silenced by contextual downgrades.
- Correlated findings require distinct actionable signals from executable code;
  imports, generated examples, and low-confidence matches cannot form a
  high-confidence behavior chain.
- Documentation, tests, fixtures, and signature corpora are contextualized and
  downgraded instead of treated as executable malware.
- Long-line and entropy checks skip lockfiles, source maps, and known generated
  output. Entropy must occur near an execution primitive rather than merely in
  the same file.
- Raw-IP checks exclude loopback, private, unspecified, link-local, and
  multicast addresses.
- GitHub Actions pinned to a full 40-character commit SHA are not reported as
  mutable.
- `workflow_run` artifact findings require a download of an upstream run's
  artifact followed by a command in the same job. Cache-write findings require
  `pull_request_target`, `issue_comment`, or `workflow_run` and an effective
  `write` or `write-only` cache mode. These
  are review signals, not proof that an artifact or cache is attacker-controlled.
  See GitHub's
  [secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use)
  and [cache access guidance](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
- CI interpolation and secret-egress checks inspect decoded multiline `run`
  blocks as individual steps, so expressions split across YAML lines are not
  silently missed or correlated across unrelated steps.
- A `pull_request` job using a self-hosted runner is a review signal because
  repository visibility and fork-approval settings are unavailable offline. See
  GitHub's [self-hosted runner warning](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/add-runners).
- Rule path globs compare case-insensitively, so mixed-case file extensions do
  not bypass a detector. Agent instruction files are reviewed as instructions,
  while ordinary documentation and test fixtures retain their lower-risk context.
- VS Code workspace recommendations are reported as prompted installation choices,
  not as automatic installs. Devcontainer extension lists and `code
--install-extension` commands are reported separately because they provision an
  extension when the surrounding setup action runs.
- Binary fonts are never rendered. The scanner inventories TTF, OTF, TTC, WOFF,
  and WOFF2 files; validates bounded container headers, table graphs, selected
  required-table invariants, and compressed-size claims where supported; looks for
  embedded ELF or structurally valid PE signatures; inventories TrueType `fpgm` and
  `prep` programs; and inspects plain or gzip-compressed OpenType SVG glyph documents
  for scripts, event handlers, and active links. Embedded SVG expansion is capped at
  8 MiB in addition to the normal per-file scan limit. It does not execute, emulate, or
  prove arbitrary glyph or shaping bytecode safe, so provenance and hash verification
  remain required.
- PDF and Office inspection is static. It detects explicit action names, embedded
  macro projects, external relationships, and DDE fields without opening the
  document. It does not decrypt documents, emulate a viewer, expand arbitrary PDF
  object streams, or determine that every external relationship is malicious.
- VSIX packages are inspected as bounded archives. Declared activation and execution
  surfaces, install lifecycle scripts, and bundled executable signatures are reported;
  extension JavaScript is still subject to the same static-analysis limits as other code.
- Package names are matched in parsed manifests and npm lockfiles. An exact
  affected resolved lockfile version is a confirmed IOC. An unlocked declared
  range that could include an affected version remains a possible exposure;
  a safe exact lockfile version is not called compromised.
- Alternate feeds, mirrors, local build scripts, and build wrappers are review
  signals because many projects use them intentionally. An official wrapper
  URL with a well-formed SHA-256 is left alone; a missing checksum is a
  hardening finding, not proof of tampering.
- `NO FINDINGS` never means safe, and incomplete coverage is reported.

## What this is not

repyy is a source and repository review tool, not a replacement for
`npm audit`, `pip-audit`, `cargo audit`, or another lockfile vulnerability
database. It does not resolve packages, contact registries during a scan, or
install dependencies. It can inspect supported manifests for declared package
indicators and lockfiles for suspicious sources and integrity clues; confirm a
dependency finding against the ecosystem's current advisory and the exact
resolved version. The npm lockfile parser reads recorded versions but does not
resolve packages or reconcile every declaration/lock disagreement.

The scanner does not follow pip `-r`/`-c` references, evaluate Ruby or build
configuration, compare dependency declarations to lockfile resolutions, or
verify downloaded wrapper archives against their declared hashes. Those checks
need a resolver or trusted artifact fetch; this scanner reads repository bytes
only. Sibling `build.rs` detection applies to unpacked repository files.

Raster-image metadata and image pixels are not parsed for embedded instructions
or scripts. Valid text SVG files are inspected for active content.

Unreadable or non-regular files, undecodable source and configuration, linked
Git metadata, resource limits, unsafe archive entries, and timeouts reduce
coverage. Intentionally excluded dependency/cache trees are listed as skipped
but do not make the default scan incomplete.

Run `repyy rules explain RULE-ID` for offline rationale, legitimate-use context,
matching scope, and review guidance. Finding dispositions organize reports but
do not change verdict or exit-code policy.

## Deliberate exclusions

Non-English comments are not evidence of malware and are not scored. GitHub
account age, follower count, and activity require online collection and remain
outside the private offline scanner. Run `repyy intel status` to see the active
offline snapshot's age, or `repyy rules list` to inspect its sources and entries.
`repyy intel update` is an explicit download of a signed public snapshot; scans
never contact the update service or upload repository data.
