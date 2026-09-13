# Detection coverage

This map documents repyy's built-in static checks. It is an acceptance map, not
a claim that every malicious program can be detected. Exact indicators age;
heuristics can produce both false positives and false negatives.

| Detection area | Representative coverage | Rule IDs or scanner checks |
| --- | --- | --- |
| Dynamic execution | `eval`, Function constructors, VM execution, string timers, browser execution APIs, OS process spawning | `EXEC-*`, `COMBO-002` |
| Obfuscation | Base64/hex/Unicode decoding, dense escapes, string reversal, computed globals, character shufflers, long/high-entropy lines | `OBFS-*`, `UNICODE-001` |
| Package lifecycle | npm lifecycle hooks; Python, Ruby, Composer, Rust, Go, and JVM build hooks | `PKG-001`, `PY-001`, `RUBY-001`, `PHP-001`, `RUST-001`, `GO-001`, `JVM-001` |
| Malicious dependencies | Attributed package/version IOCs across eight ecosystems, typosquat review signals, unusual versions, URL/VCS dependencies | `IOC-PKG-*`, `TYPOSQUAT-001`, `PKG-002`, `PKG-003`, `PKG-005` |
| Package-manager integrity | Registry credentials, custom registries, nonstandard lockfile URLs, pnpm lockfiles, unsafe package `bin` targets | `NPMRC-*`, `LOCK-001`, `PKG-004`, `PKG-006` |
| Download and execution | Pipe-to-shell, decode-to-execute, downloaded executable launch, remote imports | `CHAIN-*`, `IMPORT-002`, `DOCKER-002` |
| Backdoors | Request-controlled command execution, runtime-computed imports, Node require bypasses, hardcoded authentication bypasses | `BACKDOOR-*`, `IMPORT-001`, `IMPORT-003` |
| Credential and wallet access | SSH/cloud/container credentials, browser databases, wallets, clipboard, cookies, keylogging, forms, sensitive file reads | `CRED-*`, `EXFIL-002`, `ENV-001` |
| Secrets | Private keys, AWS/GitHub/Stripe/Slack-style tokens, generic API credentials with redacted evidence | `SECRET-*` |
| Suspicious network | Discord/Telegram/Pastebin/ngrok endpoints, public raw-IP URLs, WebSockets, DNS transfer primitives | `NET-*`, `IPURL-001`, `EXFIL-001` |
| Collection and exfiltration | Host fingerprinting or environment collection correlated with outbound transfer | `FINGERPRINT-001`, `COMBO-001` |
| Reverse and bind shells | Shell, netcat/ncat, socat, FIFO, Python, Perl, Ruby, PowerShell, and socket/dup patterns | `REVSHELL-*` |
| Cryptomining | XMRig, CoinHive, CryptoNight, stratum TCP/TLS, pool names, and corroborated mining ports | `MINER-001` |
| Sandbox/CI evasion | VM/container/CI probes, with an elevated correlated execution finding | `EVADE-001`, `COMBO-003` |
| CI/CD integrity | Untrusted GitHub event interpolation, privileged checkout, mutable action references, secret egress, and common non-GitHub CI variable injection | `CICD-*` |
| Editor/agent execution | VS Code tasks/settings/extensions, devcontainers, JetBrains commands, Vim/Neovim project config, AI-agent hooks and prompt injection | `IDE-*`, `AGENT-*` |
| Containers | Download-to-execute, remote `ADD`, privileged/host namespaces, Docker socket, capabilities, sensitive host mounts | `DOCKER-*` |
| Git metadata | Active hook contents, hooks-path changes, executable filters/helpers, unsafe protocol configuration | `GITHOOK-*`, `GITMETA-001` |
| File/repository integrity | Known malicious SHA-256, compiled binaries, executable bits, escaping symlinks, archive traversal/resource bounds, missing README/license | `IOC-HASH-SHA256`, `BINARY-001`, `EXECBIT-001`, `SYMLINK-*`, `ARCHIVE-001`, `REPO-*` |
| Social engineering | Urgency plus interview pressure, instructions to disable security or elevate privileges | `SOCIAL-*`, `APT-001` |

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
- Package names are matched only in parsed manifests. A sourced affected
  version can become a confirmed IOC; an uncertain name/range remains a review
  signal.
- `NO FINDINGS` never means safe, and incomplete coverage is reported.

## What this is not

repyy is a source and repository review tool, not a replacement for
`npm audit`, `pip-audit`, `cargo audit`, or another lockfile vulnerability
database. It does not resolve packages, contact registries during a scan, or
install dependencies. It can inspect supported manifests for declared package
indicators and lockfiles for suspicious sources and integrity clues; confirm a
dependency finding against the ecosystem's current advisory and the exact
resolved version.

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
