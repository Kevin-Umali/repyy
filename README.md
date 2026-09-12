# repyy

[![CI](https://github.com/Kevin-Umali/repyy/actions/workflows/ci.yml/badge.svg)](https://github.com/Kevin-Umali/repyy/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Kevin-Umali/repyy/actions/workflows/codeql.yml/badge.svg)](https://github.com/Kevin-Umali/repyy/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scan unfamiliar repositories before you install dependencies or run their code.

`repyy` is a local, read-only malware and supply-chain scanner for cloned GitHub
repositories, coding assignments, and other source code you do not fully trust.
It scans one or many local folders or Git remotes and reports suspicious files,
install hooks, dependencies, secrets, obfuscation, backdoors, and data theft
patterns.

```console
$ repyy scan https://github.com/example/assignment ./another-repo
DO NOT RUN  https://github.com/example/assignment
  critical 1 | high 2 | medium 1 | low 0 | files 84

NO FINDINGS  ./another-repo
  critical 0 | high 0 | medium 0 | low 0 | files 31
```

> `NO FINDINGS` is not a guarantee that code is safe. Static scanning can miss
> malware and can also report harmless code. Review the evidence before running
> an unfamiliar project.

## Install

You do not need Go to install a release.

```sh
# macOS or Linux with Homebrew
brew install --cask Kevin-Umali/tap/repyy

# Windows with Scoop
scoop bucket add repyy https://github.com/Kevin-Umali/scoop-bucket
scoop install repyy/repyy
```

Linux releases also include `.deb`, `.rpm`, and `.apk` packages. macOS, Linux,
and Windows archives are available from
[GitHub Releases](https://github.com/Kevin-Umali/repyy/releases). If you already
use Go, this remains available:

```sh
go install github.com/Kevin-Umali/repyy/cmd/repyy@latest
```

Installing `repyy` installs only the scanner. A scan never installs packages,
builds the target, runs tests, or executes code from the target repository. Git
is needed only when scanning a remote URL.

## Use it

```sh
# Scan one or many local repositories
repyy scan ./assignment-a ./assignment-b

# Scan remote repositories in temporary shallow clones
repyy scan https://github.com/org/repo git@gitlab.com:org/private.git

# Read targets from a file and scan four at a time
repyy scan --file repositories.txt --jobs 4

# Save machine-readable reports
repyy scan ./assignment --format json --output report.scan.json
repyy scan ./assignment --format sarif --output report.sarif
```

Private HTTPS clones can use `GITHUB_TOKEN`, `GITLAB_TOKEN`, or
`BITBUCKET_TOKEN`. The token is passed to Git through process-local
configuration and is not written into the clone URL. SSH remotes use your
existing SSH agent. Scans do not prompt for credentials.

## What it checks

| Area | Examples |
| --- | --- |
| Malicious packages and files | Sourced package/version advisories across npm, PyPI, RubyGems, Maven, Go, Rust, Composer, and NuGet; known SHA-256 indicators; typosquat signals. |
| Install and supply-chain behavior | npm lifecycle scripts, build hooks, custom registries, unusual lockfile URLs, URL/VCS dependencies, unsafe package binaries, and download-to-execute chains. |
| Obfuscated code | Base64, hex and Unicode escapes, `eval` and Function constructors, string shufflers, long lines, high entropy, and invisible characters. |
| Backdoors and exfiltration | Request-to-command execution, dynamic imports, reverse shells, auth bypasses, clipboard/cookie/form theft, keylogging, host profiling, and outbound transfer. |
| Secrets and sensitive files | Private keys, AWS/GitHub/Stripe-style tokens, `.env`, SSH/cloud credentials, wallets, and browser databases. Evidence is redacted. |
| Network and mining | Discord/Telegram/Pastebin/ngrok endpoints, public raw-IP URLs, WebSockets, DNS transfer patterns, XMRig, CryptoNight, mining pools, and Stratum. |
| Repository configuration | Git hooks, CI workflows, editor/devcontainer auto-run, Docker host access, symlinks, archives, binaries, executable files, and AI-agent instructions. |
| Social engineering | Requests to disable security, elevate privileges, or urgently run an interview project. These remain review signals, not proof of malware. |

The detailed, tested list is in [docs/COVERAGE.md](docs/COVERAGE.md).

Non-English comments are not treated as malicious. GitHub account age,
followers, and activity are also excluded because normal scans are private and
offline. They would require sending identifiers to an online API.

## Understand the result

| Result | Meaning |
| --- | --- |
| `NO FINDINGS` | The completed scan matched no enabled rule. This does not prove safety. |
| `REVIEW REQUIRED` | One or more findings need a person to review their context. |
| `DO NOT RUN` | A high-confidence critical behavior was found in executable or install-time code. |
| `SCAN INCOMPLETE` | A timeout, limit, permission, clone, archive, or read error reduced coverage. |

Exit code `0` means no finding reached `--fail-on` (default: `high`), `1` means
the threshold was reached, `2` means a target could not be fully scanned, and
`3` means the command or configuration was invalid.

Terminal, JSON, and SARIF reports identify the scanner, ruleset, and verified
intelligence snapshot used, so a result can be reproduced and audited later.

Documentation, tests, fixtures, and security-rule files are identified as
context and downgraded where appropriate. Private IPs, generated lockfiles,
source maps, and commit-SHA-pinned GitHub Actions also have targeted exclusions
to reduce false positives. Always review a finding instead of treating it as an
automatic accusation.

## Offline and private by default

- No telemetry, analytics, accounts, source upload, or cloud analysis.
- Local targets require no network access.
- Remote targets use the network only to clone the repository you requested.
- Clones are shallow and temporary unless you use `--history` or
  `--keep-workdir`.
- Target code is read as data; it is not imported, built, tested, or executed.
- File, archive, timeout, and symlink limits are enforced and incomplete scans
  are reported honestly.

The scanner contains a dated offline intelligence snapshot. Scans never update
it automatically. Inspect its status or contents without contacting an
external service:

```sh
repyy intel status
repyy intel status --format json
repyy rules check
repyy rules list
repyy rules list --format json
```

Updating is an explicit action. It downloads only the public snapshot and its
signature from the latest GitHub release; it does not upload source, paths,
findings, file hashes, or usage data. A snapshot is activated only after its
Ed25519 signature, schema, dates, and records pass validation.

```sh
repyy intel update
repyy intel rollback  # restore the previous verified cached snapshot
```

Updates are stored atomically in the user cache. If the cache is missing,
damaged, or fails verification, repyy warns and safely uses the snapshot
embedded in the executable. The public verification key is published at
[`keys/intelligence-ed25519.pem`](keys/intelligence-ed25519.pem). It can only
verify snapshots; it cannot create valid signatures. The private signing key is
never stored in this repository.

Package-name-only or uncertain-version matches require review. A sourced
affected version or exact published file hash provides stronger evidence, but
the surrounding code should still be inspected.

## Configure it

Repository-owned `.repyy.yaml` files are ignored so an untrusted repository
cannot weaken its own scan. Pass a configuration file you trust:

```sh
repyy rules validate examples/repyy.example.yaml
repyy scan ./assignment --config examples/repyy.example.yaml
```

Custom rules are declarative regex and path matches; they cannot run commands.
Suppressions use stable fingerprints, require a reason, and may have an expiry.
See [examples/repyy.example.yaml](examples/repyy.example.yaml).

## Use repyy as an AI skill

The optional [repyy skill](skills/repyy/SKILL.md) teaches compatible AI coding
agents to run the scanner safely and explain its results. Install it from this
repository with the [`skills` CLI](https://github.com/vercel-labs/skills):

```sh
# Choose the supported agents interactively
npx skills add Kevin-Umali/repyy --skill repyy

# Install globally for Codex without prompts
npx skills add Kevin-Umali/repyy --skill repyy -g -a codex -y
```

This installs the instruction skill, not packages from repositories you scan.
You still need the `repyy` executable installed separately.

## Contribute

```sh
git clone https://github.com/Kevin-Umali/repyy.git
cd repyy
make check
make security
make build
```

Go unit tests live beside the package they test, which is standard Go project
layout. Built-binary integration tests live in `test/integration/`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for adding detections, tests, or fixes. The
automatic pull-request checklist comes from
[.github/pull_request_template.md](.github/pull_request_template.md).

## License

MIT. Third-party intelligence sources are listed in [NOTICE](NOTICE).
