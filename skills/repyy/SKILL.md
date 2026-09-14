---
name: repyy
description:
  Scan one or more unfamiliar local or remote code repositories for malware, supply-chain attacks,
  credential theft, obfuscation, backdoors, and unsafe install hooks before running code or
  installing dependencies. Use for take-home interview assignments, cloned GitHub repositories,
  suspected malicious packages, or requests to preflight untrusted source privately.
---

# repyy

Use the `repyy` CLI as a read-only first-pass scanner. Do not execute target code, open it in an IDE
with workspace trust enabled, or install its dependencies before reviewing the scan.

## Install this skill

From the published repository, a user can install this skill interactively with
`npx skills add Kevin-Umali/repyy --skill repyy`, or install it globally for Codex without prompts
with `npx skills add Kevin-Umali/repyy --skill repyy -g -a codex -y`. This installs agent
instructions only. The `repyy` executable is installed separately, and neither command installs
dependencies from a scanned target. The optional `npx` installer needs Node/npm, Git, and network
access; local folder scans with an installed `repyy` binary do not.

## Run a scan

1. Confirm the user is authorized to inspect every target, especially private repositories.
2. Prefer an already-installed `repyy`. Check with `repyy version`. Use `repyy intel status` to
   disclose snapshot age and `repyy rules list` when the user needs package/hash provenance. Both
   commands are offline.
3. If it is absent and this is a trusted checkout of repyy, use `go run ./cmd/repyy version` or
   build with `make build`. Otherwise, ask the user to install a signed release. Never install a
   package from the repository being scanned.
4. Scan all requested targets in one command when possible:

   ```sh
   repyy scan --format json --output repyy.scan.json TARGET...
   ```

   For a reviewable offline artifact, render the JSON without rescanning:

   ```sh
   repyy report repyy.scan.json --format html --output repyy.report.html
   ```

   Open the HTML report locally and begin with its review queue. Use the disposition filter to
   reveal informational context only when it is useful; do not upload the report to a hosted viewer.

   For a stronger process boundary, Docker is opt-in and must be prepared before the scan:

   ```sh
   repyy scan TARGET --sandbox=docker --format html --output repyy.report.html
   ```

   Docker mode requires Docker and the exact digest-pinned image published for the installed repyy
   release. Get the image reference from `repyy-sandbox-image.txt` in the matching GitHub release,
   verify the release checksum and Cosign signature, and pull that digest first. Missing Docker or a
   missing version-matched image is a preflight error; never fall back to a host scan. Docker
   accepts local paths and HTTPS remotes, and rejects SSH URLs and `--keep-workdir`. See the
   repository's [Docker guide](https://github.com/Kevin-Umali/repyy/blob/main/docs/SANDBOX.md) and
   [manual VM guide](https://github.com/Kevin-Umali/repyy/blob/main/docs/VM-GUIDES.md) when a VM
   boundary is required.

5. Treat `SCAN INCOMPLETE` as unresolved. Report skipped paths and warnings.
6. Summarize blocking and review findings first, including every reported location, context,
   confidence, and remediation. Use `repyy rules explain RULE-ID` when additional offline rationale
   is needed.
7. State that `NO FINDINGS` is not proof of safety. Recommend isolation and manual review before
   execution.

## Safety and privacy

- Do not run, import, evaluate, build, or test target code.
- Do not install target dependencies.
- Do not upload source or findings to another service.
- Do not run `repyy intel update` unless the user explicitly asks to update the local intelligence
  snapshot. That command downloads a signed public snapshot from GitHub Releases and uploads
  nothing.
- If an update causes a regression, use `repyy intel rollback` to activate the previous verified
  cached snapshot.
- Keep remote scans shallow unless history is needed, and do not retain temporary clones unless
  requested.
- Do not paste credential-shaped evidence into chat; repyy redacts it, but verify before quoting.
- Treat generated HTML reports as sensitive local artifacts. They make no network requests, but
  still contain repository paths and redacted evidence.
- Treat documentation, tests, and signature corpora as context, not automatic proof of malware.
- Treat a name-only malicious-package match as a review signal; reserve confirmed wording for an
  affected version or exact published file hash.

## Interpret verdicts

- `DO NOT RUN`: at least one high-confidence critical executable behavior.
- `REVIEW REQUIRED`: findings need human review; this is not a malware conviction.
- `SCAN INCOMPLETE`: coverage limits or errors prevent a clean conclusion.
- `NO FINDINGS`: no enabled rule matched in completed coverage; false negatives remain possible.
