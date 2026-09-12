---
name: repyy
description: Scan one or more unfamiliar local or remote code repositories for malware, supply-chain attacks, credential theft, obfuscation, backdoors, and unsafe install hooks before running code or installing dependencies. Use for take-home interview assignments, cloned GitHub repositories, suspected malicious packages, or requests to preflight untrusted source privately.
---

# repyy

Use the `repyy` CLI as a read-only first-pass scanner. Do not execute target code, open it in an IDE with workspace trust enabled, or install its dependencies before reviewing the scan.

## Install this skill

From the published repository, a user can install this skill interactively with
`npx skills add Kevin-Umali/repyy --skill repyy`, or install it globally for
Codex without prompts with
`npx skills add Kevin-Umali/repyy --skill repyy -g -a codex -y`.
This installs agent instructions only. The `repyy` executable is installed
separately, and neither command installs dependencies from a scanned target.

## Run a scan

1. Confirm the user is authorized to inspect every target, especially private repositories.
2. Prefer an already-installed `repyy`. Check with `repyy version`.
   Use `repyy intel status` to disclose snapshot age and `repyy rules list`
   when the user needs package/hash provenance. Both commands are offline.
3. If it is absent and this is a trusted checkout of repyy, use `go run ./cmd/repyy version` or build with `make build`. Otherwise, ask the user to install a signed release. Never install a package from the repository being scanned.
4. Scan all requested targets in one command when possible:

   ```sh
   repyy scan --format json --output repyy.scan.json TARGET...
   ```

5. Treat `SCAN INCOMPLETE` as unresolved. Report skipped paths and warnings.
6. Summarize critical/high findings first, including rule ID, path, line, context, confidence, and remediation. Explain plausible benign contexts.
7. State that `NO FINDINGS` is not proof of safety. Recommend isolation and manual review before execution.

## Safety and privacy

- Do not run, import, evaluate, build, or test target code.
- Do not install target dependencies.
- Do not upload source or findings to another service.
- Do not run `repyy intel update` unless the user explicitly asks to update the
  local intelligence snapshot. That command downloads a signed public snapshot
  from GitHub Releases and uploads nothing.
- If an update causes a regression, use `repyy intel rollback` to activate the
  previous verified cached snapshot.
- Do not enable online reputation checks unless the user explicitly requests a
  future feature that clearly identifies its data disclosure.
- Keep remote scans shallow unless history is needed, and do not retain temporary clones unless requested.
- Do not paste credential-shaped evidence into chat; repyy redacts it, but verify before quoting.
- Treat documentation, tests, and signature corpora as context, not automatic proof of malware.
- Treat a name-only malicious-package match as a review signal; reserve
  confirmed wording for an affected version or exact published file hash.

## Interpret verdicts

- `DO NOT RUN`: at least one high-confidence critical executable behavior.
- `REVIEW REQUIRED`: findings need human review; this is not a malware conviction.
- `SCAN INCOMPLETE`: coverage limits or errors prevent a clean conclusion.
- `NO FINDINGS`: no enabled rule matched in completed coverage; false negatives remain possible.
