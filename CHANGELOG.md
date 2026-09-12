# Changelog

All notable changes are documented here. The project follows Semantic
Versioning after the first published release.

## [0.4.0] - 2026-09-12

### Added

- Added self-contained offline HTML scan reports with a semantic, accessible
  light review layout, focused review queue, filtering, file views, coverage
  details, redacted matched lines, exact remote source links, and print styling.
- Added `repyy report` for rendering existing JSON scans and `repyy rules
  explain` for offline rule guidance.
- Added complete, bounded occurrence locations and review dispositions while
  retaining the version 1 report schema and legacy finding fields.
- Added terminal detail, grouping, display-filter, progress, and color controls.

### Changed

- Prioritize actionable terminal findings, print remediation, summarize hidden
  contextual results, and update interactive progress in place.
- Apply centralized file-role and rule-scope policy across executable,
  manifest, CI, generated, dependency, test, documentation, evidence, and
  archive content.
- Distinguish process API imports from actual invocation, use structured GitHub
  Actions inspection, and require nearby execution for entropy findings.
- Preserve verdict, `--fail-on`, exit-code, offline, and privacy behavior.

### Fixed

- Avoid identifier-substring matches such as `runConvexFunction`, quoted-token
  matches such as `"process.env"`, and weak generated-file noise while retaining
  strong indicators.

## [0.3.2] - 2026-09-12

### Added

- Show immediate and periodic file, byte, and elapsed-time progress during
  terminal scans, while keeping JSON and SARIF output clean.

### Changed

- Skip common generated and cache directories by default, including Convex,
  Expo, Next.js, Turbo, CocoaPods, and Xcode build output.
- Avoid repeatedly rescanning whole files during long-line entropy checks,
  substantially improving scans of large repositories.
- Publish Homebrew installs as a Cask and document the explicit `--cask`
  command.
- Skip GoReleaser snapshot validation for documentation-only changes.

## [0.3.1] - 2026-09-12

- Publish a Homebrew Formula for the CLI instead of an unsigned Cask, avoiding
  macOS quarantine failures without bypassing Gatekeeper.

## [0.3.0] - 2026-09-12

### Added

- Added explicit signed intelligence lifecycle commands: `intel status`,
  `intel update`, and `intel rollback`.
- Added signature verification, strict snapshot validation, downgrade
  protection, a content-addressed last-known-good cache, and embedded fallback.
- Added Homebrew and Scoop publishing plus native `.deb`, `.rpm`, and `.apk`
  release packages, so installing a release does not require Go.
- Added release-time snapshot signing and binary smoke checks.
- Added ruleset and intelligence-snapshot identity to scan reports.

### Privacy

- Normal scans and status checks remain offline. Intelligence updates download
  two public release assets and never upload source, paths, findings, hashes, or
  telemetry.

## [0.2.2] - 2026-09-12

- Recognize inline scanner signature tables as detection definitions instead of
  executable malware.
- Apply context and confidence handling to long-line and entropy findings.

## [0.2.1] - 2026-09-12

- First public release of the local, read-only multi-repository scanner.
- Added terminal, JSON, and SARIF reports, configurable rules, expiring
  suppressions, bounded archive inspection, and safe temporary remote clones.
- Added offline package and SHA-256 intelligence with source, description,
  affected-version, and snapshot details.
- Added coverage for install hooks, supply-chain behavior, obfuscation,
  backdoors, reverse shells, credential theft, exfiltration, miners, CI/editor
  configuration, containers, Git metadata, and social engineering.
- Closed sub-pattern gaps in Git hooks, CI/CD, editor configuration, JavaScript
  obfuscation, reverse shells, containers, sensitive reads, and package bins.
- Reduced false positives for private IPs, generated files, and SHA-pinned actions.
- Added idiomatic Go documentation for exported production declarations.
- Added the optional repyy AI skill and documented installation with the
  `skills` CLI.

[0.4.0]: https://github.com/Kevin-Umali/repyy/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/Kevin-Umali/repyy/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Kevin-Umali/repyy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Kevin-Umali/repyy/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Kevin-Umali/repyy/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Kevin-Umali/repyy/releases/tag/v0.2.1
