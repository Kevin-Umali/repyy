# Changelog

All notable changes are documented here. The project follows Semantic Versioning after the first published release.

## [Unreleased]

## [0.6.0] - 2026-09-26

### Added

- Add sourced package indicators for `process-log`, `cdn-icon-fetch`, and
  `vite-tsconsole-log`, preserving exact affected Axios versions.
- Add bounded, data-only JavaScript literal recovery and conservative
  same-function Axios response-to-execution correlation with source and sink
  locations. Unsupported decoding remains visible as incomplete coverage.
- Publish a versioned behavioral rule catalog and a rules reference for the
  existing documentation site.

### Changed

- Consolidate scanner tests by behavior, replace self-referential rule and catalog checks with observable scan expectations, and keep edge-case and benign-control coverage in the relevant suites.
- Clarify the security boundary and release evidence in the guides and website, with clearer starting paths for first-time reviewers, CLI users, and security reviewers.
- Reduce weak findings in generated vendor bundles while retaining secrets,
  confirmed indicators, and correlated behavior.

### Fixed

- Correct documentation navigation links and labels, and serve the site favicon.
- Keep safe exact lockfile versions outside a narrowly affected advisory from
  being described as confirmed compromise; label eligible unlocked ranges as
  potential exposure.

## [0.5.3] - 2026-09-19

### Fixed

- Build the Astro documentation site before the release workflow validates its
  generated routes and artifacts, and refresh the npm lockfile for clean installs.
- Require successful main-branch CI for the exact release commit before the prepare
  workflow creates a tag or dispatches publication.
- Publish the scanner and documentation changes prepared as v0.5.2 under v0.5.3;
  the protected v0.5.2 tag failed its pre-publication gate and produced no release
  or downloadable assets.

## [0.5.2] - 2026-09-19

### Added

- Detect VS Code workspace commands, JSONC extension recommendations, automatic
  devcontainer or command-line extension installation, packaged VSIX files,
  devcontainer features, editor trust overrides, and multiline agent/MCP hooks.
- Detect additional devcontainer lifecycle commands, direnv and Nix shell hooks,
  host package/global-tool installers, scripted font installation, opaque or
  malformed binary fonts (including bounded WOFF/WOFF2 decompression), executable
  TrueType instruction tables, active SVG glyph content, repository-managed
  pre-commit hooks, and expanded
  operating-system startup persistence surfaces.
- Detect encoded PowerShell, Windows proxy-execution utilities, staged downloads,
  CMake/Meson/Bazel/Make command hooks, service and daemon persistence, PDF active
  actions, Office macros/external relationships/DDE fields, and executable VSIX
  activation capabilities or installation scripts.

### Changed

- Scope release workflow write permissions to the publishing jobs and pin sandbox base images by digest, following the first OpenSSF Scorecard assessment.
- Link directly to private vulnerability reporting from the security policy.
- Publish v0.5.1 verification evidence and standalone demo links; refresh public samples with the verified release binary and pin fixture evidence links to the release tag.
- Make benchmark subprocess exit-code handling explicit and organize its imports.
- Migrate the complete landing page and documentation site from hand-authored HTML to a static Astro and TypeScript build while preserving public routes, content, metadata, accessibility, interactions, and the existing visual design.
- Generate cross-guide search data during the Astro build, preserve sample-report bytes and CSP hashes as public assets, and update validation, CI, Make targets, and repository links for the generated static site.
- Bump the embedded rules revision to `2026.09.19` for the expanded installation
  and automatic-execution coverage.

### Fixed

- Scan extensionless executable and shebang scripts for staged downloads; preserve
  quoted paths containing spaces, ignore quoted/commented downloader examples,
  correlate nested execution wrappers, recognize default curl/wget filenames, and
  retain executable modes for scripts nested in ZIP or tar archives.
- Reject malformed, overlapping, duplicate, over-expanding, or invalidly compressed
  SFNT, TTC, WOFF, and WOFF2 font tables; accept bounded WOFF2 collection
  directories; apply structural table checks after WOFF/WOFF2 decompression; and
  validate conservative decoded-size lower bounds while keeping font and every
  embedded-SVG document's decompression bounded.
- Parse PDF names, comments, strings, and stream delimiters without treating passive
  content as actions; correlate document-open and additional actions independently
  of indirect-object order; reconstruct split/encoded Office DDE fields without
  joining unrelated fields; and identify renamed macro projects from package metadata.
- Parse escaped VSIX capability keys and executable `main`/`browser` entry points
  while limiting activation and lifecycle checks to the extension's canonical
  manifest, so bundled dependency manifests do not produce extension-level findings.
- Preserve test, example, and evidence context from outer archive paths when
  classifying findings inside Office, VSIX, font, and other nested packages.
- Run the required platform build checks for documentation-only pull requests so branch protection can resolve every required check.

## [0.5.1] - 2026-09-15

### Added

- Build identity with scanner commit, builder, source, Go version, build date, and rules revision.
- Trust, verification, security-testing, and project-story guides, plus an independent-review brief.
- Eight bounded fuzz targets, including valid and malformed archives, nested archives, traversal paths, and resource-limit cases.
- An inert paired benchmark with generated terminal, JSON, and offline HTML reports and direct fixture, rule, and regression links.
- Release provenance, platform-specific container SBOM attestations, draft-download verification, and Scorecard configuration.
- CodeQL security analysis for GitHub Actions workflows alongside the existing Go analysis.
- Repository formatting commands matching the maintainer's VS Code Prettier settings and generated-report CSP integrity checks.

### Changed

- Reorganize the landing page around reviewing unfamiliar assignments while preserving the original coverage-limit design.
- Use conservative human decision labels while retaining schema-1 machine verdicts and exit-code behavior.
- Record host/Docker scan mode per repository; show unavailable local commits and unknown legacy metadata explicitly in HTML reports.
- Publish Homebrew and Scoop manifests only after release verification succeeds; validate both manifest versions before either update.
- Version the benchmark as 1.1.0: replace the misleading quoted startup expectation with a harmless local dynamic import, preserving the original marker.
- Bump the rules revision to `2026.09.15` for the folder-open detection correction.

### Fixed

- Keep documentation navigation aligned with the section being read during scrolling, anchor navigation, and viewport changes.
- Keep the active documentation link visible within the desktop sidebar without moving the document.
- Recognize the quoted JSON `runOn` property in automatic folder-open tasks without flagging the paired manual-task control.
- Surface temporary checkout, authentication-file, and forced-container cleanup failures; preserve findings when checkout cleanup makes a scan incomplete.
- Prevent horizontal overflow from the offline report's mobile controls.

Release provenance, SBOM attestations, and Scorecard configuration require successful GitHub workflow runs before being presented as verified public evidence.

## [0.5.0] - 2026-09-13

### Added

- Added opt-in Docker isolation with separate networked HTTPS fetch and
  network-disabled scan stages, digest-pinned release images, and host-rendered
  reports. VM workflows remain documented manual options.
- Added detailed web and Markdown guides for installation, CLI usage,
  configuration, detection coverage, intelligence, Docker, Windows Sandbox,
  macOS/Linux VM workflows, and the optional AI agent skill.
- Added a manually dispatched release workflow that validates the version in
  `Makefile` and the changelog before creating a tag and publishing assets.
- Added inert adversarial fixtures and static SVG active-content checks for
  scripts, event handlers, and JavaScript links; no fixture payload is run.
- Added supply-chain review for npm aliases, overrides, and additional dependency scopes,
  pip/uv indexes, Bundler mirrors, Go workspace replacements, Cargo build
  scripts and source overrides, Composer repositories/plugins, JVM wrapper
  distributions, NuGet feeds, and MSBuild commands.
- Added GitHub workflow review for upstream artifacts in privileged jobs,
  low-trust cache writes, and pull requests on self-hosted runners.

### Changed

- Aligned generated offline HTML reports with the site design, keyboard view
  controls, per-repository counts, source links, and a readable no-JavaScript
  fallback.
- Write report files through a private temporary file and atomic rename with
  restrictive permissions.
- Made Docker isolation fail closed when Docker or the matching signed image is
  unavailable. Docker accepts local paths and HTTPS remotes, and rejects SSH
  remotes and `--keep-workdir`.
- Reorganized the documentation site around a concise hub, focused guides,
  visible back navigation, and bundled cross-guide search that works offline.
- Run relevant CI jobs after changed-file detection, cancel superseded pull
  request runs, cache sandbox image layers, lint workflows, and smoke-test CLI
  builds on Linux, macOS, and Windows.
- Parse centrally managed NuGet versions in `Directory.Packages.props` and
  inspect project-local `.bundle/config` instead of skipping that directory.
- Organize supply-chain, CI workflow, and SVG detectors in focused scan
  subpackages with their tests, and separate archive and repository inspection
  from the core scan loop. Cargo build-script inventory stays local to each scan.
- Serve the static site through directory-index routes such as `/docs/` and
  `/coverage/`, and use those clean URLs in navigation and search.

### Fixed

- Preserve successful targets when another target is incomplete, return exit
  code `2` for incomplete coverage, and keep each target's original name,
  order, remote URL, and revision.
- Preserve partial Docker findings when coverage is incomplete and reject saved
  reports whose verdict conflicts with their findings or coverage.
- Filter findings across all recorded file locations and show a redacted
  backend failure reason in incomplete reports.
- Ignore inherited Git environment overrides and restrict clone transports to
  the requested HTTPS or SSH protocol; document Git's untrusted `.git`
  boundary.
- Resolve symlinked repository roots; bound and confine Git metadata reads;
  reject spoofed trusted-registry hosts and archive-link traversal; report
  undecodable source as incomplete; and redact source-derived report fields.
- Match rule paths without case sensitivity and treat common mixed-case and
  alternate-format agent instruction files as active instructions.
- Inspect decoded multiline workflow commands for untrusted event interpolation
  and secret egress, and report unreadable supply-chain configuration as
  incomplete coverage.

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

[0.5.3]: https://github.com/Kevin-Umali/repyy/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/Kevin-Umali/repyy/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Kevin-Umali/repyy/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Kevin-Umali/repyy/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Kevin-Umali/repyy/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/Kevin-Umali/repyy/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Kevin-Umali/repyy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Kevin-Umali/repyy/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Kevin-Umali/repyy/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Kevin-Umali/repyy/releases/tag/v0.2.1
