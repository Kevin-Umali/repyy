# Repyy Phase 1 research report and implementation handoff

**Status:** Phase 1 research complete. No Repyy code, tests, docs, or website files were modified. Stop here for approval before implementation.

## Executive summary

At Repyy commit **e9dff17d680ec51f57c019be097ecc778ba6f4e1**, the scanner is a local, bounded, non-executing static analyzer with explicit coverage reporting, rule context, package/file intelligence, and useful repository-acquisition hardening. Its main gaps against the pinned malicious-repositories corpus are not a lack of generic execution-token rules. The evidence points to four concrete problems:

1. Three confirmed malicious npm packages present in the corpus are absent from Repyy’s embedded intelligence: process-log, cdn-icon-fetch, and vite-tsconsole-log.
2. The repeated axios-response-to-eval pattern is found at the execution sink, but Repyy does not recognize axios as a remote-fetch source or trace the response into the sink. It therefore misses the chain correlation.
3. Static decoding and context classification understate obfuscated source payloads: two large malicious JS payloads have only informational findings after being classified as detection-definition content.
4. One vendor-heavy sample produces thousands of weak findings, while two samples remain incomplete because four files were skipped as undecodable.

The right next step is a narrow static enhancement: add sourced package records, bounded non-executing JS constant decoding and source-to-sink correlation, then refine context/noise behavior using paired malicious and benign fixtures. Keep the current local-first model. Do not add public reputation scoring, broad domain blocklists, or a remote scan service.

The research handoff file is truncated at the end of Part XIV, mid-example after “credential steal”. Its unseen requirements remain unknown; this report covers only the scope visible in that file.

## 1. Scope, pins, and method

### Pinned states

| Item | Exact state |
| --- | --- |
| Repyy at start | bf3b423841c78f91c0353c8c455d202c4aa29f76 |
| Repyy after requested fast-forward | e9dff17d680ec51f57c019be097ecc778ba6f4e1, 2026-09-25 |
| Corpus | dc82f332dae0f4e9ea6bdc1d8341c7743c59913f, 2026-08-10 |
| Working tree | Branch main; clean after research |

The corpus commit was fetched into a bare Git object store and extracted without checkout. A static extractor verified blob hashes and rejected unsafe paths, collisions, symlinks, and non-regular file modes. It extracted 3,849 files totaling 301,396,740 bytes. The corpus has 14 project directories plus a two-PDF scammer-documents directory. A root README, image, and .gitignore were reviewed as context but were not separate Repyy scan targets.

No code, package manager, lifecycle script, build, test, container, IDE task, Git hook, or binary from the corpus was run. No dependencies were installed. No decoded code was executed. No attacker endpoint, payload URL, or C2 address was contacted. Repyy scanned only the extracted files as data. The scan report is at /private/tmp/repyy-corpus-results.json; the extraction is at /var/folders/47/b7bzt_nx2dx102fkpw2x51_00000gn/T/repyy-corpus-static-pq0yb4jf.

The Repyy scanner was built from the pinned checkout to /private/tmp. No Repyy tests were run; the objective allows them but does not require them, and this phase does not need test execution.

### Evidence labels used below

- **Implementation verified:** source code at the pinned Repyy commit.
- **Observed:** direct CLI/report output or public page content observed during this audit.
- **Documented claim:** a website or README assertion not independently verified against implementation.
- **Inference:** an interpretation from the observed source or output.
- **Proposed:** recommended new behavior.
- **Unknown:** evidence is insufficient; do not turn it into a malware or safety conclusion.

## 2. Repyy baseline

### Scanner and reporting

**Implementation verified.** Repyy’s scanner reads repository files through a confined root, avoids following symlinks, bounds each file at 50 MiB, and defaults to at most 100,000 files. Archive scanning defaults to 10,000 entries, 1 GiB expanded bytes, and depth 3. Skips, timeouts, unreadable content, and limits make coverage incomplete. Common dependency directories such as node_modules, vendor, target, and .venv are excluded unless dependency scanning is requested.

The scanner has static checks for execution, environment access, credentials, network and exfiltration primitives, obfuscation, package sources and lifecycle scripts, CI/build configuration, active documents, and other repository risks. It also scans several structured formats and archives. The rule catalog is exported through BuiltinRuleCatalog and includes descriptions, severity, confidence, disposition, matching scope, applicable paths, legitimate-use guidance, and context-downgrade metadata.

**Implementation verified.** Raw rules are regex and structured-file checks; the JavaScript path does not build a general JS AST, resolve module reachability, evaluate arbitrary JavaScript, or trace Axios response values. NET-001 matches literal-URL fetch calls, curl/wget, https.get, and requests.get/post, but not axios.get/post. EXEC-001 covers eval and Function-call forms, but not every constructor/member alias such as Function.constructor. Cross-signal correlation is confined to findings from the same file and only considers findings that remain executable, non-informational, and not low confidence.

**Observed.** In this scan, Repyy reported version 0.5.3-dev, rules 2026.09.19, and intelligence 2026-09-12.1 from the local cache. Intelligence status reported 43 packages, 34 file hashes, verified=true, stale=false. The scanner build reports its commit as unknown; the source commit used for the build is pinned above. The CLI output did not show a need to contact the network. The report JSON records the intel source as cache.

### Context and generated code

**Implementation verified.** Context classification treats paths such as dist/build and suffixes such as .min.js/.bundle.js as generated. It does not recognize the DEX sample’s public/charting_library/bundles paths. It also marks a source line as detection-definition when it contains a short set of regex-like substrings such as literal backslash-s, backslash-open-paren, Pattern:, or certain rule-construction strings. Contextual findings are downgraded, commonly to at most medium/low and informational. That rule is too broad for a minified or obfuscated executable line that happens to contain one of those substrings.

### Acquisition

**Implementation verified.** Host remote scans use a private temporary checkout, shallow depth 1 by default, no recursive submodules, an empty Git template, disabled hooks, disabled Git HTTP redirects, filtered GIT_* and SSH_ASKPASS environment variables, and allow only the requested HTTPS or SSH protocol. URL credentials, query strings, and fragments are rejected. Provider tokens are injected through host-specific Git configuration. Repyy records the cloned HEAD SHA after checkout.

Host mode still uses the user’s Git and SSH configuration/agent boundary for SSH and inherits most of the host environment. Git fetch is subject to the scan context timeout, but there is no explicit checkout byte, disk, pack, or file-count budget before the scanner begins. Git output is collected with CombinedOutput without a size cap. The scanner’s file limits therefore do not cap the preceding clone.

**Implementation verified.** Docker mode drops capabilities, sets CPU/memory/process limits, uses read-only mounts for scan input, and disables container networking during scan. Remote fetch runs with bridge networking and has no destination allowlist or disk quota. It is an explicit local CLI fetch, not a guarantee of a fully network-isolated acquisition stage.

### Intelligence behavior

**Implementation verified.** Package matching is ecosystem/name keyed. Exact affected versions and all-version ranges are supported, but the current simple matcher does not resolve package-manager semver ranges or reconcile a manifest declaration against its resolved lockfile entry. If a package name is present in intelligence but the declared version does not match the known affected range, Repyy emits a high/high manifest-review finding that says the package name appears in an advisory; it does not say that a resolved vulnerable version was found. The current Axios entry is exact-version scoped to 1.14.1 and 0.30.4.

This distinction matters in the corpus: several projects declare Axios with caret ranges that could include a compromised release, but the scan’s name-only finding is not proof that a lockfile resolves to one. erc20-token-dapp and sarostech-assessment have lockfile Axios versions 1.7.9 and 1.6.8 respectively, outside the advisory’s exact compromised versions.

**Observed.** repyy rules list --format json emits intelligence package/hash data, not the behavioral rule catalog. Rule explanations are individually available. The website’s coverage page tells users to copy repyy rules list as a source/rules command, so command naming and page copy can mislead someone looking for the behavioral catalog.

## 3. ScanRepo public investigation

No independently inspectable ScanRepo scanner implementation was found in the public surfaces reviewed. The homepage footer links to the malicious-repositories corpus and an npm package. Treat scanner internals below as documented claims, not implementation facts.

### Published claims and observable evidence

| Surface | What it says or shows | Evidence class and implication |
| --- | --- | --- |
| Homepage | Static scanner for public GitHub/Bitbucket repos, “31+” rules, six categories, 0–100 score, cached/shared results. It says it downloads a tarball and does not clone or execute. | Documented claims; not source-verified. Public/shared is a data-publication choice. |
| About | “60+” rules, entropy/string/control-flow heuristics, import graph, repository/account reputation signals, and an LLM second opinion on high-risk scans. It caps content-scanned files at 3,000 and says minified/vendor bundles are mostly skipped. | Documented claims; not independently verified. The 31+ vs 60+ mismatch is public documentation drift. |
| CLI | npx scanrepo URL, JSON, a GitHub token option, --no-publish, and exit codes 0 safe/low, 1 suspicious/inconclusive/error, 2 dangerous. | Documented behavior; CLI engine was not installed or run. --no-publish only promises not to put the result in the public feed; it does not establish zero server transmission, zero retention, or offline operation. |
| MCP | Documents scan_repo, repo_verdict, recent_scans over stdio. | Documented claim only; MCP package was not installed or exercised. |
| Public report example | ElyPrismLauncher/Launcher displays SAFE 0/100 at 24 of 1,856 files, 1% coverage, commit 5ea65f7, engine v5, scan date 2026-08-22. | Directly observable page content. It says low score is not a guarantee, but the SAFE score and 1% coverage can still be misread. |
| Samples | Seven pattern examples, “13 repositories,” and Lazarus/DPRK framing. Examples include remote eval, byte-array URL decoding, dynamic Function, malicious packages, and obfuscated config. | Page assertions are not ground truth for payload behavior or actor attribution. Some local files support the basic fetch/eval patterns; remote second stages were not retrieved. |
| Analysis | Gives Golden City C2 IP/ports, clipboard/file theft, reverse shell, and lists 13 injection points. | Publisher claims. Our scan did not contact or fetch remote payloads; local payloads do not prove every described second-stage behavior. |
| Scams | Lists accounts, identities, repository names, domains, and actor/campaign attribution; it labels some LinkedIn identities as stolen. | Public OSINT assertions with reputational consequences. Do not consume as proof without independent primary evidence. |
| Intel | Calls itself a live OSINT feed; during this audit it showed zero advisories/reports/news/repos. | Observed at audit time; dynamic content may change. |
| Latest/trending/agent/stats | Public scan feeds, trending-repository surface, autonomous-finder claim, and stats. Some routes only showed loading placeholders in the page reader. | The product surface is observable; populated content and internals were not independently verified. |
| Response guide | Recommends commands including deleting package locks before reinstall, pip uninstalling every package, killing unknown processes, and reformatting the OS. | Published advice, not validated guidance. Do not copy this style into Repyy documentation. |

The homepage says “31+” while About/MCP say “60+”; the CLI distinguishes local display from public feed sharing but does not provide enough evidence to establish what the CLI transmits to ScanRepo’s service. Telemetry, report retention, and internal scanner behavior therefore remain unknown. The source corpus page is not the scanner engine source.

### Concepts worth adapting

- Report exact file coverage and incomplete status prominently. The public 1%-coverage SAFE example demonstrates why a verdict must never hide scan coverage.
- Provide a human-oriented explanation of an observed behavior and point to the exact Repyy rule, source location, and limitation.
- A small, bounded import/entrypoint graph may help explain why a package script, Vite config, or server entrypoint activates a suspicious path. Start with static script-to-file/import reachability; do not build a whole-program analyzer in this iteration.
- Keep rule evidence, context, source commit, rule version, and intelligence version visible and reproducible.

### Concepts not to copy

- No 0–100 confidence score or account/repository reputation discount. Popularity and publisher identity cannot make dangerous code evidence safe.
- No public-by-default repo names, report sharing, or user-supplied credential transmission. Repyy’s local/private default is a product advantage.
- No broad domain/IP blocklists for common hosting services such as npoint.io. Treat URL source plus data flow to an execution sink as stronger evidence than a domain string.
- No unreviewed actor attribution, identity lists, or universal incident response instructions.
- No cloud LLM verdict or hidden telemetry in normal scans.

## 4. Git clone versus archive/API acquisition

### Existing Git path

Repyy’s current path is better hardened than a plain clone: hooks/templates, recursive submodules, redirects, ambient Git config, and unrequested protocols are disabled; the scan revision is recorded. Do not claim this makes Git itself a sandbox. Git and SSH remain host tools, the fetch stage needs network access, and checkout storage is unbounded before scanner limits apply.

### Archive tradeoffs

GitHub documents that source archives are generated from git-archive at branch/tag/commit snapshots. Archives can omit files marked export-ignore and rewrite contents marked export-subst. Git LFS content is pointer-only by default unless the repository owner enables inclusion. These are real coverage differences, not hypothetical: replacing clone with archive can silently remove evidence.

GitHub says a commit-SHA archive has stable file contents and recommends a commit ID for reproducibility. It also documents source archive redirect/URL behavior. A tarball route reduces the local Git checkout surface but adds a security-sensitive decompression and extraction boundary. Any future extractor must enforce compressed/decompressed byte, file-count, individual-file, total-byte, nesting, and time limits; validate effective PAX/GNU paths and duplicate/case/Unicode collisions; reject unsafe links and special files; confine writes; preserve executable and link evidence; and mark skipped content incomplete.

### Recommendation

**Proposed:** keep the current Git path as default for now. First add an explicit acquisition budget design; current scanner limits begin too late. Then evaluate a pinned GitHub tree/blob adapter or commit-pinned archive as an optional source adapter with inventory parity tests. A GitHub tree API can return modes, types, paths, and blob SHAs, but recursive trees can be truncated at 100,000 entries/7 MB, and blob retrieval has per-blob limits; every truncated tree and skipped blob must be visible as incomplete. Preserve generic Git fallback for Bitbucket/SSH and avoid checkout/archive substitution until parity is demonstrated.

Primary references: [Git clone manual](https://git-scm.com/docs/git-clone), [Git archive attributes](https://git-scm.com/docs/git-archive), [GitHub source code archives](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives), [GitHub LFS archives](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-git-lfs-objects-in-archives-of-your-repository), [Git Trees API](https://docs.github.com/en/rest/git/trees), and [Git Blobs API](https://docs.github.com/en/rest/git/blobs).

## 5. Corpus benchmark

### Exact Repyy run

Observed report metadata: generated 2026-09-25T16:48:34Z; tool 0.5.3-dev; source commit e9dff17d680ec51f57c019be097ecc778ba6f4e1; rules 2026.09.19; intelligence cache 2026-09-12.1. The scanner JSON says 13 of 15 targets have complete coverage and two are incomplete. All 15 targets have REVIEW REQUIRED verdicts. Summing the individual report coverage gives 3,846 files and 301,147,785 bytes read, with four files skipped. Across reports there are 1,302 finding records and 9,190 occurrences. A record may aggregate many occurrences; DEX dominates these counts due repetitive vendor code.

The format below is records/occurrences by rule ID. This is the actual JSON output, not a claim of true/false positive accuracy.

| Target | Verdict / coverage | Files / bytes | Records / occurrences | Rule counts (records/occurrences) |
| --- | --- | ---: | ---: | --- |
| 0xnfteth-horsepowerfi | REVIEW REQUIRED / complete | 406 / 44,551,544 | 96 / 150 | ENV-001 13/34; EXEC-001 6/28; FONT-002 35/35; FONT-005 7/7; IOC-PKG-MSFT-2026-04-01-AXIOS 1/1; NET-001 1/1; OBFS-001 6/6; OBFS-002 1/6; OBFS-004 22/28; REPO-002 1/1; SECRET-002 2/2; SECRET-003 1/1 |
| DEX-staking-project-ultrax | SCAN INCOMPLETE | 911 / 31,845,610 | 664 / 7,357 | ENV-001 2/5; EXEC-001 109/3943; EXEC-002 4/93; EXEC-003 4/7; EXFIL-001 1/2; EXFIL-002 1/4; FONT-002 21/21; FONT-005 18/18; IMAGE-001 1/1; IOC-PKG-MSFT-2026-04-01-AXIOS 1/1; NET-001 3/5; OBFS-001 31/65; OBFS-002 7/13; OBFS-003 2/175; OBFS-004 387/1915; OBFS-005 48/311; OBFS-008 5/19; PROTO-001 10/485; REPO-002 1/1; SECRET-002 1/2; UNICODE-001 7/271 |
| challenge-experiment-module | REVIEW REQUIRED / complete | 69 / 2,248,780 | 13 / 21 | ENV-001 1/1; EXEC-001 4/8; IOC-PKG-MSFT-2026-04-01-AXIOS 1/1; OBFS-001 2/4; OBFS-004 3/5; PATH-001 1/1; REPO-002 1/1 |
| coinpool-rental-platform1.0 | REVIEW REQUIRED / complete | 159 / 3,528,409 | 32 / 69 | ENV-001 13/28; EXEC-001 6/28; FONT-002 8/8; FONT-003 4/4; REPO-002 1/1 |
| erc20-token-dapp | REVIEW REQUIRED / complete | 380 / 21,892,877 | 115 / 150 | ENV-001 1/1; EXEC-001 5/15; EXEC-002 2/2; EXEC-003 1/1; EXEC-004 2/2; FONT-002 31/31; FONT-005 22/22; IOC-PKG-MSFT-2026-04-01-AXIOS 1/1; NET-001 2/3; OBFS-001 4/7; OBFS-004 42/63; PKG-001 1/1; REPO-002 1/1 |
| golden-city | REVIEW REQUIRED / complete | 195 / 67,496,089 | 52 / 769 | COMBO-003 1/52; ENV-001 13/28; EVADE-001 1/1; EXEC-001 12/642; FONT-002 8/8; FONT-003 4/4; IMPORT-001 1/3; OBFS-002 3/9; OBFS-004 5/6; OBFS-008 1/1; PROTO-001 2/14; REPO-002 1/1 |
| multify_staking | REVIEW REQUIRED / complete | 159 / 1,966,558 | 27 / 95 | ENV-001 1/1; EXEC-001 4/63; EXEC-003 3/4; IMPORT-001 1/3; NET-001 1/2; OBFS-004 6/11; REPO-002 1/1; SECRET-001 1/1; SECRET-003 9/9 |
| munity-game | REVIEW REQUIRED / complete | 404 / 44,204,254 | 97 / 146 | ENV-001 13/28; EXEC-001 7/32; FONT-002 35/35; FONT-005 7/7; IMPORT-001 1/4; IOC-PKG-MSFT-2026-04-01-AXIOS 1/1; NET-001 1/1; OBFS-001 6/6; OBFS-004 23/29; REPO-002 1/1; SECRET-002 2/2 |
| real-estate-rental-platform | REVIEW REQUIRED / complete | 161 / 6,942,564 | 35 / 76 | AGENT-002 1/1; ENV-001 13/28; EXEC-001 7/33; FONT-002 8/8; FONT-003 4/4; OBFS-002 1/1; REPO-002 1/1 |
| real_estate | REVIEW REQUIRED / complete | 161 / 4,039,198 | 34 / 71 | ENV-001 13/28; EXEC-001 7/29; FONT-002 8/8; FONT-003 4/4; OBFS-002 1/1; REPO-002 1/1 |
| real_estate_new | REVIEW REQUIRED / complete | 163 / 7,956,452 | 33 / 72 | ENV-001 13/28; EXEC-001 6/30; FONT-002 8/8; FONT-003 4/4; OBFS-002 1/1; REPO-002 1/1 |
| sarostech-assessment | REVIEW REQUIRED / complete | 144 / 10,341,150 | 17 / 19 | ENV-001 2/3; EXEC-001 3/4; EXFIL-002 1/1; FONT-002 2/2; IOC-PKG-MSFT-2026-04-01-AXIOS 1/1; IPURL-001 1/1; OBFS-002 1/1; OBFS-004 5/5; REPO-002 1/1 |
| trend-dev-preproduction | SCAN INCOMPLETE | 256 / 44,372,857 | 29 / 32 | ENV-001 7/7; EXEC-001 5/8; FONT-002 8/8; FONT-003 2/2; FONT-005 2/2; IOC-PKG-MSFT-2026-04-01-AXIOS 2/2; OBFS-005 1/1; PKG-001 1/1; REPO-002 1/1 |
| web3game | REVIEW REQUIRED / complete | 276 / 8,531,625 | 56 / 161 | AGENT-002 1/1; ENV-001 13/28; EXEC-001 9/83; FONT-002 5/5; FONT-005 2/2; IMPORT-001 1/3; OBFS-001 3/5; OBFS-004 19/30; PKG-002 1/1; REPO-002 1/1 |
| scammer-documents | REVIEW REQUIRED / complete | 2 / 1,229,818 | 2 / 2 | REPO-001 1/1; REPO-002 1/1 |

DEX skipped three undecodable HTML files: public/charting_library/ar-tv-chart.e2a841ff.html, ko-tv-chart.e2a841ff.html, and th-tv-chart.e2a841ff.html. Trend skipped frontend/src/helpers/localized.ts. Repyy’s status is incomplete even though file(1) identifies these as text-like files; the report only establishes Repyy’s skip reason, not the correct decoder or whether the content is benign.

REPO-001 and REPO-002 on scammer-documents mean no top-level README/license, not active document malware. Static text extraction found an “ELO Whitepaper” and a two-page assessment requirement asking a candidate to review an ERC20 staking project. The scanner reported no DOC active-content finding. The PDFs provide social-engineering context, not proof of executable malware.

### Static sample-by-sample findings

All paths below are relative to the pinned sample directory. “Miss” means no relevant Repyy finding at the loader/package path in the actual JSON report; it does not mean the full sample has no findings.

| Sample | Static evidence observed | Repyy output at that evidence |
| --- | --- | --- |
| 0xnfteth-horsepowerfi | package scripts start the server. server/controllers/userController.js:266–283 contains an immediately invoked loader, decodes environment-supplied strings/URLs, retrieves remote JSON, and uses a Function.constructor wrapper with Node require. This is a source-level loader; the response body was not fetched. | OBFS-002 medium/medium review and ENV-001 medium/low informational at lines 267–279. No EXEC-001 or NET-001 at this loader. Other sample paths have unrelated generic findings. |
| DEX-staking-project-ultrax | package.json declares vite-tsconsole-log ^1.0.4. vite.config.js:5 imports it and :25 calls proc() while Vite config is loaded. The GitHub Advisory DB source identifies vite-tsconsole-log as malicious for all versions; package implementation is not in the corpus. | No finding for vite-tsconsole-log or vite.config.js. The Axios package name gets a high/high name-only review finding. DEX’s repetitive charting bundles create 664 records/7,357 occurrences, primarily EXEC-001, OBFS-004, PROTO-001 and other vendor-pattern noise. |
| challenge-experiment-module | package.json declares rest-icon-orchestrator ^1.0.3. vite.config.js:3 imports fetchIcon and :13 calls fetchIcon("99"). No package body or lockfile is present. Search of primary advisory sources did not corroborate this exact package. A similarly named rest-icon-provider is a different package and must not be conflated. | No finding for the package or vite.config.js. Axios gets a high/high name-only review finding. Package behavior and maliciousness remain unknown. |
| coinpool-rental-platform1.0 | server/controllers/userController.js:8 executes require("process-log")() at module load; the package source is absent. Startup scripts reach the server. GitHub advisory GHSA-rqwx-v86m-wwff identifies process-log as malware, affected range >=0. | No process-log finding; only ENV-001 at userController.js:103. The all-version package advisory is missing from local intelligence. |
| erc20-token-dapp | package.json:22 declares cdn-icon-fetch ^1.0.2; vite.config.js:5 imports fetchIcon and :12 calls fetchIcon("77"). package.json:60 has prepare: npm run start. GitHub advisory GHSA-gmvp-cqg5-vgvh identifies cdn-icon-fetch as malware, affected range >=0. package-lock.json instead contains cdn-icon-fetcher 1.2.2, not cdn-icon-fetch: manifest/lock disagreement. | PKG-001 catches prepare. No finding for cdn-icon-fetch or the Vite config import/call. Axios gets a high/high name-only review finding. |
| golden-city | backend/controllers/userController.js:204–209 fetches two npoint responses and evals response data at :207–208 in an invoked path. payloads/main.js is a separate large obfuscated file; its local source has evasion and dynamic execution but the audit did not prove it is the remote response body. | EXEC-001 high/medium review catches eval at 207–208. COMBO-003 high/high review aggregates evasion and execution inside payloads/main.js; it is not evidence that Repyy correlated the npoint fetch to the eval. |
| multify_staking | next.config.js begins with a roughly 91 KB obfuscated line before the ordinary config. Static-only constant/string decoding reconstructs host/browser and wallet/extension file reads, POST to 185.235.241.208:1224/uploads, and a downloaded Python stage written under ~/.sysinfo and executed. The remote response was not obtained. | next.config.js produces 58 EXEC-001, 3 IMPORT-001, and OBFS-004, all medium/low or low/low informational in detection-definition context. The material credential collection/exfiltration behavior is understated. |
| munity-game | server/routes/paymentRoute.js:14 contains a long payload after extensive whitespace. Static substitution indicates host reconnaissance, file write under ~/.vscode, download, npm install, and node execution. The second-stage response is absent, so wallet-theft claims are unverified. | EXEC-001 and IMPORT-001 are high/medium review at line 14; OBFS-004 is informational. Axios response-to-execution is not correlated. |
| real-estate-rental-platform | server/controllers/paymentController.js:127–132 uses two npoint responses and evals each response.data.cookie in an invoked module path. | EXEC-001 high/medium review catches lines 130–131 (and other eval sites in that controller). No axios remote-fetch finding or fetch/execute correlation in that file. |
| real_estate | server/controllers/userController.js:264–267 gets npoint JSON and evals result.data.cookie at :266 in an invoked path. | EXEC-001 high/medium review at line 266. No remote-fetch correlation. |
| real_estate_new | server/controllers/paymentController.js:127–132 has the two-response npoint/eval pattern. | EXEC-001 high/medium review catches lines 130–131 (and other eval sites). No remote-fetch correlation. |
| sarostech-assessment | server/config/getContract.js:131–138 obtains data from configured GET_HASHED_URL and evals error response data at :135, gated on an error response. src/utils/cookie.js:13 contains a separate cookie-related behavior. | EXEC-001 high/medium review at getContract.js:135 and EXFIL-002 high/medium review at cookie.js:13. No correlation between these different files or between fetch and execution. |
| trend-dev-preproduction | backend/controller.js:138–144 calls an external JSON endpoint and evals items.data.cookie at :141 during the imported/controller path. | EXEC-001 high/medium review at line 141 and OBFS-005 medium/medium review at :140. No network-to-execution correlation. The localized.ts skip keeps overall coverage incomplete. |
| web3game | server/middlewares/helpers/error.js is an approximately 86 KB obfuscated payload. Static decode reconstructs browser/wallet/keychain credential collection, multipart POST to 185.235.241.208:1224/uploads, and a Python stage under ~/.sysinfo. The separate paymentController.js:127–132 has two npoint response evals. No remote response was fetched. | Payment controller evals are EXEC-001 high/medium review. error.js has 48 EXEC-001 and 3 IMPORT-001 occurrences, but all are medium/low informational due detection-definition context. No exfiltration chain is correlated. |
| scammer-documents | ELO_Whitepaper_final.pdf is a 16-page whitepaper; Requirement.pdf is a two-page project assessment. Both PDFs were parsed as inert text. | Only REPO-001/REPO-002 repository-hygiene findings. No DOC active content findings. |

### Confirmed package-intelligence gaps

Primary sources reviewed:

- [Malware in process-log, GHSA-rqwx-v86m-wwff](https://github.com/advisories/GHSA-rqwx-v86m-wwff): npm package, all versions affected, no patched version.
- [Malware in cdn-icon-fetch, GHSA-gmvp-cqg5-vgvh](https://github.com/advisories/GHSA-gmvp-cqg5-vgvh): npm package, all versions affected, no patched version.
- [MAL-2025-4289 for vite-tsconsole-log](https://osv.dev/vulnerability/MAL-2025-4289), alias GHSA-x78w-rcq7-hrmr: npm package, introduced at 0/all versions.
- [Axios GHSA-fw8c-xr5c-95f9](https://github.com/advisories/GHSA-fw8c-xr5c-95f9) and [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/): exact malicious Axios versions 1.14.1 and 0.30.4; Microsoft says to downgrade to 1.14.0 or 0.30.3.

Repyy’s current snapshot contains the Axios exact-version record but not the three all-version packages above. Adding those sourced records is the most direct, high-confidence corpus improvement. Do not add rest-icon-orchestrator without a primary advisory or statically inspected package evidence.

## 6. Confirmed gaps and proposed scanner changes

### A. Intelligence coverage and version semantics

**Confirmed gap:** package names backed by three primary malicious-package advisories are absent. Their corpus samples do not produce package IOC findings.

**Proposed:** add process-log, cdn-icon-fetch, and vite-tsconsole-log to the maintained source/generation path and embedded snapshot with exact GHSA/OSV URLs, advisory IDs, published/modified dates, npm ecosystem, all-version range, and source provenance. Update metadata and regenerate rather than hand-editing only the embedded Go slice.

Separately clarify package resolution semantics. Distinguish:
1. exact resolved vulnerable version;
2. a declared semver range that can include a vulnerable version;
3. a name match whose version is unknown.

When a lockfile is present, prefer its resolved package version for a confirmed version match. Keep an explicit medium review for an unlocked range that could resolve to a bad release. Do not call a safe exact lock entry compromised because a package.json caret range contains the package name.

### B. Fetch-to-execution data flow

**Confirmed gap:** repeated local sources fetch JSON through Axios and immediately pass response fields to eval/Function. The rule set does not recognize Axios as fetch, and same-file category aggregation has no value flow. The scanner often catches eval but not the fetch/eval chain.

**Proposed:** implement a conservative bounded source-to-sink detector for known HTTP client calls and dynamic execution sinks. Begin with same-function patterns for await axios.get/post and .then callbacks, including response.data and error.response.data. Track simple aliases and preserve exact source/sink lines. Emit a correlation rule only when a fetched value reaches eval, new Function, Function constructor, or an OS-process sink. Do not flag a plain Axios request as malicious and do not block npoint.io by domain alone.

### C. Static JavaScript decoding

**Confirmed gap:** multify_staking and web3game contain large, statically decodable payloads. Current generic OBFS/EXEC findings do not recover their high-value source strings and results are downgraded.

**Proposed:** add a small, non-executing JavaScript constant decoder for a deliberately limited expression grammar. Candidate operations supported by these samples are literal string/number arrays, static index/rotation patterns, string/character concatenation, escape decoding, base64, and byte-array plus TextDecoder. Preserve source provenance from decoded token to original offsets. Feed decoded strings/expressions back into existing rules and source/sink analysis.

Do not use eval, Node, a VM, arbitrary function execution, dynamic import, network access, or package installation. Reject unsupported expressions rather than guessing. Apply hard caps for source bytes, tokens/array items, decode rounds, output bytes, nesting depth, CPU/time, and total findings; hitting a cap must produce incomplete coverage.

### D. Context and vendor-noise policy

**Confirmed gap:** a line substring heuristic can label executable obfuscated code as detection-definition and downgrade material findings. Conversely, public/charting_library/bundles is not classified as generated, so DEX vendor files create thousands of weak findings.

**Proposed:** make context classification path- and structure-based. Remove the generic regex-substring rule from ordinary executable source or restrict it to actual scanner-rule definition files. Add a strong-evidence floor so confirmed IOC, proven fetched-data-to-execution, credential collection plus transfer, and persistence signals cannot become informational solely because a line is minified or looks regex-like. Keep weak generic eval/prototype/API noise low in vendor bundles, but still scan and retain strong secrets, IOCs, and correlated behavior.

### E. Coverage on undecodable content

**Confirmed gap:** three DEX HTML locale bundles and one trend TypeScript helper are skipped, and both repositories are explicitly incomplete.

**Proposed:** determine whether the issue is invalid encoding, NUL/control-byte classification, or an unsupported parser before changing decoding. Add a small, data-only fixture representing the actual cause. Either support a safe text decoding path or retain the exact skip and SCAN INCOMPLETE result. Never convert an unsupported file to “no findings.”

### F. Entry/activation reachability

**Inferred opportunity:** the corpus often activates payloads through package scripts, top-level require, Vite/Next config, or server-route imports. A tiny static activation graph could show “this file is loaded by start/config” and help reviewers find direct behavior sooner.

**Proposed, later:** after source-to-sink work, add bounded parsing of package scripts and static require/import edges. Show graph paths as explanatory evidence, not a score, and label dynamic/unresolved edges. Avoid a whole-program JavaScript control-flow graph until corpus tests show the smaller feature is insufficient.

## 7. Website audit

### Existing routes

Source inventory is in site/src/pages. The website source declares 14 primary routes; the website agent checked each public route and observed 200 responses at audit time.

| Route | Current purpose |
| --- | --- |
| / | Product entry, scan workflow, trust summary |
| /docs/ | Documentation index and first-scan path |
| /installation/ | Install and first local/remote scan |
| /cli/ | Commands, flags, reports, exit codes |
| /configuration/ | Custom rules, suppressions, policy |
| /isolation/ | Docker and manual VM guidance |
| /coverage/ | Manually maintained coverage map |
| /intelligence/ | Offline snapshot/update behavior |
| /agent-skill/ | Coding-agent workflow integration |
| /trust/ | Data handling, host/Docker boundaries, claims |
| /demo/ | Versioned sample report and benchmark |
| /verification/ | Release artifact verification |
| /security-testing/ | Behavioral tests, fuzzing, limitations |
| /about/ | Project principles and reporting |

There are no /rules/ or /threats/ pages today.

Many route pages are hand-written Astro, while Markdown guides are separately maintained. site/check_docs.py checks that a Markdown counterpart exists, validates routes/search anchors/artifacts, but does not verify semantic parity. site/src/data/guides.ts is navigation metadata, not a Markdown renderer. Search entries are generated from page sections but each section’s indexed text is truncated at 1,200 characters, so later material can be undiscoverable.

The existing /coverage/ page is manually authored. The Markdown docs/COVERAGE.md and rule catalog contain coverage such as EXEC-005/006, BUILD-*, PERSIST-*, and DOC-* that is missing from the page’s coverage rows; PDF/Office appear only in explanatory limits text. Repyy’s exported BuiltinRuleCatalog is the durable source for a complete rule reference.

### Page recommendations

1. **Improve existing /coverage/** rather than creating a duplicate. Generate detection area, rule IDs, severity/confidence, match scope, applicable paths, and links from the rule catalog. Show supported ecosystems and deliberate exclusions as separate data. Put ruleset version and “generated from” identity on the page.
2. **Add /rules/** because a reviewer needs to understand a specific finding, its legitimate-use cases, exact scope, remediation, and context behavior. Provide filters for category, severity, ecosystem/path and a search box. Source the data from a new stable machine-readable catalog command/artifact; do not hand-copy 100+ rules into Astro. Name the page and CLI command distinctly from intelligence data. Current repyy rules list output is not this catalog.
3. **Add /threats/** as a concise threat-model page only. Map concrete repository scenarios to existing rules and state what static evidence can/cannot establish: malicious take-home assignments; package lifecycle/config imports; remote response to dynamic execution; credential read and exfiltration; obfuscated/generated bundles; active documents. Avoid broad malware taxonomies and actor claims. The source handoff cuts off mid-example, so remaining user-requested content for this route is unknown.

Proposed technical surface: expose a versioned command or checked-in generated JSON from BuiltinRuleCatalog, such as repyy rules catalog --format json. Keep repyy intel commands explicit about package/hash indicators. Build the coverage/rules pages from that artifact, and make site checks fail if a catalog ID is missing, duplicated, unknown, or out of version sync.

## 8. Implementation plan

### Order and dependencies

1. **Intel records and package-match tests.** Add the three confirmed all-version records to the intel generation source and snapshot. Add metadata and source URLs. Resolve manifest/lockfile semantics before describing any specific version as confirmed. This is a self-contained first deliverable.
2. **Bounded JavaScript decoder foundation.** Add the small pure-data decoder and provenance model, with resource-limit behavior before enabling it on corpus paths. Do not execute decoded content.
3. **Fetch-to-execution correlation.** Add Axios and other explicitly supported source forms only inside the bounded source/sink detector. Keep generic network rules low-confidence and independent.
4. **Context/noise correction.** Reclassify actual generated/vendor paths without suppressing strong indicators. Add paired fixtures for charting-library-style benign bundle APIs and malicious bundle behavior.
5. **Coverage/activation behavior.** Fix or preserve the four undecodable-file incomplete results based on byte-level cause. Add the minimal entrypoint graph only if the earlier changes leave a demonstrated review gap.
6. **Acquisition limits and adapter study.** Specify resource caps and incomplete semantics before any change to acquisition. Keep Git default. Design a pinned tree/blob adapter or archive prototype separately and compare path/mode/blob inventory on GitHub/Bitbucket cases before considering it as default.
7. **Rule catalog and website.** Add machine-readable catalog output; generate /coverage and /rules; add curated /threats only after the truncated requirements are resolved. Update Markdown counterparts, navigation, search indexing, and claims.
8. **Documentation and release evidence.** Update docs/COVERAGE.md, docs/TRUST.md, docs/SECURITY-TESTING.md, CLI reference, demo expectations, and website trust/coverage pages only after acceptance criteria pass.

### Existing tests to expand

- Package intelligence: internal/intel/database_test.go TestAffectedExactAndAllVersions; internal/intel/snapshot_test.go TestSnapshotEntriesAreValidAndUnique; internal/scan/scanner_test.go TestDetectsConfirmedPackageNamesAcrossEcosystems and TestKnownBenignPackageIsNotBlocklisted.
- Source/sink and correlation: internal/scan/scanner_test.go TestCorrelationsRetainOnlyContributingRulesAndLocations, TestDetectsDownloadExecuteAndLifecycle, and TestLiteralDependentRulesRemainCovered.
- Decoder and context: internal/scan/scanner_test.go TestGeneratedCodeSignalsAreDetected, TestMinifiedAndDistributionOutputUsesGeneratedContext, TestGeneratedContextSuppressesWeakNoiseButRetainsSecrets; internal/scan/active_content_test.go TestEncodedStagedAndProxyExecution.
- Coverage: internal/scan/scanner_test.go TestUndecodableScriptCannotReportCompleteCoverage.
- Catalog: internal/scan/scanner_test.go TestRuleCatalogEntriesProvideReviewGuidance; internal/app/app_test.go TestRulesListJSONIncludesProvenance.
- Acquisition: internal/source/source_test.go TestSecureGitEnvironmentIsNonInteractive, TestSecureGitEnvironmentAllowsOnlyRequestedSSHProtocol, URL validation tests; internal/sandbox/docker_test.go for fetch/scan boundary claims.
- Site: site/check_docs.py route, link, search, and counterpart checks.

### Genuinely new tests

- All-version package advisories: manifest declarations for process-log, cdn-icon-fetch, and vite-tsconsole-log match; benign package names do not. Axios exact 1.14.1/0.30.4 match, safe exact lock versions do not, and a declared unlocked range that could include 1.14.1 is reported as potential range exposure rather than confirmed resolved malware.
- Axios-to-exec positive fixtures for awaited response.data, a simple alias, .then callback, and error.response.data. Benign Axios JSON request/render controls must not produce fetch/execute correlation.
- New static decoder unit test proving representative string/byte arrays decode to inert text, original offsets survive, unsupported JS is not evaluated, and per-file/array/round/output limits make coverage incomplete.
- Malicious generated-context fixture proving confirmed IOC and fetch-to-exec behavior remain review/block-level; benign vendor bundle controls prove weak APIs remain informational.
- Catalog export test proving schema/version and exact parity with BuiltinRuleCatalog; generated page check proving every catalog ID appears once and no hand-maintained unknown IDs exist.
- Acquisition budget and ref tests using inert local fixtures or a fake Git executable/server; test timeout, byte/count limit, redirect/auth boundaries, exact commit identity, cleanup failures, and incomplete result propagation. No test should contact public ScanRepo or attacker infrastructure.

### Benign controls

- Normal Vite plugins and ordinary Vite/Next config imports/calls.
- Charting/vendor bundles with routine eval/polyfill/prototype helpers and no sensitive reads, suspicious transfer, or persistence.
- Axios GET/POST used for ordinary application JSON that is not executed.
- Regex/signature-rule source containing backslash-s and Pattern: text.
- Test fixtures/docs containing eval or package lifecycle examples.
- Exact safe Axios lock versions and normal package aliases.
- PDF and Office files with passive text only.

### Security and resource limits

- Decoder must be deterministic, bounded, data-only, no code execution or network.
- Every decoding stage needs per-file and global byte/output/round/array limits, timeout, and maximum finding/location counts.
- Keep archive byte/count/depth limits and path/link confinement. Any skipped file or limit must keep coverage incomplete.
- Any source/sink report must preserve exact input and sink locations, not just a generic score.
- Acquisition resource caps must apply before scanner traversal or must use an adapter that can enforce streamed response limits. Do not describe post-clone scanner limits as clone disk protection.
- No automatic intel downloads, telemetry, report upload, or public publication from normal scans.

### Acceptance criteria

- The three advisory-backed sample dependencies produce sourced, version-correct package findings from the embedded snapshot.
- Axios 1.14.1 and 0.30.4 are confirmed exact-version hits; safe lock entries are not described as confirmed compromised. Unlocked vulnerable ranges are clearly labeled as possible resolution exposure.
- Remote data passed into eval/Function is elevated with exact source/sink evidence; plain Axios requests remain benign controls.
- Multify/web3game decoded strings reveal only static evidence and their strong behavior is not downgraded by regex-like/minified context.
- DEX vendor bundle noise is reduced without suppressing malicious behavior or secrets; undecodable content remains visible and incomplete.
- Every sample’s expected and observed behavior is recorded in the versioned benchmark without calling this corpus a global accuracy score.
- Rule catalog pages match the exact Repyy ruleset version and catalog; documentation and search route users to the right command/page.
- Remote acquisition is explicitly bounded or its remaining boundary is accurately disclosed; any unsupported/partial fetch returns incomplete.
- No change introduces remote LLM use, broad reputational scoring, public-by-default result sharing, automatic package resolution, or execution of analyzed source.

### Non-goals

- Do not execute samples, fetched stages, installers, or dependencies.
- Do not contact any sample’s npoint, C2, or exfiltration host.
- Do not implement a general JavaScript runtime or promise complete malware detection.
- Do not blocklist common hosting domains or treat account reputation as source-code safety.
- Do not add a public scan/report database or heuristic 0–100 safety score.
- Do not attribute the corpus to an actor without independent primary evidence.
- Do not replace Git acquisition with archives until inventory parity and resource-bound extraction are demonstrated.
- Do not claim that an advisory proves the missing package code’s exact runtime behavior.

## 9. Unresolved items

- The objective file ends mid-Part XIV after “credential steal”; further threat-page requirements are unavailable.
- No malicious payload endpoint was contacted. Remote response contents, later-stage behavior, and association between Golden City’s separate local payloads and remote content remain unknown.
- The actual npm package archives for the three advisory-backed packages were not downloaded or inspected; the primary advisories suffice to establish package malware and affected ranges, but not their exact per-sample payload behavior.
- rest-icon-orchestrator has no corroborating primary advisory in the sources checked. Do not infer from the similarly named rest-icon-provider package.
- DEX’s three HTML locale bundles and trend’s localized.ts remain undecoded by Repyy; their semantic contents are unresolved.
- ScanRepo engine internals, CLI transmission/retention, telemetry, and some dynamic feed contents were not independently verified. Its public docs and pages remain claims.
- The live Repyy website could be reviewed from source; direct web-reader access to repyy.dev was unavailable in this audit session.

**Approval boundary:** Phase 1 is complete. Do not edit Repyy until the user approves this report and plan.
