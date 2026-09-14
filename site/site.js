const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
document.documentElement.classList.add("has-js");

document.querySelectorAll("button, .button, .nav-docs").forEach((pressable) => {
  pressable.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    pressable.classList.add("is-pressed");
  });
  ["pointerup", "pointercancel", "pointerleave"].forEach((eventName) => {
    pressable.addEventListener(eventName, () => pressable.classList.remove("is-pressed"));
  });
});

const revealItems = document.querySelectorAll(".reveal");
if (reduceMotion) {
  revealItems.forEach((item) => item.classList.add("is-visible"));
} else {
  const revealObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        revealObserver.unobserve(entry.target);
      });
    },
    { threshold: 0.14 },
  );
  revealItems.forEach((item) => revealObserver.observe(item));
}

const showCopyResult = (button, result) => {
  const label = button.querySelector("[data-copy-label]") || button;
  const original = label.textContent;
  label.textContent = result;
  window.setTimeout(() => {
    label.textContent = original;
  }, 1600);
};

const copyText = async (button, value) => {
  try {
    await navigator.clipboard.writeText(value);
    showCopyResult(button, "Copied");
  } catch {
    const fallback = document.createElement("textarea");
    fallback.value = value;
    fallback.setAttribute("readonly", "");
    fallback.style.position = "fixed";
    fallback.style.opacity = "0";
    document.body.appendChild(fallback);
    fallback.select();
    const copied = document.execCommand("copy");
    fallback.remove();
    showCopyResult(button, copied ? "Copied" : "Select and copy");
  }
};

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", () => copyText(button, button.dataset.copy));
});

const attachTabs = (tabs, select) => {
  tabs.forEach((tab, index) => {
    tab.tabIndex = tab.classList.contains("is-active") ? 0 : -1;
    tab.addEventListener("click", (event) => select(tab, event.detail !== 0));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const nextIndex =
        event.key === "Home"
          ? 0
          : event.key === "End"
            ? tabs.length - 1
            : (index + (event.key === "ArrowLeft" ? -1 : 1) + tabs.length) % tabs.length;
      tabs[nextIndex].focus();
      select(tabs[nextIndex], false);
    });
  });
};

document.querySelectorAll("[data-install-tabs]").forEach((panel) => {
  const tabs = [...panel.querySelectorAll("[data-install-command]")];
  const output = panel.querySelector("[data-install-output]");
  const copy = panel.querySelector("[data-install-copy]");

  const select = (tab) => {
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-selected", String(active));
      item.tabIndex = active ? 0 : -1;
    });
    output.textContent = tab.dataset.installCommand;
  };

  attachTabs(tabs, select);
  copy.addEventListener("click", () => copyText(copy, output.textContent));
});

const reportFormats = {
  terminal: {
    title: "Terminal review",
    use: "Human review",
    description: "Prioritized findings with context and a clear verdict.",
    command: "repyy scan ./assignment",
    preview:
      "$ repyy scan ./assignment\n\nREVIEW REQUIRED\n2 findings need context\n\nHIGH  PKG-001   package.json:12\nMED   OBFS-003   src/setup.js:48",
  },
  json: {
    title: "Structured JSON",
    use: "Automation and archives",
    description: "Stable identifiers, provenance, coverage, and redacted evidence.",
    command: "repyy scan ./assignment --format json",
    preview:
      '{\n  "verdict": "REVIEW REQUIRED",\n  "coverage": { "complete": true },\n  "findings": [\n    {\n      "rule_id": "PKG-001",\n      "severity": "high",\n      "confidence": "high"\n    }\n  ]\n}',
  },
  sarif: {
    title: "SARIF output",
    use: "Code scanning",
    description: "Portable findings for existing security and review workflows.",
    command: "repyy scan ./assignment --format sarif",
    preview:
      '{\n  "version": "2.1.0",\n  "runs": [{\n    "tool": { "driver": { "name": "repyy" } },\n    "results": [{\n      "ruleId": "PKG-001",\n      "level": "error"\n    }]\n  }]\n}',
  },
  html: {
    title: "Offline HTML report",
    use: "Private review artifact",
    description: "A self-contained local report with filters and redacted evidence.",
    command: "repyy scan ./assignment --format html --output report.html",
    preview:
      "report.html\n\nEMBEDDED CSS AND JAVASCRIPT\nSource links open provider websites\n\nReview queue       2\nInformational      4\nCoverage       complete\nEvidence        redacted",
  },
};

document.querySelectorAll("[data-report-lab]").forEach((lab) => {
  const tabs = [...lab.querySelectorAll("[data-report-format]")];
  const screen = lab.querySelector(".report-screen");
  const title = lab.querySelector("[data-report-title]");
  const preview = lab.querySelector("[data-report-preview]");
  const use = lab.querySelector("[data-report-use]");
  const description = lab.querySelector("[data-report-description]");
  const command = lab.querySelector("[data-report-command]");
  const copy = lab.querySelector("[data-report-copy]");
  let animation;

  const select = (tab, animate) => {
    const format = reportFormats[tab.dataset.reportFormat];
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-selected", String(active));
      item.tabIndex = active ? 0 : -1;
    });
    title.textContent = format.title;
    preview.textContent = format.preview;
    use.textContent = format.use;
    description.textContent = format.description;
    command.textContent = format.command;
    lab.dataset.input = animate ? "pointer" : "keyboard";

    animation?.cancel();
    if (animate && !reduceMotion) {
      animation = screen.animate(
        [
          { opacity: 0.58, transform: "translate3d(0, 4px, 0)" },
          { opacity: 1, transform: "translate3d(0, 0, 0)" },
        ],
        { duration: 200, easing: "cubic-bezier(.23, 1, .32, 1)" },
      );
    }
  };

  attachTabs(tabs, select);
  copy.addEventListener("click", () => copyText(copy, command.textContent));
});

const docsSearch = document.querySelector("#docs-search");
if (docsSearch) {
  const sections = [...document.querySelectorAll(".docs-searchable")];

  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && document.activeElement !== docsSearch) {
      event.preventDefault();
      docsSearch.focus();
    }
    if (event.key === "Escape" && document.activeElement === docsSearch) {
      docsSearch.value = "";
      docsSearch.dispatchEvent(new Event("input"));
      docsSearch.blur();
    }
  });

  const links = [...document.querySelectorAll('.docs-sidebar a[href^="#"]')];
  const sidebarNav = document.querySelector(".docs-sidebar nav");
  sidebarNav?.addEventListener("keydown", (event) => {
    if (
      sidebarNav.scrollHeight <= sidebarNav.clientHeight ||
      event.altKey ||
      event.ctrlKey ||
      event.metaKey
    )
      return;
    const distance = {
      ArrowUp: -40,
      ArrowDown: 40,
      PageUp: -sidebarNav.clientHeight,
      PageDown: sidebarNav.clientHeight,
      Home: -sidebarNav.scrollHeight,
      End: sidebarNav.scrollHeight,
    }[event.key];
    if (distance === undefined) return;
    event.preventDefault();
    sidebarNav.scrollBy({ top: distance, behavior: "instant" });
  });
  const linkById = new Map(links.map((link) => [link.hash.slice(1), link]));
  const markCurrent = (current) => {
    links.forEach((link) => {
      link.classList.toggle("is-current", link === current);
      if (link === current) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
  };
  links.forEach((link) => {
    link.addEventListener("click", () => markCurrent(link));
  });
  const sectionObserver = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      markCurrent(linkById.get(visible.target.id));
    },
    { rootMargin: "-18% 0px -68%", threshold: [0, 0.2, 0.5] },
  );
  sections.forEach((section) => sectionObserver.observe(section));
}

const docsGlobalIndex = [
  ["/docs/", "Documentation", "overview", "Overview", "overview scanner read only guides"],
  [
    "/docs/",
    "Documentation",
    "getting-started",
    "Run your first scan",
    "getting started install first scan local folder html git",
  ],
  [
    "/docs/",
    "Documentation",
    "recipes",
    "Copyable starting points",
    "examples local remote powershell docker json sarif targets",
  ],
  [
    "/docs/",
    "Documentation",
    "verdicts-docs",
    "Read the result",
    "verdict findings no findings review required do not run incomplete exit code",
  ],
  [
    "/docs/",
    "Documentation",
    "reports-docs",
    "Choose a report",
    "terminal json sarif html report output offline file",
  ],
  [
    "/docs/",
    "Documentation",
    "privacy",
    "Know the boundary",
    "privacy network credentials telemetry upload",
  ],
  [
    "/docs/",
    "Documentation",
    "intelligence",
    "What \u201cintel\u201d means",
    "intel intelligence indicators packages hashes snapshot status update rollback",
  ],
  [
    "/docs/",
    "Documentation",
    "agent-skill-docs",
    "Give your coding agent a safe first step",
    "agent skill codex instructions workflow",
  ],
  [
    "/docs/",
    "Documentation",
    "limits-docs",
    "When coverage is incomplete",
    "limits timeout files archive incomplete coverage",
  ],
  ["/installation/", "Installation", "overview", "Installation", "install first scan binary"],
  [
    "/installation/",
    "Installation",
    "prerequisites",
    "Prerequisites",
    "git docker browser macos linux windows",
  ],
  [
    "/installation/",
    "Installation",
    "macos-linux",
    "Install on macOS and Linux",
    "homebrew archive deb rpm apk go path",
  ],
  [
    "/installation/",
    "Installation",
    "windows",
    "Install on Windows PowerShell",
    "windows powershell scoop zip path",
  ],
  [
    "/installation/",
    "Installation",
    "checksums",
    "Verify the release",
    "checksum sha256 signed binary",
  ],
  [
    "/installation/",
    "Installation",
    "first-scan",
    "Run a first local scan",
    "local html report intel status",
  ],
  [
    "/installation/",
    "Installation",
    "remote",
    "Scan a remote repository",
    "remote github gitlab bitbucket https ssh token",
  ],
  [
    "/installation/",
    "Installation",
    "troubleshooting",
    "Troubleshoot the first run",
    "command not found permission timeout html",
  ],
  [
    "/cli/",
    "CLI reference",
    "overview",
    "CLI reference",
    "commands flags scan report rules intelligence",
  ],
  ["/cli/", "CLI reference", "shape", "Command shape", "syntax subcommands targets path url"],
  ["/cli/", "CLI reference", "first-scan", "Run a first scan", "local remote folder git"],
  [
    "/cli/",
    "CLI reference",
    "targets",
    "Targets and target files",
    "multiple file jobs history clone",
  ],
  [
    "/cli/",
    "CLI reference",
    "scan-flags",
    "All scan flags",
    "format output config dependencies sandbox fail timeout detail progress severity confidence",
  ],
  ["/cli/", "CLI reference", "recipes", "Copyable scan recipes", "html json sarif ci docker"],
  ["/cli/", "CLI reference", "reports", "Choose a report format", "terminal json sarif html"],
  [
    "/cli/",
    "CLI reference",
    "report-command",
    "Render a saved JSON report",
    "report stdin filters",
  ],
  ["/cli/", "CLI reference", "rules", "Rules commands", "validate check list explain"],
  [
    "/cli/",
    "CLI reference",
    "intel",
    "Intelligence commands",
    "intel status update rollback snapshot",
  ],
  [
    "/cli/",
    "CLI reference",
    "exit-codes",
    "Exit codes and verdicts",
    "zero one two three incomplete threshold",
  ],
  ["/cli/", "CLI reference", "troubleshooting", "Troubleshooting", "git docker incomplete"],
  [
    "/configuration/",
    "Configuration",
    "overview",
    "Configuration",
    "trusted yaml custom rules suppressions",
  ],
  [
    "/configuration/",
    "Configuration",
    "boundary",
    "Understand the trust boundary",
    "repository config trust",
  ],
  ["/configuration/", "Configuration", "minimal", "Start with valid YAML", "version rules yaml"],
  ["/configuration/", "Configuration", "workflow", "Use the safe workflow", "validate scan config"],
  [
    "/configuration/",
    "Configuration",
    "rule-fields",
    "Custom rule fields",
    "severity confidence pattern globs rationale",
  ],
  [
    "/configuration/",
    "Configuration",
    "rule-walkthrough",
    "Walk through a custom rule",
    "regex example",
  ],
  ["/configuration/", "Configuration", "scope", "Choose the matching scope", "raw code structured"],
  [
    "/configuration/",
    "Configuration",
    "suppressions",
    "Suppress one reviewed finding",
    "fingerprint reason expires",
  ],
  ["/configuration/", "Configuration", "review-example", "Review example", "finding exception"],
  [
    "/configuration/",
    "Configuration",
    "limits",
    "Limits and validation errors",
    "invalid regex exit code 3",
  ],
  ["/coverage/", "Detection coverage", "overview", "Detection coverage", "rules detection limits"],
  [
    "/coverage/",
    "Detection coverage",
    "map",
    "Coverage map",
    "execution obfuscation dependencies secrets network shells mining ci containers git",
  ],
  [
    "/coverage/",
    "Detection coverage",
    "supply-chain",
    "Supply-chain files by ecosystem",
    "npm yarn pnpm pip uv bundler go cargo gradle maven composer nuget package sources build scripts wrappers",
  ],
  [
    "/coverage/",
    "Detection coverage",
    "precision",
    "How repyy improves precision",
    "context scope correlation confidence",
  ],
  [
    "/coverage/",
    "Detection coverage",
    "limits",
    "Coverage has a boundary",
    "timeout max files archive incomplete",
  ],
  [
    "/coverage/",
    "Detection coverage",
    "exclusions",
    "Deliberate exclusions",
    "generated lockfiles offline privacy",
  ],
  [
    "/coverage/",
    "Detection coverage",
    "explain",
    "Explain a rule before acting",
    "rules explain rationale",
  ],
  [
    "/coverage/",
    "Detection coverage",
    "list",
    "Inspect the active intelligence",
    "rules list snapshot packages hashes",
  ],
  [
    "/coverage/",
    "Detection coverage",
    "workflow",
    "A practical review workflow",
    "evidence verdict report",
  ],
  ["/isolation/", "Isolation", "overview", "Isolation", "docker vm sandbox network read only"],
  ["/isolation/", "Isolation", "docker", "Docker release image", "sandbox digest signed image"],
  [
    "/isolation/",
    "Isolation",
    "docker-image",
    "Verify the image signature",
    "cosign sigstore checksum",
  ],
  [
    "/isolation/",
    "Isolation",
    "local",
    "Docker with a local folder",
    "mount networking disabled json",
  ],
  ["/isolation/", "Isolation", "https", "Docker with an HTTPS remote", "fetch credentials git"],
  [
    "/isolation/",
    "Isolation",
    "edge-cases",
    "Know the edge cases",
    "incomplete timeout ssh keep workdir",
  ],
  ["/isolation/", "Isolation", "vm", "Manual VM workflows", "windows macos linux guest"],
  [
    "/isolation/",
    "Isolation",
    "windows-sandbox",
    "Windows Sandbox",
    "wsb powershell mapped folders",
  ],
  ["/isolation/", "Isolation", "utm", "macOS with UTM", "macos vm read only"],
  ["/isolation/", "Isolation", "qemu", "Linux with QEMU/KVM", "linux qemu kvm"],
  [
    "/intelligence/",
    "Intelligence",
    "overview",
    "Intelligence",
    "intel threat offline snapshot packages hashes",
  ],
  [
    "/intelligence/",
    "Intelligence",
    "difference",
    "Rules and intelligence work together",
    "built in rules indicators versions",
  ],
  [
    "/intelligence/",
    "Intelligence",
    "status",
    "Check before you scan",
    "status freshness verification cache",
  ],
  [
    "/intelligence/",
    "Intelligence",
    "update",
    "Update only when you choose to",
    "update download ed25519 signature",
  ],
  [
    "/intelligence/",
    "Intelligence",
    "rollback",
    "Roll back a cached update",
    "rollback previous cache",
  ],
  [
    "/intelligence/",
    "Intelligence",
    "investigate",
    "Investigate an indicator",
    "rules explain list check advisory hash",
  ],
  [
    "/agent-skill/",
    "Agent skill",
    "overview",
    "Optional agent skill",
    "instructions codex scan read only",
  ],
  [
    "/agent-skill/",
    "Agent skill",
    "install",
    "Install the skill",
    "npx skills add global interactive",
  ],
  [
    "/agent-skill/",
    "Agent skill",
    "workflow",
    "What the skill tells an agent to do",
    "workflow json html verdict incomplete",
  ],
  [
    "/agent-skill/",
    "Agent skill",
    "docker",
    "Use Docker when you need a process boundary",
    "docker sandbox digest ssh",
  ],
  [
    "/agent-skill/",
    "Agent skill",
    "limits",
    "Understand the limits",
    "privacy target execute build test upload intel",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "security-model",
    "Security model",
    " Repository files filenames configuration archives Git metadata and source derived report values are untrusted input The scanner reads them as data It does not intentionally import install build test or run assignment code It does not compute a complete runtime call graph Findings describe observable patterns not proof that a behavior occurred The trusted computing base includes the Repyy executable its dependencies operating system explicitly supplied rules and tools used for retrieval or isola",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "what-repyy-reads",
    "What Repyy reads",
    " Repyy inspects regular files within the selected repository selected Git metadata and bounded archive entries It reads manifests without invoking package managers Dependency cache directories are excluded by default include dependencies expands that scope Explicit trusted configuration can add rules and suppressions Do not use a rules file supplied by the assignment as trusted configuration The local target root is resolved before inspection and file reads use a confined filesystem root Symlink",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "what-repyy-does-not-execute",
    "What Repyy does not execute",
    " Normal scan paths do not invoke target scripts hooks build systems test runners Docker Compose package managers or IDEs Host remote scans invoke Git clone and revision lookup Docker mode invokes the Docker client container Git and the Repyy worker Windows report file permission setup may invoke icacls These are trusted host tools not assignment commands Source repository preparation https github com Kevin Umali repyy blob main internal source source go scanner https github com Kevin Umali repyy",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "network-behavior",
    "Network behavior",
    " This table describes implementation behavior not a firewall guarantee for the host process No scan feature uploads assignment contents or scan reports to a Repyy service Feature Default trigger Destination and data sent Authentication Failure and boundary Local scan and rules report commands Local scan default no intentional network request None embedded or verified cached intelligence is read locally None File parser failures are reported host mode has no network sandbox Host remote scan Only ",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "local-data-handling",
    "Local data handling",
    " Local scans keep source in place Reports go to stdout or the requested output path and can contain sensitive filenames repository identity and redacted evidence Redaction is pattern based not a guarantee that arbitrary secrets are removed Treat reports as sensitive and review before sharing No telemetry client or report upload path is implemented in the normal scanner Intelligence snapshots and active previous pointers are stored in the local cache Invalid cached intelligence falls back to embe",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "temporary-repositories-and-cleanup",
    "Temporary repositories and cleanup",
    " Host remotes use a private repyy clone temporary directory Git hooks templates recursive submodules redirects system global Git configuration and unrequested Git protocols are disabled Default history depth is one keep workdir deliberately retains host checkouts Otherwise cleanup is deferred clone revision failures also attempt removal Docker remotes use a private repyy sandbox parent with a writable fetch child followed by a read only scan mount Provider tokens use a separate mode 0600 tempora",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "host-mode-boundaries",
    "Host-mode boundaries",
    " Host mode is the default Remote scans use installed Git and for SSH host SSH configuration agents Git configuration is filtered but the process still inherits other host environment and OS capabilities Updating Git and SSH and choosing an appropriate isolation environment remain the user s responsibility A local static scan does not turn the host into a malware sandbox ",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "docker-mode-boundaries",
    "Docker-mode boundaries",
    " The image must be digest pinned and explicitly available locally The worker uses read only input root filesystem dropped capabilities no new privileges process memory CPU limits and bounded temporary storage Remote fetch and scan are separate stages Docker daemon access itself is a powerful host capability Containers share a kernel and are not equivalent to a dedicated virtual machine See isolation site isolation index html ",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "incomplete-scans-and-exit-codes",
    "Incomplete scans and exit codes",
    " Human status Meaning Schema 1 verdict compatibility Findings detected Findings warrant review before execution DO NOT RUN remains the legacy machine value Review required Review observed findings and their context REVIEW REQUIRED No relevant findings detected No enabled rule matched in completed coverage NO FINDINGS Scan incomplete Error limit or reduced coverage prevents a completed result SCAN INCOMPLETE Unsupported or unresolved content present Read the skipped content and warning details no",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "static-analysis-limitations",
    "Static-analysis limitations",
    " Static analysis can miss malicious behavior and flag legitimate code Dynamic imports generated code encrypted content and runtime state may be unresolved A filename signature or suspicious string alone does not establish malicious intent Inspect the evidence and ask the sender for context The demo benchmark explicitly preserves known misses ",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "claim-to-evidence-map",
    "Claim-to-evidence map",
    " Claim Evidence Status limits Normal scans read assignment code as data internal scan scanner go https github com Kevin Umali repyy blob main internal scan scanner go internal source source go https github com Kevin Umali repyy blob main internal source source go test integration cli test go https github com Kevin Umali repyy blob main test integration cli test go Implementation and regression coverage no universal non execution proof Local report rendering needs no network internal output html ",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "releases-security-testing-and-reviews",
    "Releases, security testing and reviews",
    " Read release verification VERIFICATION md security testing SECURITY TESTING md and the external review brief EXTERNAL REVIEW md See the verification guide for current CodeQL Scorecard and attestation evidence status No independent audit badge is claimed Report vulnerabilities privately using GitHub vulnerability reporting https github com Kevin Umali repyy security advisories new Include version OS impact and the smallest inert reproduction Do not send working credentials or private assignment ",
  ],
  [
    "/trust/",
    "Trust and Limitations",
    "overview",
    "Trust and Limitations",
    "Trust and Limitations Understand the boundary. Inspect the evidence.",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "current-evidence-status",
    "Current evidence status",
    " Release v0 5 0 publishes checksums and signing certificates a signed sandbox image digest and per archive SBOMs The next release workflow adds GitHub attestations and a release set SPDX SBOM Do not assume older releases have these new attestations A configured workflow is not published verification evidence The new workflow keeps the GitHub release draft until download verification succeeds A failed gate must remain visible and must not be described as a verified release Homebrew and Scoop mani",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "version-and-commit-identity",
    "Version and commit identity",
    " Run repyy version only after verifying the downloaded artifact It reports version full source commit builder label fixed source repository Go version build date and rules version Missing values are unknown local builds label their builder development These strings are diagnostics not cryptographic identity Official workflow builds inject metadata into binaries and the sandbox image Local scan reports cannot claim an immutable checkout commit local content may be uncommitted or change during ins",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "verify-provenance",
    "Verify provenance",
    " Use a recent GitHub CLI with the gh attestation command For a downloaded archive or extracted binary replace the placeholders with the exact release and filename sh gh attestation verify ARTIFACT repo Kevin Umali repyy signer workflow Kevin Umali repyy github workflows release yml source ref refs tags vX Y Z Require the expected repository workflow and release ref Check the source commit in the verification output against the release notes Attestations for extracted binaries let users verify af",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "checksums-and-existing-signatures",
    "Checksums and existing signatures",
    " A checksum detects changed bytes only after the checksum list itself is authenticated Existing releases use Cosign keyless signatures this work retains that existing path rather than adding a second signing system sh cosign verify blob checksums txt signature checksums txt sig certificate checksums txt pem certificate identity https github com Kevin Umali repyy github workflows release yml refs tags vX Y Z certificate oidc issuer https token actions githubusercontent com sha256sum check checksu",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "sbom-access-and-scope",
    "SBOM access and scope",
    " The container inventory is published as repyy container spdx json and attested against the image digest Per archive sbom json assets identify archive contents repyy release spdx json describes the release build directory as a set including platform binaries and packages It is not a separate per platform dependency assertion The workflow binds that set inventory to each binary archive package digest using an SPDX attestation Read its package inventory and relationships rather than interpreting a",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "container-verification",
    "Container verification",
    " Read the exact image digest from the verified repyy sandbox image txt asset Replace DIGEST and the version below sh gh attestation verify oci ghcr io kevin umali repyy sandbox sha256 DIGEST repo Kevin Umali repyy signer workflow Kevin Umali repyy github workflows release yml source ref refs tags vX Y Z cosign verify ghcr io kevin umali repyy sandbox sha256 DIGEST certificate identity https github com Kevin Umali repyy github workflows release yml refs tags vX Y Z certificate oidc issuer https t",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "fresh-download-release-gate",
    "Fresh-download release gate",
    " Maintainers can run the same Linux gate used by the workflow with a directory that does not yet exist sh bash scripts verify release sh vX Y Z tmp repyy verification vX Y Z This needs GitHub CLI with attestation support Cosign and SHA 256 tooling GitHub Actions supplies the tools for maintainers who do not want local installations It downloads release assets into the fresh directory and checks checksum signatures hashes artifact provenance SBOM attestations and container signatures provenance A",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "repository-security-signals",
    "Repository security signals",
    " Inspect CodeQL runs https github com Kevin Umali repyy actions workflows codeql yml Scorecard workflow https github com Kevin Umali repyy actions workflows scorecard yml the Scorecard breakdown https scorecard dev viewer uri github com Kevin Umali repyy and artifact attestations https github com Kevin Umali repyy attestations Scorecard results may be unavailable before its first default branch run A passing check is limited evidence not certification Review high risk Scorecard checks individual",
  ],
  [
    "/verification/",
    "Releases and Verification",
    "overview",
    "Releases and Verification",
    "Releases and Verification Verify what you download. Know what it proves.",
  ],
  [
    "/security-testing/",
    "Security Testing",
    "existing-regression-coverage",
    "Existing regression coverage",
    " Unit tests cover rule matching severity context configuration and suppressions report fields and exit policy Integration tests invoke the built CLI against inert local fixtures Source tests verify URL rejection and sanitized Git configuration Docker unit tests use a fake Docker executable to test invocation and hostile JSON handling they are not live isolation escape tests CI separately builds and starts the worker image for a version smoke check internal scan security regression test go scanne",
  ],
  [
    "/security-testing/",
    "Security Testing",
    "fuzz-targets-and-properties",
    "Fuzz targets and properties",
    " Target Input surface Property bounds FuzzArchiveInspection ZIP TAR and gzip bytes No crash or unbounded diagnostics 64 KiB input 32 entries 64 KiB expansion 16 KiB file depth 2 context deadline FuzzArchivePaths Portable archive paths Accepted paths cannot normalize outside the root 4 KiB input Windows and POSIX seeds FuzzSymlinkConfinement Symbolic link targets Scanner reads no bytes through repository symlinks 4 KiB target controlled external sentinel FuzzGitMetadata git config Metadata includ",
  ],
  [
    "/security-testing/",
    "Security Testing",
    "run-and-reproduce",
    "Run and reproduce",
    " sh make check make security go test internal scan run fuzz FuzzArchiveInspection fuzztime 30s parallel 2 Use the corresponding package and target name for the remaining targets Ordinary go test runs the seed corpus The Security evidence workflow runs each target for 10 seconds on changes and 120 seconds on a daily schedule Read the workflow run rather than assuming a scheduled run happened Fuzz failures are uploaded as artifacts when available For a failure preserve the generated corpus input u",
  ],
  [
    "/security-testing/",
    "Security Testing",
    "public-benchmark",
    "Public benchmark",
    " The demo demo README md and its versioned paired controls are a separate behavioral check Per release results are attached by the release workflow Known misses and all observed rules remain public a synthetic benchmark does not establish general accuracy ",
  ],
  [
    "/security-testing/",
    "Security Testing",
    "known-gaps-and-independent-review",
    "Known gaps and independent review",
    " Short fuzz runs cannot exhaust the input space Tests using fake host tools cannot prove the behavior of every installed Git Docker version OS specific permission and symlink behavior requires platform CI Resource limits do not provide dedicated VM isolation Best effort cleanup can leave temporary data after failures The external review brief EXTERNAL REVIEW md identifies the required independent scope Until a reviewer publishes their identity exact reviewed commit findings and retest outcome th",
  ],
  [
    "/security-testing/",
    "Security Testing",
    "overview",
    "Security Testing",
    "Security Testing Test the scanner. Keep the gaps visible.",
  ],
  [
    "/about/",
    "About Repyy",
    "project-principles",
    "Project principles",
    " Read assignment contents as untrusted data Report evidence and uncertainty Keep incomplete coverage visible Keep private source and reports local during scans Prefer regression coverage and verifiable releases over expanding rule counts Repyy identifies risks It cannot prove that a repository is safe ",
  ],
  [
    "/about/",
    "About Repyy",
    "security-reporting",
    "Security reporting",
    " Please use private vulnerability reporting https github com Kevin Umali repyy security advisories new for defects in Repyy Include the version and smallest inert reproduction The project maintains a security policy SECURITY md it does not promise an invented response time SLA Ordinary feedback and false positives can use the public issue templates after checking for sensitive content Read Trust and Limitations TRUST md and Security Testing SECURITY TESTING md before relying on the scanner s res",
  ],
  [
    "/about/",
    "About Repyy",
    "overview",
    "About Repyy",
    "About Repyy Built for the review before you run.",
  ],
  [
    "/demo/",
    "Demo and Sample Report",
    "safety-design",
    "Safety design",
    " All JavaScript indicators are strings or harmless configuration The lifecycle and hook examples only print markers The IDE command names a nonexistent marker The Docker image uses a nonexistent image on a reserved invalid registry Credential references are fake path strings no file read or credential collection exists Network evaluation examples are quoted text with no callable downloader or execution chain Fixtures are created without executable permissions ",
  ],
  [
    "/demo/",
    "Demo and Sample Report",
    "reproduce",
    "Reproduce",
    " From the Repyy source checkout build Repyy itself and run its trusted benchmark runner sh go build o tmp repyy cmd repyy python3 scripts benchmark py binary tmp repyy output tmp repyy demo check The runner invokes only that binary It writes results json results md sample json sample txt and sample html Open the HTML report locally or inspect the checked in sample report site demo sample sample html without installing anything Generated timestamps identify the run scan durations and temporary ro",
  ],
  [
    "/demo/",
    "Demo and Sample Report",
    "expected-outcomes-and-controls",
    "Expected outcomes and controls",
    " Case Expected rule Paired control Lifecycle PKG 001 Ordinary test script Startup configuration IMPORT 001 Normal PostCSS configuration Disguised image EXEC 001 SVG with only image markup Folder open task IDE 001 Manual task without automatic run option Git hook GITHOOK 001 Inactive sample hook Obfuscated download CHAIN 001 Normal display string Credential reference CRED 001 Specific benign environment variable Docker socket DOCKER 001 Ordinary read only data volume Benchmark 1 0 0 detects six o",
  ],
  [
    "/demo/",
    "Demo and Sample Report",
    "benchmark-versioning",
    "Benchmark versioning",
    " Version this corpus separately from Repyy Add a paired control with every new risky case Preserve difficult cases and known misses Change expectations explicitly and explain why This is a small synthetic regression corpus not a representative malware dataset or a universal accuracy score The benchmark runner is the cross package regression check use repyy rules explain RULE ID to inspect each linked rule s evidence and guidance ",
  ],
  [
    "/demo/",
    "Demo and Sample Report",
    "overview",
    "Demo and Sample Report",
    "Demo and Sample Report Inspect a real report. No installation needed.",
  ],
];
const docsSearchInput = document.querySelector("#docs-search");
if (docsSearchInput) {
  const box = docsSearchInput.closest(".docs-search");
  const results = document.createElement("div");
  results.className = "docs-search-results";
  results.id = "docs-search-results";
  results.setAttribute("role", "region");
  results.setAttribute("aria-label", "Documentation search results");
  results.hidden = true;
  box?.appendChild(results);
  docsSearchInput.setAttribute("aria-controls", results.id);
  docsSearchInput.setAttribute("aria-expanded", "false");
  const render = () => {
    const query = docsSearchInput.value.trim().toLowerCase();
    results.replaceChildren();
    if (!query) {
      results.hidden = true;
      docsSearchInput.setAttribute("aria-expanded", "false");
      return;
    }
    const matches = docsGlobalIndex.filter((item) =>
      query.split(/\s+/).every((word) => item.slice(1).join(" ").toLowerCase().includes(word)),
    );
    if (!matches.length) {
      const message = document.createElement("p");
      message.className = "docs-search-empty";
      message.textContent = "No documentation matches that search.";
      results.appendChild(message);
    }
    matches.slice(0, 30).forEach(([page, pageTitle, id, title]) => {
      const link = document.createElement("a");
      link.href = page + "#" + id;
      const heading = document.createElement("strong");
      heading.textContent = title;
      const location = document.createElement("small");
      location.textContent = pageTitle;
      link.append(heading, location);
      results.appendChild(link);
    });
    if (matches.length) {
      const count = document.createElement("p");
      count.className = "docs-search-count";
      count.textContent =
        matches.length > 30
          ? "Showing 30 of " + matches.length + " matches"
          : matches.length + (matches.length === 1 ? " match" : " matches");
      results.appendChild(count);
    }
    results.hidden = false;
    docsSearchInput.setAttribute("aria-expanded", "true");
    const localEmpty = document.querySelector("#docs-empty");
    if (localEmpty) localEmpty.hidden = true;
  };
  docsSearchInput.addEventListener("input", render);
  docsSearchInput.addEventListener("focus", () => {
    if (docsSearchInput.value.trim()) render();
  });
  docsSearchInput.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" && !results.hidden) {
      event.preventDefault();
      results.querySelector("a")?.focus();
    }
  });
  results.addEventListener("keydown", (event) => {
    const links = [...results.querySelectorAll("a")];
    const index = links.indexOf(document.activeElement);
    if (event.key === "ArrowDown" && index >= 0) {
      event.preventDefault();
      links[Math.min(index + 1, links.length - 1)]?.focus();
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      index <= 0 ? docsSearchInput.focus() : links[index - 1]?.focus();
    }
    if (event.key === "Escape") {
      event.preventDefault();
      docsSearchInput.value = "";
      docsSearchInput.dispatchEvent(new Event("input"));
      docsSearchInput.focus();
    }
  });
  document.addEventListener("pointerdown", (event) => {
    if (!box?.contains(event.target)) {
      results.hidden = true;
      docsSearchInput.setAttribute("aria-expanded", "false");
    }
  });
}

document.querySelectorAll("[data-drag-rail]").forEach((viewport) => {
  const rail = viewport.querySelector(".situation-rail");
  const nativeScroll = window.matchMedia("(max-width: 640px)").matches || reduceMotion;
  if (nativeScroll) return;

  const spring = { mass: 1, stiffness: 100, damping: 10 };
  let position = 0;
  let target = 0;
  let velocity = 0;
  let frame;
  let lastFrame = 0;
  let pointerId;
  let pressX = 0;
  let lastX = 0;
  let dragging = false;
  let history = [];

  const lowerBound = () => Math.min(0, viewport.clientWidth - rail.scrollWidth);
  const clamp = (value) => Math.max(lowerBound(), Math.min(0, value));
  const rubberbandDistance = (overshoot) => {
    const dimension = viewport.clientWidth;
    const constant = 0.55;
    return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot));
  };
  const applyResistance = (value) => {
    const min = lowerBound();
    if (value > 0) return rubberbandDistance(value);
    if (value < min) return min + rubberbandDistance(value - min);
    return value;
  };
  const render = () => {
    rail.style.transform = `translate3d(${position}px, 0, 0)`;
  };
  const settle = (time) => {
    if (!lastFrame) lastFrame = time;
    const dt = Math.min((time - lastFrame) / 1000, 0.032);
    lastFrame = time;
    const acceleration =
      (-spring.stiffness * (position - target) - spring.damping * velocity) / spring.mass;
    velocity += acceleration * dt;
    position += velocity * dt;
    render();
    if (Math.abs(target - position) > 0.1 || Math.abs(velocity) > 0.1) {
      frame = requestAnimationFrame(settle);
    } else {
      position = target;
      velocity = 0;
      lastFrame = 0;
      render();
    }
  };
  const animateTo = (next, initialVelocity = velocity) => {
    target = clamp(next);
    velocity = initialVelocity;
    lastFrame = 0;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(settle);
  };
  const setInstantly = (next) => {
    cancelAnimationFrame(frame);
    position = clamp(next);
    target = position;
    velocity = 0;
    lastFrame = 0;
    render();
  };
  const project = (initialVelocity, decelerationRate = 0.99) =>
    ((initialVelocity / 1000) * decelerationRate) / (1 - decelerationRate);

  viewport.addEventListener("pointerdown", (event) => {
    if (pointerId !== undefined) return;
    pointerId = event.pointerId;
    pressX = event.clientX;
    lastX = event.clientX;
    dragging = false;
    history = [{ x: event.clientX, time: performance.now() }];
    cancelAnimationFrame(frame);
    viewport.setPointerCapture(pointerId);
  });

  viewport.addEventListener("pointermove", (event) => {
    if (event.pointerId !== pointerId) return;
    const deltaFromPress = event.clientX - pressX;
    if (!dragging && Math.abs(deltaFromPress) < 10) return;
    dragging = true;
    const delta = event.clientX - lastX;
    position = applyResistance(position + delta);
    lastX = event.clientX;
    const now = performance.now();
    history.push({ x: event.clientX, time: now });
    history = history.filter((sample) => now - sample.time <= 100);
    render();
  });

  const release = (event) => {
    if (event.pointerId !== pointerId) return;
    viewport.releasePointerCapture(pointerId);
    pointerId = undefined;
    if (!dragging || history.length < 2) {
      animateTo(position, 0);
      return;
    }
    const first = history[0];
    const last = history[history.length - 1];
    const releaseVelocity = ((last.x - first.x) / Math.max(last.time - first.time, 1)) * 1000;
    animateTo(position + project(releaseVelocity), releaseVelocity);
  };

  viewport.addEventListener("pointerup", release);
  viewport.addEventListener("pointercancel", release);
  viewport.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    if (event.key === "Home") setInstantly(0);
    else if (event.key === "End") setInstantly(lowerBound());
    else setInstantly(position + (event.key === "ArrowLeft" ? 320 : -320));
  });
  window.addEventListener("resize", () => setInstantly(position));
});
