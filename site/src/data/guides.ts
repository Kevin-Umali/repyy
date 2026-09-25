export interface GuideSection {
  id: string;
  label: string;
}

export interface Guide {
  slug: string;
  route: `/${string}/`;
  label: string;
  title: string;
  description: string;
  markdown: string[];
  sections: GuideSection[];
}

export const guides = [
  {
    slug: "docs",
    route: "/docs/",
    label: "Documentation",
    title: "repyy documentation",
    description: "Start here for repyy installation, reports, isolation, and detailed guides.",
    markdown: ["README.md"],
    sections: [
      {
        id: "overview",
        label: "Start with a scan",
      },
      {
        id: "choose-your-path",
        label: "Choose your path",
      },
      {
        id: "getting-started",
        label: "Run your first scan",
      },
      {
        id: "recipes",
        label: "Copyable starting points",
      },
      {
        id: "verdicts-docs",
        label: "Read the result",
      },
      {
        id: "reports-docs",
        label: "Choose a report",
      },
      {
        id: "privacy",
        label: "Know the boundary",
      },
      {
        id: "intelligence",
        label: "What “intel” means",
      },
      {
        id: "agent-skill-docs",
        label: "Give your coding agent a safe first step",
      },
      {
        id: "limits-docs",
        label: "When coverage is incomplete",
      },
    ],
  },
  {
    slug: "installation",
    route: "/installation/",
    label: "Installation",
    title: "repyy installation",
    description: "Install repyy, verify the binary, and run a first repository scan.",
    markdown: ["docs/INSTALLATION.md"],
    sections: [
      {
        id: "overview",
        label: "Start with a first scan",
      },
      {
        id: "prerequisites",
        label: "Prerequisites",
      },
      {
        id: "macos-linux",
        label: "Install on macOS and Linux",
      },
      {
        id: "windows",
        label: "Install on Windows PowerShell",
      },
      {
        id: "checksums",
        label: "Verify the release",
      },
      {
        id: "first-scan",
        label: "Run a first local scan",
      },
      {
        id: "remote",
        label: "Scan a remote repository",
      },
      {
        id: "troubleshooting",
        label: "Troubleshoot the first run",
      },
    ],
  },
  {
    slug: "cli",
    route: "/cli/",
    label: "CLI reference",
    title: "repyy CLI reference",
    description: "Practical repyy command-line reference: scans, reports, rules, intelligence, flags, and exit codes.",
    markdown: ["docs/CLI.md"],
    sections: [
      {
        id: "overview",
        label: "Every command, one next move",
      },
      {
        id: "shape",
        label: "Command shape",
      },
      {
        id: "first-scan",
        label: "Run a first scan",
      },
      {
        id: "targets",
        label: "Targets and target files",
      },
      {
        id: "scan-flags",
        label: "All scan flags",
      },
      {
        id: "recipes",
        label: "Copyable scan recipes",
      },
      {
        id: "reports",
        label: "Choose a report format",
      },
      {
        id: "report-command",
        label: "Render a saved JSON report",
      },
      {
        id: "rules",
        label: "Rules commands",
      },
      {
        id: "intel",
        label: "Intelligence commands",
      },
      {
        id: "exit-codes",
        label: "Exit codes and verdicts",
      },
      {
        id: "troubleshooting",
        label: "Troubleshooting",
      },
    ],
  },
  {
    slug: "configuration",
    route: "/configuration/",
    label: "Configuration",
    title: "repyy trusted configuration",
    description: "Configure reviewed custom rules and narrow finding suppressions for repyy.",
    markdown: ["docs/CONFIGURATION.md"],
    sections: [
      {
        id: "overview",
        label: "Make policy explicit",
      },
      {
        id: "boundary",
        label: "Understand the trust boundary",
      },
      {
        id: "minimal",
        label: "Start with valid YAML",
      },
      {
        id: "workflow",
        label: "Use the safe workflow",
      },
      {
        id: "rule-fields",
        label: "Custom rule fields",
      },
      {
        id: "rule-walkthrough",
        label: "Walk through a custom rule",
      },
      {
        id: "scope",
        label: "Choose the matching scope",
      },
      {
        id: "suppressions",
        label: "Suppress one reviewed finding",
      },
      {
        id: "review-example",
        label: "Review example: from finding to exception",
      },
      {
        id: "limits",
        label: "Limits and validation errors",
      },
    ],
  },
  {
    slug: "isolation",
    route: "/isolation/",
    label: "Isolation",
    title: "repyy isolation",
    description: "Run repyy with Docker, Windows Sandbox, UTM, or QEMU isolation.",
    markdown: ["docs/SANDBOX.md", "docs/VM-GUIDES.md"],
    sections: [
      {
        id: "overview",
        label: "Give the scan its own boundary",
      },
      {
        id: "docker",
        label: "Docker: use the signed release image",
      },
      {
        id: "docker-image",
        label: "Verify the image signature",
      },
      {
        id: "local",
        label: "Docker with a local folder",
      },
      {
        id: "https",
        label: "Docker with an HTTPS remote",
      },
      {
        id: "edge-cases",
        label: "Know the edge cases",
      },
      {
        id: "vm",
        label: "Manual VM workflows",
      },
      {
        id: "windows-sandbox",
        label: "Windows Sandbox",
      },
      {
        id: "utm",
        label: "macOS with UTM",
      },
      {
        id: "qemu",
        label: "Linux with QEMU/KVM",
      },
    ],
  },
  {
    slug: "coverage",
    route: "/coverage/",
    label: "Detection coverage",
    title: "Detection coverage · repyy documentation",
    description: "Detailed detection coverage, precision controls, exclusions, and rule reference for repyy.",
    markdown: ["docs/COVERAGE.md"],
    sections: [
      {
        id: "overview",
        label: "Know what the scan can see",
      },
      {
        id: "map",
        label: "Coverage map",
      },
      {
        id: "supply-chain",
        label: "Supply-chain files by ecosystem",
      },
      {
        id: "precision",
        label: "How repyy improves precision",
      },
      {
        id: "limits",
        label: "Coverage has a boundary",
      },
      {
        id: "exclusions",
        label: "Deliberate exclusions",
      },
      {
        id: "explain",
        label: "Explain a rule before acting",
      },
      {
        id: "list",
        label: "Inspect the active intelligence",
      },
      {
        id: "workflow",
        label: "A practical review workflow",
      },
    ],
  },
  {
    slug: "intelligence",
    route: "/intelligence/",
    label: "Intelligence",
    title: "repyy intelligence guide",
    description: "Understand repyy intelligence snapshots, verification, updates, rollback, and rule commands.",
    markdown: [],
    sections: [
      {
        id: "overview",
        label: "Fresh signals, private by default",
      },
      {
        id: "difference",
        label: "Rules and intelligence work together",
      },
      {
        id: "status",
        label: "Check before you scan",
      },
      {
        id: "update",
        label: "Update only when you choose to",
      },
      {
        id: "rollback",
        label: "Roll back a cached update",
      },
      {
        id: "investigate",
        label: "Investigate an indicator",
      },
    ],
  },
  {
    slug: "agent-skill",
    route: "/agent-skill/",
    label: "Agent skill",
    title: "repyy agent skill guide",
    description: "Install and use the optional repyy agent skill before opening unfamiliar repositories.",
    markdown: ["skills/repyy/SKILL.md"],
    sections: [
      {
        id: "overview",
        label: "Make the first move before code runs",
      },
      {
        id: "install",
        label: "Install the skill",
      },
      {
        id: "workflow",
        label: "What the skill tells an agent to do",
      },
      {
        id: "docker",
        label: "Use Docker when you need a process boundary",
      },
      {
        id: "limits",
        label: "Understand the limits",
      },
    ],
  },
  {
    slug: "trust",
    route: "/trust/",
    label: "Trust and Limitations",
    title: "Trust and Limitations · repyy documentation",
    description: "Trust and Limitations: Repyy reviews take-home assignments before execution, with evidence and visible limitations.",
    markdown: ["docs/TRUST.md"],
    sections: [
      {
        id: "overview",
        label: "Understand the boundary",
      },
      {
        id: "security-model",
        label: "Security model",
      },
      {
        id: "what-repyy-reads",
        label: "What Repyy reads",
      },
      {
        id: "what-repyy-does-not-execute",
        label: "What Repyy does not execute",
      },
      {
        id: "network-behavior",
        label: "Network behavior",
      },
      {
        id: "local-data-handling",
        label: "Local data handling",
      },
      {
        id: "temporary-repositories-and-cleanup",
        label: "Temporary repositories and cleanup",
      },
      {
        id: "host-mode-boundaries",
        label: "Host-mode boundaries",
      },
      {
        id: "docker-mode-boundaries",
        label: "Docker-mode boundaries",
      },
      {
        id: "incomplete-scans-and-exit-codes",
        label: "Incomplete scans and exit codes",
      },
      {
        id: "static-analysis-limitations",
        label: "Static-analysis limitations",
      },
      {
        id: "claim-to-evidence-map",
        label: "Claim-to-evidence map",
      },
      {
        id: "releases-security-testing-and-reviews",
        label: "Releases, security testing and reviews",
      },
    ],
  },
  {
    slug: "demo",
    route: "/demo/",
    label: "Demo and Sample Report",
    title: "Demo and Sample Report · repyy documentation",
    description: "Demo and Sample Report: Repyy reviews take-home assignments before execution, with evidence and visible limitations.",
    markdown: ["demo/README.md"],
    sections: [
      {
        id: "overview",
        label: "Inspect a real report",
      },
      {
        id: "safety-design",
        label: "Safety design",
      },
      {
        id: "reproduce",
        label: "Reproduce",
      },
      {
        id: "expected-outcomes-and-controls",
        label: "Expected outcomes and controls",
      },
      {
        id: "benchmark-versioning",
        label: "Benchmark versioning",
      },
      {
        id: "changes-from-benchmark-1-0-0",
        label: "Changes from benchmark 1.0.0",
      },
    ],
  },
  {
    slug: "verification",
    route: "/verification/",
    label: "Releases and Verification",
    title: "Releases and Verification · repyy documentation",
    description: "Releases and Verification: Repyy reviews take-home assignments before execution, with evidence and visible limitations.",
    markdown: ["docs/VERIFICATION.md"],
    sections: [
      {
        id: "overview",
        label: "Verify what you download",
      },
      {
        id: "current-evidence-status",
        label: "Verified v0.5.3 release",
      },
      {
        id: "version-and-commit-identity",
        label: "Version and commit identity",
      },
      {
        id: "verify-provenance",
        label: "Verify provenance",
      },
      {
        id: "checksums-and-existing-signatures",
        label: "Checksums and existing signatures",
      },
      {
        id: "sbom-access-and-scope",
        label: "SBOM access and scope",
      },
      {
        id: "container-verification",
        label: "Container verification",
      },
      {
        id: "fresh-download-release-gate",
        label: "Fresh-download release gate",
      },
      {
        id: "repository-security-signals",
        label: "Repository security signals",
      },
    ],
  },
  {
    slug: "security-testing",
    route: "/security-testing/",
    label: "Security Testing",
    title: "Security Testing · repyy documentation",
    description: "Security Testing: Repyy reviews take-home assignments before execution, with evidence and visible limitations.",
    markdown: ["docs/SECURITY-TESTING.md"],
    sections: [
      {
        id: "overview",
        label: "Test the scanner",
      },
      {
        id: "existing-regression-coverage",
        label: "Behavioral test coverage",
      },
      {
        id: "fuzz-targets-and-properties",
        label: "Fuzz targets and properties",
      },
      {
        id: "run-and-reproduce",
        label: "Run and reproduce",
      },
      {
        id: "public-benchmark",
        label: "Public benchmark",
      },
      {
        id: "known-gaps-and-independent-review",
        label: "Known gaps and independent review",
      },
    ],
  },
  {
    slug: "about",
    route: "/about/",
    label: "About Repyy",
    title: "About Repyy · repyy documentation",
    description: "About Repyy: Repyy reviews take-home assignments before execution, with evidence and visible limitations.",
    markdown: ["docs/ABOUT.md"],
    sections: [
      {
        id: "overview",
        label: "Built for the reviewbefore you run.",
      },
      {
        id: "project-principles",
        label: "Project principles",
      },
      {
        id: "security-reporting",
        label: "Security reporting",
      },
    ],
  },
] as const satisfies readonly Guide[];

export function getGuide(slug: string): Guide {
  const guide = guides.find((item) => item.slug === slug);
  if (!guide) throw new Error(`Unknown guide: ${slug}`);
  return guide;
}
