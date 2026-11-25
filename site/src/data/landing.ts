export const installs = [
  { id: "brew", command: "brew install --cask Kevin-Umali/tap/repyy" },
  { id: "scoop", command: "scoop bucket add repyy https://github.com/Kevin-Umali/scoop-bucket; scoop install repyy/repyy" },
  { id: "go", command: "go install github.com/Kevin-Umali/repyy/cmd/repyy@latest" },
];

export const tree = [
  { path: "├── package.json", note: "lifecycle scripts, registries", finding: "postinstall runs scripts/setup.js", hitByDefault: true },
  { path: "├── .github/workflows/ci.yml", note: "automation", finding: "untrusted checkout in pull_request_target", hitByDefault: false },
  { path: "├── .vscode/tasks.json", note: "editor tasks", finding: "task runs a shell command on folder open", hitByDefault: false },
  { path: "├── .git/hooks/pre-commit", note: "git hooks", finding: "hook downloads and runs a script", hitByDefault: false },
  { path: "├── AGENTS.md", note: "agent instructions", finding: "tells the agent to skip review", hitByDefault: false },
  { path: "├── Dockerfile", note: "containers", finding: "mounts the Docker socket", hitByDefault: false },
  { path: "├── .env.example", note: "credentials, redacted", finding: "live-looking token, redacted", hitByDefault: false },
  { path: "├── fixtures/sample.zip", note: "archives, 3 levels deep", finding: "executable 3 archives deep", hitByDefault: false },
  { path: "└── src/setup.js", note: "encoded payloads", finding: "base64 decoded into eval", hitByDefault: true },
] as const;

export const formats = [
  {
    id: "terminal",
    use: "read it now",
    command: "repyy scan ./take-home --format terminal",
    preview: `{a:REVIEW REQUIRED}
2 findings need context

{a:HIGH}  PKG-002   package.json:9
{b:MED}   OBFS-003  src/setup.js:48`,
  },
  {
    id: "json",
    use: "hand to an agent",
    command: "repyy scan ./take-home --format json",
    preview: `{
  "verdict": "REVIEW REQUIRED",
  "coverage": { "complete": true },
  "findings": [
    { "rule_id": "PKG-002", "severity": "high", "confidence": "medium" }
  ]
}`,
  },
  {
    id: "sarif",
    use: "code scanning",
    command: "repyy scan ./take-home --format sarif",
    preview: `{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "repyy" } },
    "results": [{ "ruleId": "PKG-002", "level": "error" }]
  }]
}`,
  },
  {
    id: "html",
    use: "offline report",
    command: "repyy scan ./take-home --format html --output report.html",
    preview: `{m:report.html · self-contained, no network}

Review queue        2
Informational       4
Coverage            complete
Evidence            redacted`,
  },
];

export const limits = [
  ["--timeout", "10m", "per repository"],
  ["--max-files", "100000", "per repository"],
  ["--max-file-size", "50MiB", "per file"],
  ["archive depth", "3", "nested archives"],
];

export const evidence = [
  ["x", "signed releases", "Signatures, SBOMs and build provenance.", "/verification/"],
  ["x", "tested scanner", "CodeQL, regression tests, bounded fuzzing.", "/security-testing/"],
  ["x", "reproducible demo", "Inert fixtures, paired controls, visible misses.", "/demo/"],
  [" ", "independent review", "Pending. A scope is prepared; no audit is claimed.", ""],
];

export const faq = [
  [
    "does “no findings” mean the repository is safe?",
    "No. It means the completed scan matched no enabled rule. Static analysis can miss malicious behavior and can flag harmless code.",
  ],
  ["can I scan private repositories?", "Yes. HTTPS clones can use supported provider tokens. SSH remotes use your existing SSH agent."],
  ["can a repository weaken its own scan?", "No. A repository's own .repyy.yaml is ignored. Pass a config you trust with --config."],
];

export const matrix = [
  `              <span class="t-m">confidence →</span>`,
  `              low    med    high`,
  `<span class="t-m">severity</span> high │  ·      <span class="t-a">●</span>      ·`,
  `         med  │  ·      <b>●</b>      ·`,
  `         low  │  ·      ·      <b>●</b>`,
  `              └─────────────────────`,
].join("\n");
