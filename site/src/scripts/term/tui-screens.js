export const COLS = 86;
export const ROWS = 21;

const PKG_002 = {
  title: "Dependency uses a non-registry source: ui-kit",
  severity: "high",
  confidence: "medium",
  at: "package.json:9",
  rule: "PKG-002",
  category: "suspicious dependency source",
  action: "Verify the dependency source and pin it to an immutable trusted revision.",
  evidence: '"ui-kit": "git+https://git.example.dev/ui-kit.git"',
};
const PKG_001 = {
  title: "Package lifecycle script: postinstall",
  severity: "medium",
  confidence: "medium",
  at: "package.json:6",
  rule: "PKG-001",
  category: "package lifecycle",
  action: "Review the script before installing dependencies.",
  evidence: '"postinstall": "node scripts/setup.js"',
};
const REPO_002 = {
  title: "Repository has no top-level license",
  severity: "low",
  confidence: "high",
  at: ".",
  rule: "REPO-002",
  category: "repository hygiene",
  action: "Clarify the code origin and permitted use.",
  evidence: "",
};

export const scenarios = {
  sample: {
    target: "./take-home",
    status: "REVIEW REQUIRED",
    files: 214,
    bytes: 1_904_311,
    elapsed: "1.82s",
    complete: true,
    findings: [PKG_002, PKG_001, REPO_002],
    skipped: [],
  },
  incomplete: {
    target: "./take-home",
    status: "SCAN INCOMPLETE",
    files: 211,
    bytes: 1_877_604,
    elapsed: "1.79s",
    complete: false,
    findings: [PKG_001],
    skipped: ["fixtures/sample.zip!vendor.zip!deps.zip (archive-depth limit)"],
  },
};

const LIMITATION = "Repyy performs static analysis. A result with no relevant findings does not prove that the repository is safe.";

const TAGS = "abmsprylgdw";
const MARKUP = new RegExp(`\\{([${TAGS}]):([^}]*)\\}`, "g");
const strip = (line) => line.replace(MARKUP, "$2");
const pad = (line, width) => line + " ".repeat(Math.max(0, width - strip(line).length));
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

const HUE = { critical: "r", high: "a", medium: "y", low: "l" };
const BADGE = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW" };
const sev = (s) => `{${HUE[s]}:${s}}`;
const badge = (s) => `{${HUE[s]}:${BADGE[s].padEnd(5)}}`;

const statusPill = (status) => (status === "SCAN INCOMPLETE" ? `{w: ${status} }` : `{p: ${status} }`);

const counts = (findings) =>
  ["critical", "high", "medium", "low"]
    .map((level) => [level, findings.filter((f) => f.severity === level).length])
    .filter(([, n]) => n > 0)
    .map(([level, n]) => `${sev(level)}{m: ${n}}`)
    .join("{m: · }");

const header = (section, { tab = 1, scenario = "sample" } = {}) => {
  const title = `{a:r/}  {b:repyy}  {d:/}  {m:${section}}`;
  if (!tab) return [title, `{d:${"─".repeat(COLS)}}`, ""];
  const s = scenarios[scenario];
  const right = `{m:${s.target}}  ${statusPill(s.status)}`;
  const tabs = ["1 Findings", "2 Repositories", "3 Coverage"].map((t, i) => (i + 1 === tab ? `{a:● ${t}}` : `{m:${t}}`)).join("  ");
  return [pad(title, COLS - strip(right).length) + right, `${tabs}  {d:${"─".repeat(COLS - strip(tabs).length - 2)}}`, ""];
};

const footer = (keys, { mode = "REVIEW", position = "" } = {}) => {
  const left = `{p: ${mode} }`;
  return [position ? pad(left, COLS - position.length) + `{m:${position}}` : left, keys.map(([k, v]) => `{b:${k}} ${v}`).join(" {m:•} ")];
};

const frame = (body, keys, opts) => {
  const rows = body.slice(0, ROWS - 2);
  while (rows.length < ROWS - 2) rows.push("");
  return [...rows, ...footer(keys, opts)];
};

const dialog = (base, title, lines, width = 68) => {
  const inner = width - 6;
  const box = [
    `{a:╭${"─".repeat(width - 2)}╮}`,
    `{a:│}${" ".repeat(width - 2)}{a:│}`,
    ...[`{a:${title}}`, "", ...lines].map((l) => `{a:│}  ${pad(l, inner)}  {a:│}`),
    `{a:│}${" ".repeat(width - 2)}{a:│}`,
    `{a:╰${"─".repeat(width - 2)}╯}`,
  ];
  const x = Math.floor((COLS - width) / 2);
  const y = Math.max(3, Math.floor((ROWS - box.length) / 2));
  return base.map((line, i) => {
    const row = i - y;
    if (row < 0 || row >= box.length) return line;
    const plain = strip(line).padEnd(COLS);
    return `{d:${plain.slice(0, x)}}${box[row]}{d:${plain.slice(x + width)}}`;
  });
};

export function prompt(typed = "", { caret = true, history = [], cwd = "~/take-home" } = {}) {
  const lines = [`{m:${cwd}} {a:❯} git clone https://github.com/acme-hiring/take-home .`, "{m:Cloning into '.'... done.}", "", ...history];
  lines.push(`{m:${cwd}} {a:❯} ${typed}${caret ? "{s: }" : ""}`);
  while (lines.length < ROWS) lines.push("");
  return lines;
}

export function progress(pct, elapsed, spin = 0) {
  const width = 40;
  const fill = Math.round((pct / 100) * width);
  const spinner = "⣾⣽⣻⢿⡿⣟⣯⣷"[spin % 8];
  return frame(
    [
      ...header("Scan", { tab: 0 }),
      "",
      `{a:${spinner}} {b:Scanning repositories}`,
      "{m:./take-home}",
      "",
      `{a:${"━".repeat(fill)}}{m:${"─".repeat(width - fill)}}`,
      "",
      `{b:${pct}%}{m:  ·  ${pct >= 100 ? 1 : 0} of 1 repositories finished}`,
      "{m:Per-repository timeout 10m0s}",
      "",
      "{m:Static analysis only: nothing in the target is installed or run.}",
    ],
    [["q", "cancel"]],
    { mode: "SCAN", position: `${elapsed.toFixed(1)}s` },
  );
}

export function review(selected = 0, { notice = "", scenario = "sample" } = {}) {
  const s = scenarios[scenario];
  const body = [...header("Review", { scenario }), counts(s.findings)];
  if (notice) body.push(`{a:${notice}}`);
  body.push(`{m:${plural(s.findings.filter((f) => f.action).length, "finding", "findings")} with a suggested fix}`, "");
  s.findings.forEach((f, i) => {
    const marker = i === selected ? "{a:▍} " : "  ";
    body.push(`${marker}${badge(f.severity)}${i === selected ? `{b:${f.title}}` : f.title}`);
    body.push(`       {m:${f.at}}{d: · ${f.rule}}`);
  });
  return frame(
    body,
    [
      ["e", "export"],
      ["enter", "detail"],
      ["/", "search"],
      ["↑↓", "move"],
      ["f", "filter"],
      ["h", "handoff"],
      ["?", "keys"],
      ["q", "quit"],
    ],
    { position: `${selected + 1} / ${s.findings.length}` },
  );
}

export function detail(selected = 0, { scenario = "sample" } = {}) {
  const list = scenarios[scenario].findings;
  const f = list[selected];
  const body = [
    ...header(`Finding ${selected + 1} of ${list.length}`, { scenario }),
    `${badge(f.severity)}{m:${f.confidence} confidence · ${f.rule}}`,
    "",
    `{b:${f.title}}`,
    `{a:${f.at}}`,
    "",
    "{d:RECOMMENDED ACTION}",
    ...wrap(f.action, COLS),
  ];
  if (f.evidence) body.push("", "{d:EVIDENCE}", `{${HUE[f.severity]}:┃} ${f.evidence}`);
  body.push("", "{d:DETECTION}", `${f.rule} · ${f.category} · review`);
  return frame(
    body,
    [
      ["e", "export"],
      ["[ ]", "prev/next"],
      ["↑↓", "scroll"],
      ["l", "locations"],
      ["y", "copy path"],
      ["esc", "back"],
      ["q", "quit"],
    ],
    { position: `${selected + 1} / ${list.length}` },
  );
}

export function handoff({ scenario = "sample" } = {}) {
  const s = scenarios[scenario];
  const body = [
    ...header("Handoff brief", { scenario }),
    `# Repyy handoff: ${s.target}`,
    "",
    `- Status: ${s.status}`,
    `- Coverage: ${s.complete ? "complete" : "partial"}, ${s.files} files scanned`,
    "",
    `## Findings (${s.findings.length})`,
    "",
    ...s.findings.flatMap((f, i) => [
      ...wrap(`${i + 1}. **${f.severity}** \`${f.rule}\` ${f.title} at \`${f.at}\` (${f.confidence} confidence)`, COLS),
      ...(f.action ? wrap(f.action, COLS - 9).map((l, j) => (j ? "         " : "   Next: ") + l) : []),
    ]),
  ];
  return frame(body, [
    ["e", "export"],
    ["y", "copy brief"],
    ["↑↓", "scroll"],
    ["esc", "back"],
    ["q", "quit"],
  ]);
}

export function coverage({ scenario = "sample" } = {}) {
  const s = scenarios[scenario];
  const state = s.complete ? "{g:● complete coverage}" : "{y:◐ partial coverage}";
  const body = [
    ...header("Coverage", { tab: 3, scenario }),
    `{b:${s.target}}`,
    statusPill(s.status),
    "",
    `${state}{m: · ${s.files} files · ${(s.bytes / 1048576).toFixed(1)} MB · ${s.elapsed} · host scan}`,
  ];
  if (s.skipped.length) body.push("", "{d:SKIPPED AREAS}", ...s.skipped.map((x) => `• ${x}`));
  body.push("", ...wrap(LIMITATION, COLS - 4).map((l) => `{m:${l}}`));
  return frame(body, [
    ["e", "export"],
    ["↑↓", "scroll"],
    ["esc", "back"],
    ["q", "quit"],
  ]);
}

export function exportFormat(selected = 0) {
  const options = ["HTML   ·  Read and share", "JSON   ·  Agent handoff", "SARIF  ·  Code scanning"];
  const base = review(0);
  const lines = ["{b:Report format}", "{m:Exports include all findings.}", ...options.map((o, i) => (i === selected ? `{a:› ${o}}` : `  ${o}`))];
  return [
    ...dialog(base.slice(0, ROWS - 2), "Export report", lines),
    ...footer(
      [
        ["↑↓", "choose"],
        ["enter", "continue"],
        ["esc", "cancel"],
      ],
      { mode: "EXPORT" },
    ),
  ];
}

export function exportPath(value, { caret = true, format = "HTML" } = {}) {
  const base = review(0);
  const lines = [`{b:Save ${format} report}`, "{m:Choose a new file. Existing files stay untouched.}", `{a:>} ${value}${caret ? "{s: }" : ""}`];
  return [
    ...dialog(base.slice(0, ROWS - 2), "Export report", lines),
    ...footer(
      [
        ["enter", "save"],
        ["esc", "cancel"],
      ],
      { mode: "EXPORT" },
    ),
  ];
}

function wrap(text, width) {
  const out = [""];
  for (const word of text.split(" ")) {
    const line = out[out.length - 1];
    if (line && line.length + word.length + 1 > width) out.push(word);
    else out[out.length - 1] = line ? `${line} ${word}` : word;
  }
  return out;
}

const escape = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function toHTML(lines) {
  return lines.map((line) => escape(line).replace(MARKUP, (_, k, t) => `<span class="t-${k}">${t}</span>`)).join("\n");
}
