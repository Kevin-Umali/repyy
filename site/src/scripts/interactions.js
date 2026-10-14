import { terminalPreview } from "./terminal-preview.js";
import { motionPreference, motionToken, motionDuration, revealUpdate } from "./motion.js";

const easeOut = motionToken("--ease-smooth-out");
const uiDuration = motionDuration("--duration-fast");

const copyFeedback = new WeakMap();
document.querySelectorAll("[data-copy], [data-install-copy], [data-report-copy]").forEach((button, index) => {
  const status = document.createElement("p");
  status.id = `copy-status-${index}`;
  status.className = "copy-feedback visually-hidden";
  status.setAttribute("role", "status");
  status.setAttribute("aria-atomic", "true");
  const container = button.closest(".docs-command, .recipe-grid article, .report-screen, .install-panel") || button.parentElement;
  const reportBar = container.querySelector(".report-screen-bar");
  if (reportBar) reportBar.after(status);
  else container.appendChild(status);
  button.setAttribute("aria-describedby", status.id);
  const label = button.querySelector("[data-copy-label]") || button;
  copyFeedback.set(button, { label, original: label.textContent, status, timeout: undefined });
});

const showCopyResult = (button, copied) => {
  const feedback = copyFeedback.get(button);
  window.clearTimeout(feedback.timeout);
  feedback.label.textContent = copied ? "Copied" : feedback.original;
  button.dataset.copied = String(copied);
  revealUpdate(feedback.label);
  feedback.status.classList.toggle("visually-hidden", copied);
  feedback.status.textContent = copied ? "Command copied." : "Couldn't copy. Select the command and copy it manually.";
  if (copied) {
    feedback.timeout = window.setTimeout(() => {
      feedback.label.textContent = feedback.original;
      button.dataset.copied = "false";
      feedback.timeout = undefined;
    }, 1600);
  }
};

const copyText = async (button, value) => {
  copyFeedback.get(button).status.textContent = "";
  try {
    await navigator.clipboard.writeText(value);
    showCopyResult(button, true);
  } catch {
    const fallback = document.createElement("textarea");
    fallback.value = value;
    fallback.setAttribute("readonly", "");
    fallback.style.position = "fixed";
    fallback.style.opacity = "0";
    let copied = false;
    try {
      document.body.appendChild(fallback);
      fallback.select();
      copied = document.execCommand("copy");
    } catch {
      copied = false;
    } finally {
      fallback.remove();
      button.focus({ preventScroll: true });
    }
    showCopyResult(button, copied);
  }
};

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", () => copyText(button, button.dataset.copy));
});

const attachTabs = (tabs, select) => {
  tabs.forEach((tab, index) => {
    tab.tabIndex = tab.classList.contains("is-active") ? 0 : -1;
    tab.addEventListener("click", (event) => select(tab, event.detail > 0));
    tab.addEventListener("keydown", (event) => {
      const vertical = tab.closest('[role="tablist"]')?.getAttribute("aria-orientation") === "vertical";
      const previous = vertical ? "ArrowUp" : "ArrowLeft";
      const next = vertical ? "ArrowDown" : "ArrowRight";
      if (![previous, next, "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const nextIndex =
        event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === previous ? -1 : 1) + tabs.length) % tabs.length;
      tabs[nextIndex].focus();
      select(tabs[nextIndex]);
    });
  });
};

document.querySelectorAll("[data-install-tabs]").forEach((panel) => {
  const tabs = [...panel.querySelectorAll("[data-install-command]")];
  const output = panel.querySelector("[data-install-output]");
  const copy = panel.querySelector("[data-install-copy]");

  const select = (tab) => {
    if (tab.getAttribute("aria-selected") === "true") return;
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-selected", String(active));
      item.tabIndex = active ? 0 : -1;
    });
    output.textContent = tab.dataset.installCommand;
    revealUpdate(output);
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
    preview: "$ repyy scan ./assignment\n\nREVIEW REQUIRED\n2 findings need context\n\nHIGH  PKG-001   package.json:12\nMED   OBFS-003   src/setup.js:48",
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
  const title = lab.querySelector("[data-report-title]");
  const preview = lab.querySelector("[data-report-preview]");
  const updatePreview = terminalPreview(preview);
  const use = lab.querySelector("[data-report-use]");
  const description = lab.querySelector("[data-report-description]");
  const command = lab.querySelector("[data-report-command]");
  const copy = lab.querySelector("[data-report-copy]");
  const select = (tab, animate = false) => {
    if (tab.getAttribute("aria-selected") === "true") return;
    const format = reportFormats[tab.dataset.reportFormat];
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-selected", String(active));
      item.tabIndex = active ? 0 : -1;
    });
    title.textContent = format.title;
    use.textContent = format.use;
    updatePreview(format.preview, { isTerminal: tab.dataset.reportFormat === "terminal", animate });
    description.textContent = format.description;
    command.textContent = format.command;
    if (animate) revealUpdate(description);
  };

  attachTabs(tabs, select);
  copy.addEventListener("click", () => copyText(copy, command.textContent));
});

document.querySelectorAll(".faq-list details").forEach((details) => {
  const summary = details.querySelector("summary");
  const content = details.querySelector("p");
  let animation;
  motionPreference.addEventListener("change", () => {
    if (motionPreference.matches) animation?.cancel();
  });
  summary.addEventListener("click", (event) => {
    event.preventDefault();
    animation?.cancel();
    details.open = !details.open;
    details.dataset.expanded = String(details.open);
    if (!details.open || motionPreference.matches || event.detail === 0) return;
    animation = content.animate(
      [
        { opacity: 0, transform: "translateY(-4px)" },
        { opacity: 1, transform: "translateY(0)" },
      ],
      { duration: uiDuration, easing: easeOut },
    );
  });
});
