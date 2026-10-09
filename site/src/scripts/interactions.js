const motionPreference = window.matchMedia("(prefers-reduced-motion: reduce)");
document.documentElement.classList.add("has-js");

const rootStyles = getComputedStyle(document.documentElement);
const easeOut = rootStyles.getPropertyValue("--ease-out").trim() || "cubic-bezier(0.23, 1, 0.32, 1)";
const durationValue = rootStyles.getPropertyValue("--duration-ui").trim();
const uiDuration = durationValue.endsWith("ms") ? Number.parseFloat(durationValue) : 200;

const revealItems = document.querySelectorAll(".reveal");
if (motionPreference.matches) {
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
  feedback.status.classList.toggle("visually-hidden", copied);
  feedback.status.textContent = copied ? "Command copied." : "Couldn't copy. Select the command and copy it manually.";
  if (copied) {
    feedback.timeout = window.setTimeout(() => {
      feedback.label.textContent = feedback.original;
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
    tab.addEventListener("click", () => select(tab));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const nextIndex =
        event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowLeft" ? -1 : 1) + tabs.length) % tabs.length;
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
  const use = lab.querySelector("[data-report-use]");
  const description = lab.querySelector("[data-report-description]");
  const command = lab.querySelector("[data-report-command]");
  const copy = lab.querySelector("[data-report-copy]");
  const select = (tab) => {
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
  };

  attachTabs(tabs, select);
  copy.addEventListener("click", () => copyText(copy, command.textContent));
});

document.querySelectorAll(".faq-list details").forEach((details) => {
  const summary = details.querySelector("summary");
  const content = details.querySelector("p");
  let expanded = details.open;
  let heightAnimation;
  let contentAnimation;

  motionPreference.addEventListener("change", () => {
    if (!motionPreference.matches) return;
    heightAnimation?.cancel();
    contentAnimation?.cancel();
    details.open = expanded;
    details.style.height = "";
    details.style.overflow = "";
  });

  summary.addEventListener("click", (event) => {
    event.preventDefault();
    expanded = !expanded;

    if (motionPreference.matches) {
      heightAnimation?.cancel();
      contentAnimation?.cancel();
      details.open = expanded;
      details.style.height = "";
      details.style.overflow = "";
      return;
    }

    const startHeight = details.getBoundingClientRect().height;
    const interruptedContent = contentAnimation ? getComputedStyle(content) : undefined;
    heightAnimation?.cancel();
    contentAnimation?.cancel();
    details.style.height = `${startHeight}px`;
    details.style.overflow = "hidden";
    if (expanded) details.open = true;

    const endHeight = summary.getBoundingClientRect().height + (expanded ? content.getBoundingClientRect().height : 0);
    heightAnimation = details.animate([{ height: `${startHeight}px` }, { height: `${endHeight}px` }], {
      duration: uiDuration,
      easing: easeOut,
    });
    contentAnimation = content.animate(
      [
        {
          opacity: interruptedContent ? Number.parseFloat(interruptedContent.opacity) : expanded ? 0 : 1,
          transform: interruptedContent?.transform || (expanded ? "translate3d(0, -4px, 0)" : "translate3d(0, 0, 0)"),
        },
        {
          opacity: expanded ? 1 : 0,
          transform: expanded ? "translate3d(0, 0, 0)" : "translate3d(0, -4px, 0)",
        },
      ],
      { duration: uiDuration, easing: easeOut },
    );

    heightAnimation.addEventListener(
      "finish",
      () => {
        details.open = expanded;
        details.style.height = "";
        details.style.overflow = "";
        heightAnimation = undefined;
        contentAnimation = undefined;
      },
      { once: true },
    );
  });
});
