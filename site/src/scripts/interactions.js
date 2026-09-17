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
        event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowLeft" ? -1 : 1) + tabs.length) % tabs.length;
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
