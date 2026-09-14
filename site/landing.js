// Index-only enhancement. Native scrolling owns touch, trackpad, and interruption.
(() => {
  const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
  if (!motion.matches) document.documentElement.classList.add("landing-motion");

  // Each reused preview stays associated with the currently selected tab.
  [
    ["[data-report-lab]", ".report-screen", "report-preview"],
    ["[data-install-tabs]", ".install-command", "install-preview"],
  ].forEach(([scope, content, id]) => {
    const group = document.querySelector(scope);
    if (!group) return;
    const panel = group.querySelector(content);
    const tabs = [...group.querySelectorAll('[role="tab"]')];
    panel.id = id;
    panel.setAttribute("role", "tabpanel");
    panel.tabIndex = 0;
    tabs.forEach((tab, index) => {
      tab.id = `${id}-tab-${index}`;
      tab.setAttribute("aria-controls", id);
    });
    const label = () =>
      panel.setAttribute(
        "aria-labelledby",
        tabs.find((tab) => tab.getAttribute("aria-selected") === "true").id,
      );
    new MutationObserver(label).observe(group, {
      attributes: true,
      subtree: true,
      attributeFilter: ["aria-selected"],
    });
    label();
  });

  motion.addEventListener("change", () => {
    document.documentElement.classList.toggle("landing-motion", !motion.matches);
  });
})();
