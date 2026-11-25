export function mountStatus({ sections, links, where, pos }) {
  const setCurrent = (id) => {
    links.forEach((a) => (a.dataset.sectionLink === id ? a.setAttribute("aria-current", "true") : a.removeAttribute("aria-current")));
    const section = sections.find((s) => s.id === id);
    if (where && section) where.textContent = section.dataset.statusLabel ?? id;
  };
  const io = new IntersectionObserver((entries) => entries.forEach((e) => e.isIntersecting && setCurrent(e.target.id)), {
    rootMargin: "-35% 0px -60% 0px",
  });
  sections.forEach((s) => io.observe(s));

  const update = () => {
    const max = document.documentElement.scrollHeight - innerHeight;
    const p = max > 0 ? Math.round((scrollY / max) * 100) : 0;
    if (pos) pos.textContent = p <= 0 ? "top" : p >= 100 ? "bot" : `${p}%`;
  };
  addEventListener("scroll", update, { passive: true });
  update();
}

export function mountKeys(keymap) {
  const help = document.querySelector("[data-keyhelp]");
  help?.addEventListener("click", (e) => e.target === help && help.close());

  addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return;
    if (e.target instanceof Element && e.target.closest("input, textarea, select, [contenteditable]")) return;
    if (e.key === "?") {
      if (help?.open) help.close();
      else help?.showModal();
      e.preventDefault();
      return;
    }
    if (help?.open) return;
    const action = keymap[e.key];
    if (!action) return;
    e.preventDefault();
    action(e);
  });
}

export const jumpTo = (el) => {
  if (!el) return;
  el.scrollIntoView({ behavior: "instant", block: "start" });
  if (el.id) history.replaceState(null, "", `#${el.id}`);
};
