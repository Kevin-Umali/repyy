const docsSearch = document.querySelector("#docs-search");

if (docsSearch) {
  document.addEventListener("keydown", (event) => {
    const target = event.target;
    const editing = target instanceof HTMLElement && (target.closest("input, textarea, select") || target.isContentEditable);
    if (event.key === "/" && !editing && !event.altKey && !event.ctrlKey && !event.metaKey) {
      event.preventDefault();
      docsSearch.focus();
    }
  });

  const links = [...document.querySelectorAll('.docs-toc-links a[href^="#"]')];
  const sections = [...new Set(links.map((link) => document.getElementById(link.hash.slice(1))).filter(Boolean))];
  const tocNav = document.querySelector(".docs-toc nav");
  const sectionMenu = document.querySelector(".docs-section-menu");
  sectionMenu?.addEventListener("click", (event) => {
    if (event.target instanceof Element && event.target.closest("a")) sectionMenu.removeAttribute("open");
  });

  for (const nav of document.querySelectorAll(".docs-sidebar nav, .docs-toc nav")) {
    nav.addEventListener("keydown", (event) => {
      if (nav.scrollHeight <= nav.clientHeight || event.altKey || event.ctrlKey || event.metaKey) return;
      const distances = {
        ArrowUp: -40,
        ArrowDown: 40,
        PageUp: -nav.clientHeight,
        PageDown: nav.clientHeight,
        Home: -nav.scrollHeight,
        End: nav.scrollHeight,
      };
      const distance = distances[event.key];
      if (distance === undefined) return;
      event.preventDefault();
      nav.scrollBy({ top: distance, behavior: "instant" });
    });
  }

  let currentId;
  let scrollFrame;
  const updateCurrent = () => {
    scrollFrame = undefined;
    const visibleSections = sections.filter((section) => section.getClientRects().length);
    if (!visibleSections.length) return;
    const readingLine = parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) + 1;
    let current = visibleSections[0];
    for (const section of visibleSections) {
      if (section.getBoundingClientRect().top > readingLine) break;
      current = section;
    }
    if (scrollY > 0 && Math.ceil(scrollY + innerHeight) >= document.documentElement.scrollHeight) current = visibleSections.at(-1);
    if (!current || current.id === currentId) return;
    currentId = current.id;
    links.forEach((link) => {
      const active = link.hash.slice(1) === currentId;
      link.classList.toggle("is-current", active);
      if (active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
    const activeLink = tocNav?.querySelector('[aria-current="location"]');
    if (activeLink && tocNav.getClientRects().length) {
      const item = activeLink.getBoundingClientRect();
      const container = tocNav.getBoundingClientRect();
      if (item.top < container.top) tocNav.scrollTop += item.top - container.top;
      else if (item.bottom > container.bottom) tocNav.scrollTop += item.bottom - container.bottom;
    }
  };
  const scheduleCurrent = () => {
    if (scrollFrame === undefined) scrollFrame = requestAnimationFrame(updateCurrent);
  };
  window.addEventListener("scroll", scheduleCurrent, { passive: true });
  window.addEventListener("resize", scheduleCurrent);
  window.addEventListener("hashchange", scheduleCurrent);
  window.addEventListener("pageshow", scheduleCurrent);
  new ResizeObserver(scheduleCurrent).observe(document.querySelector(".docs-main"));
  updateCurrent();
}
