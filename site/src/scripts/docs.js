const docsSearch = document.querySelector("#docs-search");

if (docsSearch) {
  const sections = [...document.querySelectorAll(".docs-searchable")];
  const localEmpty = document.querySelector("#docs-empty");

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

  docsSearch.addEventListener("input", () => {
    const query = docsSearch.value.trim().toLowerCase();
    let visible = 0;
    sections.forEach((section) => {
      const haystack = `${section.dataset.search || ""} ${section.textContent}`.toLowerCase();
      const matches = !query || query.split(/\s+/).every((word) => haystack.includes(word));
      section.hidden = !matches;
      if (matches) visible += 1;
    });
    if (localEmpty) localEmpty.hidden = Boolean(!query || visible);
  });

  const links = [...document.querySelectorAll('.docs-sidebar a[href^="#"]')];
  const sidebarNav = document.querySelector(".docs-sidebar nav");
  sidebarNav?.addEventListener("keydown", (event) => {
    if (sidebarNav.scrollHeight <= sidebarNav.clientHeight || event.altKey || event.ctrlKey || event.metaKey) return;
    const distances = {
      ArrowUp: -40,
      ArrowDown: 40,
      PageUp: -sidebarNav.clientHeight,
      PageDown: sidebarNav.clientHeight,
      Home: -sidebarNav.scrollHeight,
      End: sidebarNav.scrollHeight,
    };
    const distance = distances[event.key];
    if (distance === undefined) return;
    event.preventDefault();
    sidebarNav.scrollBy({ top: distance, behavior: "instant" });
  });

  let currentId;
  let scrollFrame;
  const updateCurrent = () => {
    scrollFrame = undefined;
    const visibleSections = sections.filter((section) => section.getClientRects().length);
    if (!visibleSections.length) return;
    const headerBottom = document.querySelector(".docs-header").getBoundingClientRect().bottom;
    const anchorOffset = parseFloat(getComputedStyle(visibleSections[0]).scrollMarginTop) || 0;
    const readingLine = Math.max(headerBottom + 16, anchorOffset) + 1;
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
    const activeLink = sidebarNav?.querySelector('[aria-current="location"]');
    if (activeLink && sidebarNav.getClientRects().length) {
      const item = activeLink.getBoundingClientRect();
      const container = sidebarNav.getBoundingClientRect();
      if (item.top < container.top) sidebarNav.scrollTop += item.top - container.top;
      else if (item.bottom > container.bottom) sidebarNav.scrollTop += item.bottom - container.bottom;
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
