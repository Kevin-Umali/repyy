const input = document.querySelector("#docs-search");

if (input) {
  const box = input.closest(".docs-search");
  const results = document.createElement("div");
  results.className = "docs-search-results";
  results.id = "docs-search-results";
  results.setAttribute("role", "region");
  results.setAttribute("aria-label", "Documentation search results");
  results.hidden = true;
  box?.appendChild(results);
  input.setAttribute("aria-controls", results.id);
  input.setAttribute("aria-expanded", "false");
  let index = [];

  const loadIndex = async () => {
    if (index.length) return index;
    const response = await fetch("/search-index.json");
    if (!response.ok) throw new Error(`Search index returned ${response.status}`);
    index = await response.json();
    return index;
  };

  const render = async () => {
    const query = input.value.trim().toLowerCase();
    results.replaceChildren();
    if (!query) {
      results.hidden = true;
      input.setAttribute("aria-expanded", "false");
      return;
    }
    try {
      const entries = await loadIndex();
      if (input.value.trim().toLowerCase() !== query) return;
      const matches = entries.filter((item) => query.split(/\s+/).every((word) => `${item.pageTitle} ${item.title} ${item.text}`.toLowerCase().includes(word)));
      if (!matches.length) {
        const message = document.createElement("p");
        message.className = "docs-search-empty";
        message.textContent = "No documentation matches that search.";
        results.appendChild(message);
      }
      matches.slice(0, 30).forEach((item) => {
        const link = document.createElement("a");
        link.href = `${item.route}#${item.id}`;
        const heading = document.createElement("strong");
        heading.textContent = item.title;
        const location = document.createElement("small");
        location.textContent = item.pageTitle;
        link.append(heading, location);
        results.appendChild(link);
      });
      const count = document.createElement("p");
      count.className = "docs-search-count";
      count.textContent = matches.length > 30 ? `Showing 30 of ${matches.length} matches` : `${matches.length} ${matches.length === 1 ? "match" : "matches"}`;
      results.appendChild(count);
    } catch {
      const message = document.createElement("p");
      message.className = "docs-search-empty";
      message.textContent = "Search is temporarily unavailable. Browse the guides instead.";
      results.appendChild(message);
    }
    results.hidden = false;
    input.setAttribute("aria-expanded", "true");
  };

  input.addEventListener("input", render);
  input.addEventListener("focus", () => input.value.trim() && render());
  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" && !results.hidden) {
      event.preventDefault();
      results.querySelector("a")?.focus();
    }
  });
  results.addEventListener("keydown", (event) => {
    const links = [...results.querySelectorAll("a")];
    const position = links.indexOf(document.activeElement);
    if (event.key === "ArrowDown" && position >= 0) {
      event.preventDefault();
      links[Math.min(position + 1, links.length - 1)]?.focus();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      position <= 0 ? input.focus() : links[position - 1]?.focus();
    } else if (event.key === "Escape") {
      event.preventDefault();
      input.value = "";
      input.dispatchEvent(new Event("input"));
      input.focus();
    }
  });
  document.addEventListener("pointerdown", (event) => {
    if (!box?.contains(event.target)) {
      results.hidden = true;
      input.setAttribute("aria-expanded", "false");
    }
  });
}
