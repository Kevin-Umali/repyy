import { animate, motionPreference, motionToken } from "./motion.js";

const input = document.querySelector("#docs-search");

if (input) {
  document.documentElement.classList.add("has-js");
  const status = document.querySelector("#docs-search-status");
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
  let indexPromise;
  let loadingTimer;
  let revision = 0;
  let surfaceAnimation;

  const showResults = () => {
    const opening = results.hidden || results.inert;
    surfaceAnimation?.cancel();
    results.hidden = false;
    results.inert = false;
    input.setAttribute("aria-expanded", "true");
    if (opening) {
      surfaceAnimation = animate(results, [
        { opacity: 0, transform: `scale(${motionToken("--scale-dropdown-open")})` },
        { opacity: 1, transform: "scale(1)" },
      ]);
    }
  };
  const hideResults = () => {
    revision++;
    clearTimeout(loadingTimer);
    surfaceAnimation?.cancel();
    input.setAttribute("aria-expanded", "false");
    results.inert = true;
    if (results.hidden) return;
    surfaceAnimation = animate(
      results,
      [
        { opacity: 1, transform: "scale(1)" },
        { opacity: 0, transform: `scale(${motionToken("--scale-dropdown-close")})` },
      ],
      "--duration-quick",
    );
    if (!surfaceAnimation) results.hidden = true;
    else surfaceAnimation.addEventListener("finish", () => (results.hidden = true), { once: true });
  };
  motionPreference.addEventListener("change", () => {
    if (motionPreference.matches && results.inert) results.hidden = true;
  });

  const loadIndex = async () => {
    if (index.length) return index;
    if (!indexPromise) {
      indexPromise = fetch("/search-index.json")
        .then((response) => {
          if (!response.ok) throw new Error(`Search index returned ${response.status}`);
          return response.json();
        })
        .then((entries) => {
          index = entries;
          return index;
        })
        .catch((error) => {
          indexPromise = undefined;
          throw error;
        });
    }
    return indexPromise;
  };

  const render = async () => {
    const query = input.value.trim().toLowerCase();
    const current = ++revision;
    window.clearTimeout(loadingTimer);
    status.textContent = "";
    if (!query) {
      hideResults();
      return;
    }
    loadingTimer = window.setTimeout(() => {
      if (current !== revision || index.length) return;
      const message = document.createElement("p");
      message.className = "docs-search-loading";
      message.textContent = "Searching documentation…";
      status.textContent = message.textContent;
      results.replaceChildren(message);
      showResults();
    }, 150);
    try {
      const entries = await loadIndex();
      window.clearTimeout(loadingTimer);
      if (current !== revision) return;
      results.replaceChildren();
      const matches = entries.filter((item) => query.split(/\s+/).every((word) => `${item.pageTitle} ${item.title} ${item.text}`.toLowerCase().includes(word)));
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
      count.className = matches.length ? "docs-search-count" : "docs-search-empty";
      count.textContent = !matches.length
        ? "No documentation matches that search. Try a command, guide name, or concept such as Docker."
        : matches.length > 30
          ? `Showing 30 of ${matches.length} matches`
          : `${matches.length} ${matches.length === 1 ? "match" : "matches"}`;
      results.appendChild(count);
      status.textContent = count.textContent;
    } catch {
      window.clearTimeout(loadingTimer);
      if (current !== revision) return;
      results.replaceChildren();
      const message = document.createElement("p");
      message.className = "docs-search-empty";
      message.textContent = "Search is temporarily unavailable. Browse the guides instead.";
      results.appendChild(message);
      status.textContent = message.textContent;
    }
    showResults();
  };

  const dismiss = (event) => {
    event.preventDefault();
    input.value = "";
    input.dispatchEvent(new Event("input"));
    input.focus();
  };

  input.addEventListener("input", render);
  input.addEventListener("focus", () => input.value.trim() && render());
  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" && !results.hidden) {
      event.preventDefault();
      results.querySelector("a")?.focus();
    } else if (event.key === "Escape") {
      dismiss(event);
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
      dismiss(event);
    }
  });
  results.addEventListener("click", (event) => {
    if (!(event.target instanceof Element) || !event.target.closest("a")) return;
    input.value = "";
    input.dispatchEvent(new Event("input"));
  });
  document.addEventListener("pointerdown", (event) => {
    if (!box?.contains(event.target)) {
      hideResults();
    }
  });
  box.addEventListener("focusout", (event) => {
    if (!box.contains(event.relatedTarget)) hideResults();
  });
  window.addEventListener("pagehide", () => {
    revision++;
    clearTimeout(loadingTimer);
    surfaceAnimation?.cancel();
    results.hidden = true;
    results.inert = true;
    input.setAttribute("aria-expanded", "false");
  });
}
