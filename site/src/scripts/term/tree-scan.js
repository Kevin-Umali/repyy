const STEP = 460;
const HOLD = 3800;

export function mountTreeScan(root) {
  const rows = [...root.querySelectorAll("[data-row]")];
  const cursor = root.querySelector("[data-tree-cursor]");
  const counter = root.querySelector("[data-tree-count]");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  let timer = 0;
  let visible = false;
  let i = 0;
  let lastHits = "";

  const reshuffle = () => {
    let picked;
    do {
      const count = 2 + Math.floor(Math.random() * 2);
      picked = [...rows.keys()]
        .sort(() => Math.random() - 0.5)
        .slice(0, count)
        .sort((a, b) => a - b);
    } while (picked.join() === lastHits);
    lastHits = picked.join();
    rows.forEach((r, n) => r.toggleAttribute("data-hit", picked.includes(n)));
  };

  const count = (read) => {
    const hits = rows.slice(0, read).filter((r) => r.hasAttribute("data-hit")).length;
    if (counter) counter.textContent = `${read} of ${rows.length} read · ${hits} ${hits === 1 ? "finding" : "findings"}`;
  };

  const moveCursor = (row, instant = false) => {
    if (!cursor) return;
    if (instant) cursor.setAttribute("data-instant", "");
    cursor.style.height = `${row.offsetHeight}px`;
    cursor.style.transform = `translateY(${row.offsetTop}px)`;
    if (instant) {
      void cursor.offsetWidth;
      cursor.removeAttribute("data-instant");
    }
  };

  const finish = () => {
    rows.forEach((r) => (r.dataset.state = "read"));
    cursor?.removeAttribute("data-on");
    count(rows.length);
  };

  const step = () => {
    if (!visible || reduced.matches) return;
    if (i === 0) {
      rows.forEach((r) => (r.dataset.state = "queued"));
      reshuffle();
      moveCursor(rows[0], true);
      cursor?.setAttribute("data-on", "");
      count(0);
    }
    if (i < rows.length) {
      moveCursor(rows[i]);
      rows[i].dataset.state = "read";
      i++;
      count(i);
      timer = setTimeout(step, STEP);
    } else {
      cursor?.removeAttribute("data-on");
      i = 0;
      timer = setTimeout(step, HOLD);
    }
  };

  finish();
  new IntersectionObserver(([entry]) => {
    const was = visible;
    visible = entry.isIntersecting;
    if (visible && !was) timer = setTimeout(step, 700);
    if (!visible) {
      clearTimeout(timer);
      finish();
      i = 0;
    }
  }).observe(root);
  reduced.addEventListener("change", () => {
    if (!reduced.matches) return;
    clearTimeout(timer);
    finish();
  });
}
