import { flows } from "./tui-flows.js";
import { toHTML } from "./tui-screens.js";

const SWAP = { duration: 180, easing: "cubic-bezier(0.22, 1, 0.36, 1)" };
const PRESS = { duration: 160, easing: "cubic-bezier(0.23, 1, 0.32, 1)" };

export function mountTui(root) {
  const flow = flows[root.dataset.flow];
  if (!flow) return;
  const screen = root.querySelector("[data-tui-screen]");
  const keycap = root.querySelector("[data-tui-key]");
  const keyLabel = keycap.querySelector(".keycap-label");
  const toggle = root.querySelector("[data-tui-toggle]");
  const pill = root.querySelector("[data-steps-pill]");
  const steps = [...root.querySelectorAll("[data-step]")];
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  const { beats, length } = flow.script();

  let clock = 0;
  let last = 0;
  let index = -1;
  let playing = !reduced.matches;
  let visible = false;
  let raf = 0;
  let scene = "";
  let current = -1;

  const paint = (lines, { soft = true } = {}) => {
    const next = lines[0];
    screen.innerHTML = toHTML(lines);
    if (soft && scene && next !== scene) {
      const frames = reduced.matches
        ? [{ opacity: 0.6 }, { opacity: 1 }]
        : [
            { opacity: 0.55, filter: "blur(2px)" },
            { opacity: 1, filter: "blur(0)" },
          ];
      screen.animate(frames, SWAP);
    }
    scene = next;
  };

  const placePill = (instant = false) => {
    const li = steps[current];
    if (!pill) return;
    if (!li) {
      pill.style.opacity = "0";
      return;
    }
    if (instant) pill.setAttribute("data-instant", "");
    pill.style.opacity = "1";
    pill.style.width = `${li.offsetWidth}px`;
    pill.style.height = `${li.offsetHeight}px`;
    pill.style.transform = `translate(${li.offsetLeft}px, ${li.offsetTop}px)`;
    if (instant) {
      void pill.offsetWidth;
      pill.removeAttribute("data-instant");
    }
  };

  const mark = (n, instant = false) => {
    if (n === current && !instant) return;
    current = n;
    steps.forEach((el, i) => el.toggleAttribute("data-current", i === n));
    placePill(instant);
  };

  const press = (key) => {
    const changed = keyLabel.textContent !== key;
    keyLabel.textContent = key;
    keycap.removeAttribute("data-empty");
    if (reduced.matches) return;
    keycap.animate([{ transform: "translateY(3px) scale(0.96)", color: "var(--accent)" }, { transform: "none" }], PRESS);
    if (changed) {
      keyLabel.animate(
        [
          { opacity: 0, filter: "blur(2px)", transform: "translateY(4px)" },
          { opacity: 1, filter: "blur(0)", transform: "none" },
        ],
        SWAP,
      );
    }
  };

  const show = ({ render, step }) => {
    paint(render(), { soft: false });
    mark(step, true);
  };

  const tick = (now) => {
    raf = 0;
    if (!playing || !visible) return;
    // Background tabs deliver frames late; cap the catch-up so a long pause can't skip the story.
    clock += Math.min(1000, now - (last || now));
    last = now;
    if (clock >= length) {
      clock = 0;
      index = -1;
    }
    while (index + 1 < beats.length && beats[index + 1].t <= clock) {
      index++;
      const beat = beats[index];
      if (index + 1 < beats.length && beats[index + 1].t <= clock) continue;
      paint(beat.render());
      mark(beat.step);
      if (beat.key) press(beat.key);
    }
    raf = requestAnimationFrame(tick);
  };

  const run = () => {
    if (!raf && playing && visible) {
      last = 0;
      raf = requestAnimationFrame(tick);
    }
  };

  const setPlaying = (next) => {
    playing = next;
    root.dataset.state = playing ? "playing" : "paused";
    toggle.setAttribute("aria-pressed", String(!playing));
    toggle.textContent = playing ? "pause" : "play";
    if (!playing) {
      cancelAnimationFrame(raf);
      raf = 0;
    }
    run();
  };

  toggle.addEventListener("click", () => setPlaying(!playing));
  reduced.addEventListener("change", () => {
    if (!reduced.matches) return;
    setPlaying(false);
    show(flow.poster);
  });
  new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
    run();
  }).observe(root);
  new ResizeObserver(() => placePill(true)).observe(root);

  scene = screen.textContent.split("\n")[0];
  const pin = flow.pins?.[new URLSearchParams(location.search).get("tui")];
  if (pin) {
    show(pin);
    setPlaying(false);
    return;
  }
  mark(flow.poster.step, true);
  setPlaying(playing);
}

export function mountAllTui(scope = document) {
  scope.querySelectorAll("[data-tui]").forEach((root) => mountTui(root));
}
