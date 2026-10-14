import { motionPreference, motionDuration } from "./motion.js";
const lifetime = new AbortController();
const options = { signal: lifetime.signal };
const hover = window.matchMedia("(hover: hover) and (pointer: fine)");
const controllers = [];
for (const figure of document.querySelectorAll("[data-anatomy]")) {
  const card = figure.closest(".coverage-card");
  const parts = [...figure.querySelectorAll("[data-travel]")].map((element) => ({
    element,
    travel: element.dataset.travel.split(",").map(Number),
    rest: (element.dataset.rest || "0,0").split(",").map(Number),
  }));
  let position = 0,
    target = 0,
    frame = 0,
    from = 0,
    started = 0,
    visible = true;
  const duration = motionDuration("--duration-fast");
  const draw = () => {
    parts.forEach(({ element, travel, rest }) =>
      element.setAttribute("transform", `translate(${rest[0] + travel[0] * position} ${rest[1] + travel[1] * position})`),
    );
    figure.querySelectorAll("[data-bench-mark],[data-anatomy-reveal]").forEach((mark) => (mark.style.opacity = String(position)));
  };
  const settle = () => {
    cancelAnimationFrame(frame);
    frame = 0;
    position = target;
    draw();
  };
  const tick = (now) => {
    if (!figure.isConnected || document.hidden || !visible || motionPreference.matches) return settle();
    if (!started) started = now;
    const t = Math.min(1, (now - started) / duration);
    position = t === 1 ? target : from + (target - from) * (1 - (1 - t) ** 3);
    draw();
    frame = t < 1 ? requestAnimationFrame(tick) : 0;
  };
  const select = (next) => {
    if (target === next) return;
    target = next;
    cancelAnimationFrame(frame);
    if (motionPreference.matches || document.hidden || !visible) return settle();
    from = position;
    started = 0;
    frame = requestAnimationFrame(tick);
  };
  card.addEventListener(
    "pointerenter",
    (e) => {
      if (e.pointerType === "mouse" && hover.matches) select(1);
    },
    options,
  );
  card.addEventListener("pointerleave", () => select(0), options);
  const observer = new IntersectionObserver((entries) => {
    visible = entries.at(-1).isIntersecting;
    if (!visible) {
      select(0);
      settle();
    }
  });
  observer.observe(card);
  motionPreference.addEventListener("change", settle, options);
  document.addEventListener(
    "visibilitychange",
    () => {
      if (document.hidden) settle();
    },
    options,
  );
  window.addEventListener("pagehide", settle, options);
  controllers.push(() => {
    settle();
    observer.disconnect();
  });
  draw();
}
const cleanup = () => {
  controllers.forEach((dispose) => dispose());
  lifetime.abort();
};
document.addEventListener("astro:before-swap", cleanup, options);
if (import.meta.hot) import.meta.hot.dispose(cleanup);
