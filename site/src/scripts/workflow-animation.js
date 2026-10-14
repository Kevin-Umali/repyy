import { motionPreference, motionToken } from "./motion.js";
const lifetime = new AbortController();
const options = { signal: lifetime.signal };
const cleanups = [];
for (const figure of document.querySelectorAll("[data-workflow-animation]")) {
  let visible = false;
  const animations = [];
  const easing = motionToken("--ease-smooth-out");
  const sync = () =>
    animations.forEach((animation) => {
      if (visible && !document.hidden && !motionPreference.matches) animation.play();
      else animation.pause();
    });
  figure.querySelectorAll(".workflow-station").forEach((station, index) => {
    const start = index / 3;
    const offsets = [0, start, start + 0.1, start + 0.23, start + 0.31, 1];
    const values = [0, 0, 1, 1, 0, 0];
    station.querySelectorAll("[data-travel]").forEach((part) => {
      const travel = part.dataset.travel.split(",").map(Number);
      const rest = (part.dataset.rest || "0,0").split(",").map(Number);
      const transform = (value) => `translate(${rest[0] + travel[0] * value}px,${rest[1] + travel[1] * value}px)`;
      part.style.transform = transform(0);
      const animation = part.animate(
        offsets.map((offset, i) => ({ offset, transform: transform(values[i]), easing })),
        { duration: 9000, iterations: Infinity },
      );
      animation.pause();
      animations.push(animation);
    });
    station.querySelectorAll("[data-bench-mark]").forEach((mark) => {
      const animation = mark.animate(
        offsets.map((offset, i) => ({ offset, opacity: values[i] })),
        { duration: 9000, iterations: Infinity },
      );
      animation.pause();
      animations.push(animation);
    });
  });
  const observer = new IntersectionObserver(
    (entries) => {
      visible = entries.at(-1).isIntersecting;
      sync();
    },
    { threshold: 0.08 },
  );
  observer.observe(figure);
  document.addEventListener("visibilitychange", sync, options);
  motionPreference.addEventListener("change", sync, options);
  window.addEventListener("pagehide", () => animations.forEach((a) => a.pause()), options);
  window.addEventListener("pageshow", sync, options);
  cleanups.push(() => {
    observer.disconnect();
    animations.forEach((a) => a.cancel());
  });
}
const cleanup = () => {
  cleanups.forEach((dispose) => dispose());
  lifetime.abort();
};
document.addEventListener("astro:before-swap", cleanup, options);
if (import.meta.hot) import.meta.hot.dispose(cleanup);
