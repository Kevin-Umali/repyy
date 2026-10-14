export const motionPreference = window.matchMedia("(prefers-reduced-motion: reduce)");
const styles = getComputedStyle(document.documentElement);
export const motionToken = (name) => styles.getPropertyValue(name).trim();
export const motionDuration = (name) => Number.parseFloat(motionToken(name)) || 0;
const active = new Map();

export function animate(element, frames, duration = "--duration-fast", options = {}) {
  active.get(element)?.cancel();
  if (motionPreference.matches || !element.animate) return;
  const animation = element.animate(frames, {
    duration: motionDuration(duration),
    easing: motionToken("--ease-smooth-out"),
    ...options,
  });
  active.set(element, animation);
  const forget = () => {
    if (active.get(element) === animation) active.delete(element);
  };
  animation.addEventListener("finish", forget, { once: true });
  animation.addEventListener("cancel", forget, { once: true });
  return animation;
}

export function revealUpdate(element) {
  return animate(
    element,
    [
      { opacity: 0.6, filter: `blur(${motionToken("--blur-small")})` },
      { opacity: 1, filter: "blur(0)" },
    ],
    "--duration-quick",
  );
}

const cancelAll = () => {
  active.forEach((animation) => animation.cancel());
  active.clear();
};
motionPreference.addEventListener("change", () => motionPreference.matches && cancelAll());
window.addEventListener("pagehide", cancelAll);
document.addEventListener("astro:before-swap", cancelAll);
