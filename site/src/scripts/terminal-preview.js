import { motionPreference, motionDuration } from "./motion.js";

export function terminalPreview(source) {
  const visual = document.createElement("span");
  visual.className = "terminal-output";
  visual.setAttribute("aria-hidden", "true");
  let text = source.textContent.trim(),
    terminal = true,
    timer,
    guard,
    played = false;
  visual.textContent = text;
  source.after(visual);
  source.classList.add("visually-hidden");
  const settle = () => {
    clearTimeout(timer);
    clearTimeout(guard);
    visual.textContent = text;
    visual.dataset.running = "false";
  };
  const play = () => {
    settle();
    if (motionPreference.matches || document.hidden || !terminal) return;
    const [command, ...rows] = text.split("\n");
    let cursor = 0,
      row = 0;
    visual.textContent = "";
    visual.dataset.running = "true";
    const print = () => {
      if (!source.isConnected || document.hidden) {
        settle();
        return;
      }
      if (cursor < command.length) {
        visual.textContent = command.slice(0, ++cursor);
        timer = setTimeout(print, 22);
      } else if (row < rows.length) {
        visual.textContent += "\n" + rows[row++];
        timer = setTimeout(print, motionDuration("--stagger-step"));
      } else settle();
    };
    guard = setTimeout(settle, 2000);
    print();
  };
  const observer = new IntersectionObserver(
    (entries) => {
      if (entries.at(-1).isIntersecting && !played) {
        played = true;
        play();
      } else if (!entries.at(-1).isIntersecting) settle();
    },
    { threshold: 0.3 },
  );
  observer.observe(source.parentElement);
  const lifetime = new AbortController();
  const options = { signal: lifetime.signal };
  motionPreference.addEventListener(
    "change",
    () => {
      if (motionPreference.matches) settle();
    },
    options,
  );
  document.addEventListener(
    "visibilitychange",
    () => {
      if (document.hidden) settle();
    },
    options,
  );
  window.addEventListener("pagehide", settle, options);
  const cleanup = () => {
    settle();
    observer.disconnect();
    lifetime.abort();
    visual.remove();
    source.classList.remove("visually-hidden");
  };
  document.addEventListener("astro:before-swap", cleanup, options);
  if (import.meta.hot) import.meta.hot.dispose(cleanup);
  return (next, { isTerminal, animate }) => {
    text = next;
    terminal = isTerminal;
    source.textContent = text;
    settle();
    if (animate && terminal) play();
  };
}
