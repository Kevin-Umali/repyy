const RAMP = " .:-=+*#%@";
const FPS = 30;
const PERIOD = 7;
const WORDMARK_ASPECT = 3.4;
const POSTER_TIME = 3.1;
const RULES = ["PKG-001", "CHAIN-001", "CRED-001", "DECODE-001", "GITHOOK-001", "AGENT-001", "DOCKER-001", "EXEC-001", "CICD-001"];

function hash(x, y) {
  let h = (x * 374761393 + y * 668265263) | 0;
  h = Math.imul(h ^ (h >>> 13), 1274126177);
  return ((h ^ (h >>> 16)) >>> 0) / 4294967295;
}

function noise(x, y) {
  const xi = Math.floor(x);
  const yi = Math.floor(y);
  const xf = x - xi;
  const yf = y - yi;
  const u = xf * xf * (3 - 2 * xf);
  const v = yf * yf * (3 - 2 * yf);
  const a = hash(xi, yi);
  const b = hash(xi + 1, yi);
  const c = hash(xi, yi + 1);
  const d = hash(xi + 1, yi + 1);
  return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
}

export function mountWordmark(pre, { text = "repyy/", accentFrom = 5 } = {}) {
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  let cols = 0;
  let rows = 0;
  let mask = new Float32Array(0);
  let accent = new Uint8Array(0);
  let raf = 0;
  let last = 0;
  let t = 0;
  let visible = false;
  let sweep = -1;
  let hits = [];

  const plant = () => {
    const solid = [];
    for (let y = 0; y < rows; y++) {
      for (let x = 2; x < cols - 2; x++) if (mask[y * cols + x] > 0.7 && !accent[y * cols + x]) solid.push([x, y]);
    }
    const rules = [...RULES].sort(() => Math.random() - 0.5);
    const want = 2 + Math.floor(Math.random() * 2);
    hits = [];
    for (let tries = 0; tries < 200 && hits.length < want && solid.length; tries++) {
      const [x, y] = solid[Math.floor(Math.random() * solid.length)];
      if (hits.some((h) => Math.abs(h.x - x) < cols / 6)) continue;
      const label = `! ${rules[hits.length]}`;
      const free = (row) => row >= 0 && row < rows && [...label].every((_, i) => x + i < cols && mask[row * cols + x + i] < 0.04);
      let row = -1;
      for (let d = 1; d < rows && row < 0; d++) {
        if (free(y - d)) row = y - d;
        else if (free(y + d)) row = y + d;
      }
      hits.push({ x, y, label, row });
    }
  };

  const marks = (beam) => {
    const out = new Map();
    for (const h of hits) {
      if (beam < h.x) continue;
      out.set(h.y * cols + h.x - 1, ["[", "hit-box"]);
      out.set(h.y * cols + h.x, ["!", "hit"]);
      out.set(h.y * cols + h.x + 1, ["]", "hit-box"]);
      if (h.row >= 0) [...h.label].forEach((ch, i) => out.set(h.row * cols + h.x + i, [ch, "hit-label"]));
    }
    return out;
  };

  const layout = () => {
    const probe = document.createElement("span");
    probe.textContent = "M".repeat(20);
    pre.textContent = "";
    pre.append(probe);
    const cell = probe.getBoundingClientRect().width / 20;
    probe.remove();
    const line = parseFloat(getComputedStyle(pre).lineHeight);
    cols = Math.max(20, Math.floor(pre.clientWidth / cell));
    rows = Math.max(6, Math.round((cols * cell) / line / WORDMARK_ASPECT));

    const canvas = document.createElement("canvas");
    const w = cols;
    const h = rows * 2;
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = "#fff";
    ctx.textBaseline = "alphabetic";
    const sy = (2 * cell) / line;
    ctx.setTransform(1, 0, 0, sy, 0, 0);
    const lh = h / sy;
    const font = (px) => `800 ${px}px ui-sans-serif, -apple-system, "Helvetica Neue", Arial, sans-serif`;
    let size = lh;
    ctx.font = font(size);
    let tm = ctx.measureText(text);
    size *= Math.min((w * 0.99) / tm.width, (lh * 0.96) / (tm.actualBoundingBoxAscent + tm.actualBoundingBoxDescent));
    ctx.font = font(size);
    tm = ctx.measureText(text);
    const baseline = (lh + tm.actualBoundingBoxAscent - tm.actualBoundingBoxDescent) / 2;
    ctx.fillText(text, (w - tm.width) / 2, baseline);
    const head = (w - tm.width) / 2 + ctx.measureText(text.slice(0, accentFrom)).width;

    const data = ctx.getImageData(0, 0, w, h).data;
    mask = new Float32Array(cols * rows);
    accent = new Uint8Array(cols * rows);
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const a = data[(y * 2 * w + x) * 4] / 255;
        const b = data[((y * 2 + 1) * w + x) * 4] / 255;
        mask[y * cols + x] = (a + b) / 2;
        accent[y * cols + x] = x >= head ? 1 : 0;
      }
    }
    pre.style.setProperty("--rows", rows);
  };

  const draw = () => {
    const phase = (t % PERIOD) / PERIOD;
    const beam = -8 + phase * (cols + 24);
    if (Math.floor(t / PERIOD) !== sweep) {
      sweep = Math.floor(t / PERIOD);
      plant();
    }
    const found = marks(beam);
    let html = "";
    for (let y = 0; y < rows; y++) {
      let run = "";
      let cls = "";
      const flush = () => {
        if (!run) return;
        html += cls ? `<span class="${cls}">${run}</span>` : run;
        run = "";
      };
      for (let x = 0; x < cols; x++) {
        const m = mask[y * cols + x];
        let ch = " ";
        let k = "";
        if (m > 0.04) {
          const n = noise(x * 0.18 + t * 0.22, y * 0.35 - t * 0.09);
          const d = Math.min(1, m * (0.62 + n * 0.5));
          ch = RAMP[Math.max(1, Math.min(RAMP.length - 1, Math.round(d * (RAMP.length - 1))))];
          const behind = beam - x;
          if (behind >= 0 && behind < 1.5) k = "beam";
          else if (behind >= 0 && behind < 6) k = "trail";
          else if (behind >= 0 && behind < 16) k = "trail-far";
          else if (accent[y * cols + x]) k = "acc";
        } else {
          const behind = beam - x;
          if (behind >= 0 && behind < 1) {
            ch = "│";
            k = "beam-dim";
          } else if (hash(x * 7, y * 13) > 0.985) {
            ch = "·";
            k = "dust";
          }
        }
        const mark = found.get(y * cols + x);
        if (mark) [ch, k] = mark;
        if (k !== cls) {
          flush();
          cls = k;
        }
        run += ch;
      }
      flush();
      html += "\n";
    }
    pre.innerHTML = html;
  };

  const loop = (now) => {
    raf = requestAnimationFrame(loop);
    if (now - last < 1000 / FPS) return;
    t += Math.min(0.25, (now - (last || now)) / 1000);
    last = now;
    draw();
  };

  const run = () => {
    cancelAnimationFrame(raf);
    raf = 0;
    if (visible && !reduced.matches) {
      last = 0;
      raf = requestAnimationFrame(loop);
    }
  };

  layout();
  t = POSTER_TIME;
  draw();
  let width = pre.clientWidth;
  new ResizeObserver(() => {
    if (Math.abs(pre.clientWidth - width) < 2) return;
    width = pre.clientWidth;
    layout();
    sweep = -1;
    draw();
  }).observe(pre);
  new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
    run();
  }).observe(pre);
  reduced.addEventListener("change", run);
}
