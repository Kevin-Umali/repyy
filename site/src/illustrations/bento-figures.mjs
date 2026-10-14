import * as k from "./iso-kit.mjs";
import { benchSvg, benchAxes } from "./inspection-bench.mjs";

function workshop(bounds, height) {
  const P = k.fitProjection(k.boxCorners(bounds, 0, height), 560, 400, { pad: 20, azimuth: 38, elevation: 34 });
  const slab = (plan, z, h, tone = "mid", lit = false) => k.solidSvg(k.slabOf(plan, z, h, P, 6, Math.min(0.8, h / 3)), { tone, lit });
  const bolts = (plan, z, inset = 4) =>
    k.dotsSvg(
      k.corners(plan, inset).map(([x, y]) => k.iso([x, y, z], P)),
      { size: 0.7, tone: "mid" },
    );
  const paper = (plan, z, printed = true) =>
    slab(plan, z, 0.7, "hi") +
    (printed
      ? Array.from({ length: 6 }, (_, i) =>
          k.lineSvg(k.lineOnTop([plan.x + 6, plan.y + 7 + i * 5], [plan.x + plan.w - 8 - (i % 3) * 5, plan.y + 7 + i * 5], z + 0.7, P), {
            tone: "lo",
            free: true,
          }),
        ).join("")
      : "");
  const moving = (body, vector) => `<g data-travel="${k.axisVector(P, vector).join(",")}">${body}</g>`;
  const render = (body, label) => k.figureSvg({ width: 560, height: 400, body, label });
  return { P, slab, bolts, paper, moving, render };
}

// A rubber stamp and a source sheet: the value is covered while its shape remains.
// Six paper sheets, two clips, sole, body, shoulder, neck, collar, grip, two caps,
// twenty grip ribs, four label fasteners and an ink-pad case with a removable lid.
function stamp() {
  const base = { x: -80, y: -48, w: 168, d: 104, r: 2 };
  const { P, slab, bolts, paper, moving, render } = workshop({ ...base, y: -65, d: 130 }, 114);
  const out = [`<path class="iso-halo" d="${k.haloOf(base, 0, 1, P)}"/>`];
  for (let i = 0; i < 6; i++) out.push(paper({ x: -76 + i * 0.8, y: -43 + i * 0.5, w: 148, d: 86, r: 1 }, i * 0.7, i === 5));
  out.push(`<g data-anatomy-reveal style="opacity:0">${slab({ x: -46, y: -12, w: 90, d: 17, r: 1 }, 4.3, 0.1, "lo", true)}</g>`);
  for (const x of [-61, 53]) out.push(slab({ x, y: -45, w: 13, d: 7, r: 1 }, 4.3, 2, "mid"), bolts({ x, y: -45, w: 13, d: 7 }, 6.3, 2));
  const tool = [];
  tool.push(slab({ x: -52, y: -24, w: 104, d: 48, r: 4 }, 25, 3, "lo"));
  tool.push(slab({ x: -55, y: -27, w: 110, d: 54, r: 5 }, 28, 7, "mid"));
  tool.push(slab({ x: -52, y: -24, w: 104, d: 48, r: 4 }, 35, 2, "hi"), bolts({ x: -52, y: -24, w: 104, d: 48 }, 37, 6));
  tool.push(slab({ x: -15, y: -12, w: 30, d: 24, r: 3 }, 37, 6, "mid"));
  tool.push(slab({ x: -9, y: -8, w: 18, d: 16, r: 3 }, 43, 35, "mid"));
  tool.push(slab({ x: -13, y: -12, w: 26, d: 24, r: 3 }, 78, 5, "hi"));
  tool.push(slab({ x: -50, y: -18, w: 100, d: 36, r: 12 }, 83, 15, "mid"));
  tool.push(slab({ x: -45, y: -15, w: 90, d: 30, r: 10 }, 98, 2, "hi", true));
  for (let x = -35; x <= 35; x += 7) for (const y of [-16, 11]) tool.push(slab({ x, y, w: 2, d: 5, r: 1 }, 98, 2, "mid"));
  tool.push(k.faceTextSvg(k.topMatrix([0, 3], 100, P), "REDACTED", { size: 6.5, tone: "mid", anchor: "middle" }));
  out.push(moving(tool.join(""), [0, 0, -20]));
  return render(out, "A redaction stamp lowers onto a source document, masking a value.");
}

// Five separately mounted drawers expose repository surfaces beyond the app folder.
function cabinet() {
  const base = { x: -78, y: -54, w: 156, d: 110, r: 5 };
  const { P, slab, bolts, paper, moving, render } = workshop({ ...base, d: 142 }, 113);
  const out = [`<path class="iso-halo" d="${k.haloOf(base, 0, 1, P)}"/>`];
  for (const [x, y] of k.corners(base, 14)) out.push(slab({ x: x - 5, y: y - 5, w: 10, d: 10, r: 2 }, 0, 8, "lo"));
  out.push(slab(base, 8, 4, "mid"));
  out.push(slab({ x: -68, y: -44, w: 136, d: 4, r: 1 }, 12, 96, "lo"), slab({ x: -68, y: -40, w: 4, d: 78, r: 1 }, 12, 96, "mid"));
  for (let i = 0; i < 5; i++) {
    const z = 14 + i * 18,
      tray = [];
    tray.push(slab({ x: -61, y: -38, w: 122, d: 73, r: 2 }, z, 2, "mid"));
    for (const x of [-61, 58]) tray.push(slab({ x, y: -38, w: 3, d: 73, r: 1 }, z + 2, 12, "mid"));
    tray.push(paper({ x: -51, y: -29, w: 48, d: 45, r: 1 }, z + 2), paper({ x: 3, y: -29, w: 48, d: 45, r: 1 }, z + 2));
    tray.push(slab({ x: -49, y: -31, w: 14, d: 5, r: 1 }, z + 3, 2, "hi", i === 2));
    tray.push(slab({ x: -62, y: 33, w: 124, d: 4, r: 2 }, z, 15, "hi"));
    for (const x of [-17, 13]) tray.push(slab({ x, y: 37, w: 4, d: 5, r: 1 }, z + 6, 3, "mid"));
    tray.push(slab({ x: -20, y: 42, w: 40, d: 3, r: 1 }, z + 6, 3, "hi"));
    out.push(moving(tray.join(""), [0, i === 2 ? 40 : 0, 0]));
  }
  out.push(slab({ x: 64, y: -40, w: 4, d: 78, r: 1 }, 12, 96, "mid"));
  out.push(slab({ x: -68, y: -44, w: 136, d: 82, r: 3 }, 108, 4, "hi"), bolts({ x: -68, y: -44, w: 136, d: 82 }, 112, 7));
  return render(out, "A repository cabinet with five drawers. Its middle drawer slides open to reveal more files.");
}
// Frames include the full animated travel and shadow, without unused canvas around the object.
const frame = (svg, viewBox) => svg.replace(/viewBox="[^"]+"/, `viewBox="${viewBox}"`);
const bench = benchSvg
  .replace("data-bench-head", `data-rest="${benchAxes.x.map((v) => v * -78).join(",")}" data-travel="${benchAxes.x.map((v) => v * 156).join(",")}"`)
  .replace("data-bench-drawer", `data-travel="${benchAxes.y.map((v) => v * 24).join(",")}"`);
export const figures = {
  install: {
    svg: frame(bench, "165 80 430 340"),
    rest: "Read the files. Leave the code still.",
  },
  secrets: { svg: frame(stamp(), "100 75 350 320"), rest: "Keep the evidence." },
  surface: {
    svg: frame(cabinet(), "115 15 360 370"),
    rest: "There is more than src/.",
  },
};

function sourceTray() {
  const base = { x: -72, y: -52, w: 144, d: 104, r: 4 };
  const { P, slab, bolts, paper, moving, render } = workshop(base, 80);
  const out = [`<path class="iso-halo" d="${k.haloOf(base, 0, 1, P)}"/>`, slab(base, 0, 5, "mid")];
  for (const x of [-72, 68]) out.push(slab({ x, y: -52, w: 4, d: 104, r: 1 }, 5, 24, "mid"));
  out.push(slab({ x: -68, y: -52, w: 136, d: 4, r: 1 }, 5, 24, "mid"));
  for (let i = 0; i < 7; i++) out.push(paper({ x: -61 + i * 0.5, y: -40 + i * 0.5, w: 120, d: 80, r: 1 }, 6 + i * 1.3, i === 6));
  const sheet = paper({ x: -60, y: -40, w: 120, d: 80, r: 1 }, 26) + slab({ x: -53, y: -35, w: 26, d: 7, r: 1 }, 26.7, 0.5, "hi", true);
  out.push(moving(sheet, [0, 0, 18]), bolts(base, 5, 8));
  return render(out, "Source files resting in a tray. One sheet rises to be inspected.");
}
function evidenceReport() {
  const base = { x: -74, y: -50, w: 148, d: 100, r: 4 };
  const { P, slab, paper, moving, render } = workshop(base, 72);
  const out = [`<path class="iso-halo" d="${k.haloOf(base, 0, 1, P)}"/>`, slab(base, 0, 5, "mid")];
  for (let i = 0; i < 6; i++) out.push(paper({ x: -66 + i * 0.6, y: -42 + i * 0.5, w: 132, d: 84, r: 1 }, 5 + i * 0.8, false));
  const sheet = [paper({ x: -62, y: -39, w: 124, d: 78, r: 2 }, 18, false)];
  sheet.push(slab({ x: -50, y: -30, w: 100, d: 13, r: 2 }, 18.7, 0.7, "hi", true));
  sheet.push(k.faceTextSvg(k.topMatrix([-44, -21], 19.5, P), "REVIEW REQUIRED", { size: 6, tone: "mid" }));
  for (let i = 0; i < 3; i++) {
    sheet.push(slab({ x: -50, y: -7 + i * 13, w: 9, d: 7, r: 1 }, 18.7, 0.5, i === 0 ? "lo" : "mid", i === 0));
    sheet.push(k.lineSvg(k.lineOnTop([-33, -3 + i * 13], [48 - i * 9, -3 + i * 13], 19, P), { tone: "lo", free: true }));
  }
  out.push(moving(sheet.join(""), [0, 0, 14]));
  return render(out, "An inspection report separates findings into rows for a person to review.");
}
export const workflowFigures = [frame(sourceTray(), "80 85 400 315"), frame(bench, "165 80 430 340"), frame(evidenceReport(), "75 90 410 310")];
