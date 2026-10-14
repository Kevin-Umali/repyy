import * as k from "./iso-kit.mjs";

// A flatbed inspection bench: the moving optical head reads a fixed specimen;
// a side tray presents evidence. Nothing on the bench executes the specimen.
// Parts: 8 foot pads/risers, base/lip (2), platen/frame (5), paper cards (6),
// rail beds/tracks/stops (12), gantry shoes/posts/bridge/caps/aperture (13),
// evidence tray/four walls/handle/papers (10), ruler/index plates (4).
const base = { x: -154, y: -86, w: 342, d: 172, r: 8 };
const P = k.fitProjection(k.boxCorners(base, -22, 84), 760, 440, { pad: 44, azimuth: 38, elevation: 36 });
const at = (p) => k.iso(p, P);
const line = (d, tone = "lo", free) => k.lineSvg(d, { tone, free });
const dots = (points, tone = "mid", size = 0.5) => k.dotsSvg(points.map(at), { tone, size });
const slab = (plan, z, h, tone = "mid", extra = {}) => {
  return k.solidSvg(k.slabOf(plan, z, h, P, 5, Math.min(0.8, h / 3)), { tone, ...extra });
};
const screws = (plan, z, inset = 4) => {
  const corners = k.corners(plan, inset);
  return line(corners.map(([x, y]) => k.ring(x, y, 1.5, z, P, 12)).join(""), "lo") + dots(corners.map(([x, y]) => [x, y, z]));
};
const paper = (plan, z, lengths) => {
  const out = [slab(plan, z, 0.7, "hi")];
  lengths.forEach((length, i) =>
    out.push(line(k.lineOnTop([plan.x + 5, plan.y + 6 + i * 4], [plan.x + 5 + length, plan.y + 6 + i * 4], z + 0.7, P), i === 0 ? "mid" : "lo", true)),
  );
  return out.join("");
};

function foundation() {
  const out = [`<path class="iso-halo" d="${k.haloOf(base, -22, 1, P)}"/>`];
  k.corners(base, 22)
    .sort((a, b) => k.depthOf([...a, 0], P) - k.depthOf([...b, 0], P))
    .forEach(([x, y]) => {
      out.push(slab({ x: x - 8, y: y - 8, w: 16, d: 16, r: 3 }, -22, 3, "lo"));
      out.push(slab({ x: x - 6, y: y - 6, w: 12, d: 12, r: 2 }, -19, 7, "lo"));
    });
  out.push(slab(base, -12, 10, "lo", { inner: line(k.sideSeam(base, -8, P, 5), "faint") }));
  out.push(slab(k.insetPlan(base, 1), -2, 2, "mid"));
  out.push(line(k.planOutline(k.insetPlan(base, 6), 0, P), "faint"), screws(base, 0, 10));
  const label = { x: -138, y: 64, w: 44, d: 12, r: 1.5 };
  out.push(slab(label, 0, 0.8, "mid"), screws(label, 0.8, 2));
  out.push(k.faceTextSvg(k.topMatrix([-116, 71.5], 0.8, P), "repyy /", { size: 4.2, tone: "mid", anchor: "middle" }));
  const ruler = { x: -80, y: 68, w: 186, d: 7, r: 0.8 };
  out.push(slab(ruler, 0, 0.6, "lo"));
  const ticks = k.topTicks(-76, 102, 4, 5, 68, 0.6, [2, 4.5], P);
  out.push(line(ticks.minor, "lo"), line(ticks.major, "mid"));
  return out.join("");
}

function rail(y) {
  const out = [];
  const bed = { x: -136, y, w: 246, d: 10, r: 1.5 };
  out.push(slab(bed, 0, 4, "mid"), screws(bed, 4, 3));
  out.push(slab({ x: -125, y: y + 2.5, w: 224, d: 5, r: 0.7 }, 4, 3, "hi"));
  for (const x of [-136, 102]) {
    const stop = { x, y: y - 2, w: 8, d: 14, r: 1 };
    out.push(slab(stop, 4, 8, "mid"), screws(stop, 12, 2));
  }
  return out.join("");
}

function specimen() {
  const out = [];
  out.push(slab({ x: -131, y: -41, w: 235, d: 82, r: 3 }, 0, 2, "lo"));
  out.push(slab({ x: -127, y: -37, w: 227, d: 74, r: 2 }, 2, 1, "hi"));
  for (const y of [-41, 38]) out.push(slab({ x: -131, y, w: 235, d: 3, r: 0.6 }, 2, 2, "mid"));
  for (const x of [-131, 101]) out.push(slab({ x, y: -38, w: 3, d: 76, r: 0.6 }, 2, 2, "mid"));
  [-118, -45, 28].forEach((x, index) => {
    const plan = { x, y: -27, w: 62, d: 54, r: 1 };
    out.push(paper({ ...plan, x: x + 1.5, y: -25.5 }, 3, []));
    out.push(paper(plan, 3.7, [30, 44, 38, 43, 24, 39, 32, 42]));
    out.push(`<g class="bench-mark" data-bench-mark="${index}">${line(k.lineOnTop([x + 5, -9], [x + 49, -9], 4.6, P), "lit", true)}</g>`);
    const clip = { x: x + 23, y: -29, w: 16, d: 5, r: 1 };
    out.push(
      slab(clip, 4.4, 1.4, "mid"),
      dots([
        [x + 27, -26.5, 5.8],
        [x + 35, -26.5, 5.8],
      ]),
    );
  });
  return out.join("");
}

function gantry() {
  const out = [];
  for (const y of [-56, 46]) {
    const shoe = { x: -12, y: y - 2, w: 24, d: 14, r: 2 };
    out.push(slab(shoe, 7, 5, "mid"), screws(shoe, 12));
    const post = { x: -7, y, w: 14, d: 10, r: 1 };
    out.push(slab(post, 12, 44, "mid", { inner: line(k.sideSeam(post, 48, P, 5), "lo") }));
    out.push(line(k.planOutline(k.insetPlan(post, 2), 56, P), "lo"));
  }
  const beam = { x: -12, y: -58, w: 24, d: 118, r: 3 };
  out.push(slab(beam, 56, 12, "hi", { inner: line(k.sideSeam(beam, 60, P, 5), "lo") }));
  out.push(slab(k.insetPlan(beam, 1.5), 68, 2, "hi"), screws(beam, 70, 5));
  const aperture = { x: -6, y: -36, w: 12, d: 76, r: 2 };
  out.push(slab(aperture, 70, 0.8, "hi", { lit: true }));
  out.push(line(k.planOutline(k.insetPlan(aperture, 2), 70.8, P), "mid"));
  for (const y of [-48, 48]) {
    out.push(slab({ x: -8, y, w: 16, d: 5, r: 1 }, 70, 1.5, "mid"));
    out.push(
      dots([
        [-4, y + 2.5, 71.5],
        [4, y + 2.5, 71.5],
      ]),
    );
  }
  for (let y = -30; y <= 30; y += 5) out.push(line(k.planOutline({ x: -3, y, w: 6, d: 1.2, r: 0.6 }, 70.8, P, 3), "faint"));
  return out.join("");
}

function evidence() {
  const out = [];
  const plan = { x: 122, y: -38, w: 52, d: 76, r: 2 };
  out.push(slab(plan, 0, 4, "lo"));
  out.push(slab({ x: 122, y: -38, w: 52, d: 3, r: 1 }, 4, 12, "mid"));
  out.push(slab({ x: 122, y: -35, w: 3, d: 70, r: 1 }, 4, 12, "mid"));
  const tray = [];
  tray.push(slab({ x: 125, y: -34, w: 46, d: 66, r: 1 }, 4, 2, "mid"));
  tray.push(paper({ x: 129, y: -29, w: 37, d: 54, r: 1 }, 6, [21, 26, 24, 18, 25, 22, 15, 25, 20, 24]));
  tray.push(slab({ x: 125, y: 31, w: 46, d: 4, r: 1 }, 4, 9, "hi"));
  tray.push(slab({ x: 140, y: 35, w: 5, d: 4, r: 1 }, 7, 3, "mid"));
  tray.push(slab({ x: 153, y: 35, w: 5, d: 4, r: 1 }, 7, 3, "mid"));
  tray.push(slab({ x: 138, y: 39, w: 22, d: 3, r: 1 }, 7, 3, "hi"));
  out.push(`<g data-bench-drawer>${tray.join("")}</g>`);
  out.push(slab({ x: 171, y: -35, w: 3, d: 73, r: 1 }, 4, 12, "mid"));
  out.push(screws(plan, 16, 1.5));
  return out.join("");
}

export const benchAxes = { x: k.axisVector(P, [1, 0, 0]), y: k.axisVector(P, [0, 1, 0]) };
export const benchSvg = k.figureSvg({
  width: 760,
  height: 440,
  label: "An illustrative inspection bench: three source documents lie on a fixed platen beneath a movable reading head. A side tray holds review evidence.",
  body: [foundation(), rail(-56), specimen(), rail(46), evidence(), `<g data-bench-head transform="${k.translateAlong(P, [-78, 0, 0])}">${gantry()}</g>`],
});
