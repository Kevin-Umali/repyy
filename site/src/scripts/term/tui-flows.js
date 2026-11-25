import { coverage, detail, exportFormat, exportPath, handoff, progress, prompt, review } from "./tui-screens.js";

function builder() {
  const beats = [];
  let t = 500;
  let step = 0;
  return {
    get t() {
      return t;
    },
    step(n) {
      step = n;
    },
    at(ms, render, key) {
      t = ms;
      beats.push({ t, render, key, step });
    },
    type(text, render) {
      for (let i = 1; i <= text.length; i++) this.at(t + (i === 1 ? 300 : 55 + (i % 3) * 18), () => render(text.slice(0, i)));
    },
    scan() {
      const start = t + 200;
      for (let i = 0; i <= 25; i++) {
        const pct = Math.min(100, Math.round((i / 25) ** 0.8 * 100));
        this.at(start + i * 90, () => progress(pct, 0.1 + i * 0.07, i));
      }
    },
    done(tail = 900) {
      return { beats, length: t + tail };
    },
  };
}

const SCAN = "repyy scan . --format tui";
const SAVED = "Saved HTML report to repyy-report.html";

export const flows = {
  tour: {
    title: "~/take-home · repyy scan . --format tui",
    steps: [
      ["type", "repyy scan . --format tui"],
      ["scan", "files are read, nothing is run"],
      ["review", "3 findings, coverage complete"],
      ["↓", "move to the next finding"],
      ["e", "export an HTML report"],
      ["q", "quit back to the shell"],
    ],
    poster: { render: () => review(0), step: 2 },
    pins: {
      prompt: { render: () => prompt(SCAN.slice(0, 12)), step: 0 },
      scan: { render: () => progress(62, 1.4, 3), step: 1 },
      review: { render: () => review(0), step: 2 },
      moved: { render: () => review(1), step: 3 },
      export: { render: () => exportFormat(0), step: 4 },
      saved: { render: () => review(1, { notice: SAVED }), step: 4 },
    },
    script() {
      const b = builder();
      b.step(0);
      b.at(b.t, () => prompt(""));
      b.type(SCAN, (s) => prompt(s));
      b.at(b.t + 450, () => prompt(SCAN, { caret: false }), "enter");
      b.step(1);
      b.scan();
      b.step(2);
      b.at(b.t + 300, () => review(0));
      b.step(3);
      b.at(b.t + 2600, () => review(1), "↓");
      b.step(4);
      b.at(b.t + 1700, () => review(1), "e");
      b.at(b.t + 10, () => exportFormat(0));
      b.at(b.t + 1100, () => exportFormat(0), "enter");
      b.at(b.t + 10, () => exportPath("repyy-report.html"));
      b.at(b.t + 1000, () => exportPath("repyy-report.html", { caret: false }), "enter");
      b.at(b.t + 250, () => review(1, { notice: SAVED }));
      b.step(5);
      b.at(b.t + 2800, () => review(1, { notice: SAVED }), "q");
      const history = [`{m:~/take-home} {a:❯} ${SCAN}`];
      b.at(b.t + 200, () => prompt("", { history }));
      b.at(b.t + 1300, () => prompt("", { history }), "ctrl+l");
      b.at(b.t + 250, () => prompt(""));
      return b.done();
    },
  },

  inspect: {
    title: "interactive review · read findings, hand off, check coverage",
    steps: [
      ["enter", "open the selected finding"],
      ["]", "step to the next finding in place"],
      ["h", "a Markdown brief for an issue or agent"],
      ["esc", "back to the queue"],
      ["3", "open the coverage tab"],
    ],
    poster: { render: () => detail(1), step: 1 },
    pins: {
      queue: { render: () => review(0), step: 0 },
      detail: { render: () => detail(1), step: 1 },
      handoff: { render: () => handoff(), step: 2 },
      coverage: { render: () => coverage(), step: 4 },
    },
    script() {
      const b = builder();
      b.step(0);
      b.at(b.t, () => review(0));
      b.at(b.t + 1500, () => detail(0), "enter");
      b.step(1);
      b.at(b.t + 2600, () => detail(1), "]");
      b.step(2);
      b.at(b.t + 3000, () => handoff(), "h");
      b.step(3);
      b.at(b.t + 3800, () => review(1), "esc");
      b.step(4);
      b.at(b.t + 1400, () => coverage(), "3");
      b.at(b.t + 3400, () => review(1), "esc");
      b.at(b.t + 1200, () => review(0), "↑");
      return b.done(600);
    },
  },

  incomplete: {
    title: "~/take-home · a scan that hit the archive-depth limit",
    steps: [
      ["scan", "an archive nests past 3 levels"],
      ["review", "SCAN INCOMPLETE, partial coverage"],
      ["3", "coverage names the skipped area"],
      ["esc", "back to findings"],
    ],
    poster: { render: () => coverage({ scenario: "incomplete" }), step: 2 },
    pins: {
      review: { render: () => review(0, { scenario: "incomplete" }), step: 1 },
      coverage: { render: () => coverage({ scenario: "incomplete" }), step: 2 },
    },
    script() {
      const b = builder();
      b.step(0);
      b.at(b.t, () => progress(0, 0.1, 0));
      b.scan();
      b.step(1);
      b.at(b.t + 300, () => review(0, { scenario: "incomplete" }));
      b.step(2);
      b.at(b.t + 2800, () => coverage({ scenario: "incomplete" }), "3");
      b.step(3);
      b.at(b.t + 4200, () => review(0, { scenario: "incomplete" }), "esc");
      return b.done(1800);
    },
  },
};
