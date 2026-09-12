const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

document.querySelectorAll('button, .button, .nav-docs').forEach((pressable) => {
  pressable.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    pressable.classList.add('is-pressed');
  });
  ['pointerup', 'pointercancel', 'pointerleave'].forEach((eventName) => {
    pressable.addEventListener(eventName, () => pressable.classList.remove('is-pressed'));
  });
});

const revealItems = document.querySelectorAll('.reveal');
if (reduceMotion) {
  revealItems.forEach((item) => item.classList.add('is-visible'));
} else {
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('is-visible');
      revealObserver.unobserve(entry.target);
    });
  }, { threshold: .14 });
  revealItems.forEach((item) => revealObserver.observe(item));
}

const showCopyResult = (button, result) => {
  const label = button.querySelector('[data-copy-label]') || button;
  const original = label.textContent;
  label.textContent = result;
  window.setTimeout(() => { label.textContent = original; }, 1600);
};

const copyText = async (button, value) => {
  try {
    await navigator.clipboard.writeText(value);
    showCopyResult(button, 'Copied');
  } catch {
    showCopyResult(button, 'Select and copy');
  }
};

document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', () => copyText(button, button.dataset.copy));
});

const attachTabs = (tabs, select) => {
  tabs.forEach((tab, index) => {
    tab.tabIndex = tab.classList.contains('is-active') ? 0 : -1;
    tab.addEventListener('click', (event) => select(tab, event.detail !== 0));
    tab.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const nextIndex = event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? tabs.length - 1
          : (index + (event.key === 'ArrowLeft' ? -1 : 1) + tabs.length) % tabs.length;
      tabs[nextIndex].focus();
      select(tabs[nextIndex], false);
    });
  });
};

document.querySelectorAll('[data-install-tabs]').forEach((panel) => {
  const tabs = [...panel.querySelectorAll('[data-install-command]')];
  const output = panel.querySelector('[data-install-output]');
  const copy = panel.querySelector('[data-install-copy]');

  const select = (tab) => {
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle('is-active', active);
      item.setAttribute('aria-selected', String(active));
      item.tabIndex = active ? 0 : -1;
    });
    output.textContent = tab.dataset.installCommand;
  };

  attachTabs(tabs, select);
  copy.addEventListener('click', () => copyText(copy, output.textContent));
});

const reportFormats = {
  terminal: {
    title: 'Terminal review',
    use: 'Human review',
    description: 'Prioritized findings with context and a clear verdict.',
    command: 'repyy scan ./assignment',
    preview: '$ repyy scan ./assignment\n\nREVIEW REQUIRED\n2 findings need context\n\nHIGH  PKG-014   package.json:12\nMED   OBF-003   src/setup.js:48',
  },
  json: {
    title: 'Structured JSON',
    use: 'Automation and archives',
    description: 'Stable identifiers, provenance, coverage, and redacted evidence.',
    command: 'repyy scan ./assignment --format json',
    preview: '{\n  "verdict": "review_required",\n  "coverage": "complete",\n  "findings": [\n    {\n      "rule": "PKG-014",\n      "severity": "high",\n      "confidence": "high"\n    }\n  ]\n}',
  },
  sarif: {
    title: 'SARIF output',
    use: 'Code scanning',
    description: 'Portable findings for existing security and review workflows.',
    command: 'repyy scan ./assignment --format sarif',
    preview: '{\n  "version": "2.1.0",\n  "runs": [{\n    "tool": { "driver": { "name": "repyy" } },\n    "results": [{\n      "ruleId": "PKG-014",\n      "level": "error"\n    }]\n  }]\n}',
  },
  html: {
    title: 'Offline HTML report',
    use: 'Private review artifact',
    description: 'A self-contained local report with filters and redacted evidence.',
    command: 'repyy scan ./assignment --format html --output report.html',
    preview: 'report.html\n\nNO NETWORK REQUESTS\nSelf-contained assets\n\nReview queue       2\nInformational      4\nCoverage       complete\nEvidence        redacted',
  },
};

document.querySelectorAll('[data-report-lab]').forEach((lab) => {
  const tabs = [...lab.querySelectorAll('[data-report-format]')];
  const screen = lab.querySelector('.report-screen');
  const title = lab.querySelector('[data-report-title]');
  const preview = lab.querySelector('[data-report-preview]');
  const use = lab.querySelector('[data-report-use]');
  const description = lab.querySelector('[data-report-description]');
  const command = lab.querySelector('[data-report-command]');
  const copy = lab.querySelector('[data-report-copy]');
  let animation;

  const select = (tab, animate) => {
    const format = reportFormats[tab.dataset.reportFormat];
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle('is-active', active);
      item.setAttribute('aria-selected', String(active));
      item.tabIndex = active ? 0 : -1;
    });
    title.textContent = format.title;
    preview.textContent = format.preview;
    use.textContent = format.use;
    description.textContent = format.description;
    command.textContent = format.command;
    lab.dataset.input = animate ? 'pointer' : 'keyboard';

    animation?.cancel();
    if (animate && !reduceMotion) {
      animation = screen.animate([
        { opacity: .58, transform: 'translate3d(0, 4px, 0)' },
        { opacity: 1, transform: 'translate3d(0, 0, 0)' },
      ], { duration: 200, easing: 'cubic-bezier(.23, 1, .32, 1)' });
    }
  };

  attachTabs(tabs, select);
  copy.addEventListener('click', () => copyText(copy, command.textContent));
});

const docsSearch = document.querySelector('#docs-search');
if (docsSearch) {
  const sections = [...document.querySelectorAll('.docs-searchable')];
  const empty = document.querySelector('#docs-empty');
  docsSearch.addEventListener('input', () => {
    const query = docsSearch.value.trim().toLowerCase();
    let visibleCount = 0;
    sections.forEach((section) => {
      const text = `${section.dataset.search} ${section.textContent}`.toLowerCase();
      const matches = !query || text.includes(query);
      section.hidden = !matches;
      if (matches) visibleCount += 1;
    });
    empty.hidden = visibleCount !== 0;
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === '/' && document.activeElement !== docsSearch) {
      event.preventDefault();
      docsSearch.focus();
    }
    if (event.key === 'Escape' && document.activeElement === docsSearch) {
      docsSearch.value = '';
      docsSearch.dispatchEvent(new Event('input'));
      docsSearch.blur();
    }
  });

  const links = [...document.querySelectorAll('.docs-sidebar a[href^="#"]')];
  const linkById = new Map(links.map((link) => [link.hash.slice(1), link]));
  const sectionObserver = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    links.forEach((link) => link.classList.remove('is-current'));
    linkById.get(visible.target.id)?.classList.add('is-current');
  }, { rootMargin: '-18% 0px -68%', threshold: [0, .2, .5] });
  sections.forEach((section) => sectionObserver.observe(section));
}

document.querySelectorAll('[data-drag-rail]').forEach((viewport) => {
  const rail = viewport.querySelector('.situation-rail');
  const nativeScroll = window.matchMedia('(max-width: 640px)').matches || reduceMotion;
  if (nativeScroll) return;

  const spring = { mass: 1, stiffness: 100, damping: 10 };
  let position = 0;
  let target = 0;
  let velocity = 0;
  let frame;
  let lastFrame = 0;
  let pointerId;
  let pressX = 0;
  let lastX = 0;
  let dragging = false;
  let history = [];

  const lowerBound = () => Math.min(0, viewport.clientWidth - rail.scrollWidth);
  const clamp = (value) => Math.max(lowerBound(), Math.min(0, value));
  const rubberbandDistance = (overshoot) => {
    const dimension = viewport.clientWidth;
    const constant = .55;
    return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot));
  };
  const applyResistance = (value) => {
    const min = lowerBound();
    if (value > 0) return rubberbandDistance(value);
    if (value < min) return min + rubberbandDistance(value - min);
    return value;
  };
  const render = () => {
    rail.style.transform = `translate3d(${position}px, 0, 0)`;
  };
  const settle = (time) => {
    if (!lastFrame) lastFrame = time;
    const dt = Math.min((time - lastFrame) / 1000, .032);
    lastFrame = time;
    const acceleration = (-spring.stiffness * (position - target) - spring.damping * velocity) / spring.mass;
    velocity += acceleration * dt;
    position += velocity * dt;
    render();
    if (Math.abs(target - position) > .1 || Math.abs(velocity) > .1) {
      frame = requestAnimationFrame(settle);
    } else {
      position = target;
      velocity = 0;
      lastFrame = 0;
      render();
    }
  };
  const animateTo = (next, initialVelocity = velocity) => {
    target = clamp(next);
    velocity = initialVelocity;
    lastFrame = 0;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(settle);
  };
  const setInstantly = (next) => {
    cancelAnimationFrame(frame);
    position = clamp(next);
    target = position;
    velocity = 0;
    lastFrame = 0;
    render();
  };
  const project = (initialVelocity, decelerationRate = .99) =>
    (initialVelocity / 1000) * decelerationRate / (1 - decelerationRate);

  viewport.addEventListener('pointerdown', (event) => {
    if (pointerId !== undefined) return;
    pointerId = event.pointerId;
    pressX = event.clientX;
    lastX = event.clientX;
    dragging = false;
    history = [{ x: event.clientX, time: performance.now() }];
    cancelAnimationFrame(frame);
    viewport.setPointerCapture(pointerId);
  });

  viewport.addEventListener('pointermove', (event) => {
    if (event.pointerId !== pointerId) return;
    const deltaFromPress = event.clientX - pressX;
    if (!dragging && Math.abs(deltaFromPress) < 10) return;
    dragging = true;
    const delta = event.clientX - lastX;
    position = applyResistance(position + delta);
    lastX = event.clientX;
    const now = performance.now();
    history.push({ x: event.clientX, time: now });
    history = history.filter((sample) => now - sample.time <= 100);
    render();
  });

  const release = (event) => {
    if (event.pointerId !== pointerId) return;
    viewport.releasePointerCapture(pointerId);
    pointerId = undefined;
    if (!dragging || history.length < 2) {
      animateTo(position, 0);
      return;
    }
    const first = history[0];
    const last = history[history.length - 1];
    const releaseVelocity = (last.x - first.x) / Math.max(last.time - first.time, 1) * 1000;
    animateTo(position + project(releaseVelocity), releaseVelocity);
  };

  viewport.addEventListener('pointerup', release);
  viewport.addEventListener('pointercancel', release);
  viewport.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Home') setInstantly(0);
    else if (event.key === 'End') setInstantly(lowerBound());
    else setInstantly(position + (event.key === 'ArrowLeft' ? 320 : -320));
  });
  window.addEventListener('resize', () => setInstantly(position));
});
