const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
document.documentElement.classList.add('has-js');

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
    const fallback = document.createElement('textarea');
    fallback.value = value;
    fallback.setAttribute('readonly', '');
    fallback.style.position = 'fixed';
    fallback.style.opacity = '0';
    document.body.appendChild(fallback);
    fallback.select();
    const copied = document.execCommand('copy');
    fallback.remove();
    showCopyResult(button, copied ? 'Copied' : 'Select and copy');
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
  const sidebarNav = document.querySelector('.docs-sidebar nav');
  sidebarNav?.addEventListener('keydown', (event) => {
    if (sidebarNav.scrollHeight <= sidebarNav.clientHeight || event.altKey || event.ctrlKey || event.metaKey) return;
    const distance = {
      ArrowUp: -40, ArrowDown: 40,
      PageUp: -sidebarNav.clientHeight, PageDown: sidebarNav.clientHeight,
      Home: -sidebarNav.scrollHeight, End: sidebarNav.scrollHeight,
    }[event.key];
    if (distance === undefined) return;
    event.preventDefault();
    sidebarNav.scrollBy({ top: distance, behavior: 'instant' });
  });
  const linkById = new Map(links.map((link) => [link.hash.slice(1), link]));
  const markCurrent = (current) => {
    links.forEach((link) => {
      link.classList.toggle('is-current', link === current);
      if (link === current) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    });
  };
  links.forEach((link) => {
    link.addEventListener('click', () => markCurrent(link));
  });
  const sectionObserver = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    markCurrent(linkById.get(visible.target.id));
  }, { rootMargin: '-18% 0px -68%', threshold: [0, .2, .5] });
  sections.forEach((section) => sectionObserver.observe(section));
}

const docsGlobalIndex = [
  ['docs.html','Documentation','overview','Overview','overview scanner read only guides'],
  ['docs.html','Documentation','getting-started','Run your first scan','getting started install first scan local folder html git'],
  ['docs.html','Documentation','recipes','Copyable starting points','examples local remote powershell docker json sarif targets'],
  ['docs.html','Documentation','verdicts-docs','Read the result','verdict findings no findings review required do not run incomplete exit code'],
  ['docs.html','Documentation','reports-docs','Choose a report','terminal json sarif html report output offline file'],
  ['docs.html','Documentation','privacy','Know the boundary','privacy network credentials telemetry upload'],
  ['docs.html','Documentation','intelligence','What “intel” means','intel intelligence indicators packages hashes snapshot status update rollback'],
  ['docs.html','Documentation','agent-skill-docs','Give your coding agent a safe first step','agent skill codex instructions workflow'],
  ['docs.html','Documentation','limits-docs','When coverage is incomplete','limits timeout files archive incomplete coverage'],
  ['installation.html','Installation','overview','Installation','install first scan binary'],
  ['installation.html','Installation','prerequisites','Prerequisites','git docker browser macos linux windows'],
  ['installation.html','Installation','macos-linux','Install on macOS and Linux','homebrew archive deb rpm apk go path'],
  ['installation.html','Installation','windows','Install on Windows PowerShell','windows powershell scoop zip path'],
  ['installation.html','Installation','checksums','Verify the release','checksum sha256 signed binary'],
  ['installation.html','Installation','first-scan','Run a first local scan','local html report intel status'],
  ['installation.html','Installation','remote','Scan a remote repository','remote github gitlab bitbucket https ssh token'],
  ['installation.html','Installation','troubleshooting','Troubleshoot the first run','command not found permission timeout html'],
  ['cli.html','CLI reference','overview','CLI reference','commands flags scan report rules intelligence'],
  ['cli.html','CLI reference','shape','Command shape','syntax subcommands targets path url'],
  ['cli.html','CLI reference','first-scan','Run a first scan','local remote folder git'],
  ['cli.html','CLI reference','targets','Targets and target files','multiple file jobs history clone'],
  ['cli.html','CLI reference','scan-flags','All scan flags','format output config dependencies sandbox fail timeout detail progress severity confidence'],
  ['cli.html','CLI reference','recipes','Copyable scan recipes','html json sarif ci docker'],
  ['cli.html','CLI reference','reports','Choose a report format','terminal json sarif html'],
  ['cli.html','CLI reference','report-command','Render a saved JSON report','report stdin filters'],
  ['cli.html','CLI reference','rules','Rules commands','validate check list explain'],
  ['cli.html','CLI reference','intel','Intelligence commands','intel status update rollback snapshot'],
  ['cli.html','CLI reference','exit-codes','Exit codes and verdicts','zero one two three incomplete threshold'],
  ['cli.html','CLI reference','troubleshooting','Troubleshooting','git docker incomplete'],
  ['configuration.html','Configuration','overview','Configuration','trusted yaml custom rules suppressions'],
  ['configuration.html','Configuration','boundary','Understand the trust boundary','repository config trust'],
  ['configuration.html','Configuration','minimal','Start with valid YAML','version rules yaml'],
  ['configuration.html','Configuration','workflow','Use the safe workflow','validate scan config'],
  ['configuration.html','Configuration','rule-fields','Custom rule fields','severity confidence pattern globs rationale'],
  ['configuration.html','Configuration','rule-walkthrough','Walk through a custom rule','regex example'],
  ['configuration.html','Configuration','scope','Choose the matching scope','raw code structured'],
  ['configuration.html','Configuration','suppressions','Suppress one reviewed finding','fingerprint reason expires'],
  ['configuration.html','Configuration','review-example','Review example','finding exception'],
  ['configuration.html','Configuration','limits','Limits and validation errors','invalid regex exit code 3'],
  ['coverage.html','Detection coverage','overview','Detection coverage','rules detection limits'],
  ['coverage.html','Detection coverage','map','Coverage map','execution obfuscation dependencies secrets network shells mining ci containers git'],
  ['coverage.html','Detection coverage','precision','How repyy improves precision','context scope correlation confidence'],
  ['coverage.html','Detection coverage','limits','Coverage has a boundary','timeout max files archive incomplete'],
  ['coverage.html','Detection coverage','exclusions','Deliberate exclusions','generated lockfiles offline privacy'],
  ['coverage.html','Detection coverage','explain','Explain a rule before acting','rules explain rationale'],
  ['coverage.html','Detection coverage','list','Inspect the active intelligence','rules list snapshot packages hashes'],
  ['coverage.html','Detection coverage','workflow','A practical review workflow','evidence verdict report'],
  ['isolation.html','Isolation','overview','Isolation','docker vm sandbox network read only'],
  ['isolation.html','Isolation','docker','Docker release image','sandbox digest signed image'],
  ['isolation.html','Isolation','docker-image','Verify the image signature','cosign sigstore checksum'],
  ['isolation.html','Isolation','local','Docker with a local folder','mount networking disabled json'],
  ['isolation.html','Isolation','https','Docker with an HTTPS remote','fetch credentials git'],
  ['isolation.html','Isolation','edge-cases','Know the edge cases','incomplete timeout ssh keep workdir'],
  ['isolation.html','Isolation','vm','Manual VM workflows','windows macos linux guest'],
  ['isolation.html','Isolation','windows-sandbox','Windows Sandbox','wsb powershell mapped folders'],
  ['isolation.html','Isolation','utm','macOS with UTM','macos vm read only'],
  ['isolation.html','Isolation','qemu','Linux with QEMU/KVM','linux qemu kvm'],
  ['intelligence.html','Intelligence','overview','Intelligence','intel threat offline snapshot packages hashes'],
  ['intelligence.html','Intelligence','difference','Rules and intelligence work together','built in rules indicators versions'],
  ['intelligence.html','Intelligence','status','Check before you scan','status freshness verification cache'],
  ['intelligence.html','Intelligence','update','Update only when you choose to','update download ed25519 signature'],
  ['intelligence.html','Intelligence','rollback','Roll back a cached update','rollback previous cache'],
  ['intelligence.html','Intelligence','investigate','Investigate an indicator','rules explain list check advisory hash'],
  ['agent-skill.html','Agent skill','overview','Optional agent skill','instructions codex scan read only'],
  ['agent-skill.html','Agent skill','install','Install the skill','npx skills add global interactive'],
  ['agent-skill.html','Agent skill','workflow','What the skill tells an agent to do','workflow json html verdict incomplete'],
  ['agent-skill.html','Agent skill','docker','Use Docker when you need a process boundary','docker sandbox digest ssh'],
  ['agent-skill.html','Agent skill','limits','Understand the limits','privacy target execute build test upload intel'],
];
const docsSearchInput = document.querySelector('#docs-search');
if (docsSearchInput) {
  const box = docsSearchInput.closest('.docs-search');
  const results = document.createElement('div');
  results.className = 'docs-search-results';
  results.id = 'docs-search-results';
  results.setAttribute('role', 'region');
  results.setAttribute('aria-label', 'Documentation search results');
  results.hidden = true;
  box?.appendChild(results);
  docsSearchInput.setAttribute('aria-controls', results.id);
  docsSearchInput.setAttribute('aria-expanded', 'false');
  const render = () => {
    const query = docsSearchInput.value.trim().toLowerCase();
    results.replaceChildren();
    if (!query) { results.hidden = true; docsSearchInput.setAttribute('aria-expanded', 'false'); return; }
    const matches = docsGlobalIndex.filter((item) => query.split(/\s+/).every((word) => item.slice(1).join(' ').toLowerCase().includes(word)));
    if (!matches.length) { const message = document.createElement('p'); message.className = 'docs-search-empty'; message.textContent = 'No documentation matches that search.'; results.appendChild(message); }
    matches.slice(0, 30).forEach(([page, pageTitle, id, title]) => { const link = document.createElement('a'); link.href = page + '#' + id; const heading = document.createElement('strong'); heading.textContent = title; const location = document.createElement('small'); location.textContent = pageTitle; link.append(heading, location); results.appendChild(link); });
    if (matches.length) { const count = document.createElement('p'); count.className = 'docs-search-count'; count.textContent = matches.length > 30 ? 'Showing 30 of ' + matches.length + ' matches' : matches.length + (matches.length === 1 ? ' match' : ' matches'); results.appendChild(count); }
    results.hidden = false; docsSearchInput.setAttribute('aria-expanded', 'true');
    const localEmpty = document.querySelector('#docs-empty'); if (localEmpty) localEmpty.hidden = true;
  };
  docsSearchInput.addEventListener('input', render);
  docsSearchInput.addEventListener('focus', () => { if (docsSearchInput.value.trim()) render(); });
  docsSearchInput.addEventListener('keydown', (event) => { if (event.key === 'ArrowDown' && !results.hidden) { event.preventDefault(); results.querySelector('a')?.focus(); } });
  results.addEventListener('keydown', (event) => { const links = [...results.querySelectorAll('a')]; const index = links.indexOf(document.activeElement); if (event.key === 'ArrowDown' && index >= 0) { event.preventDefault(); links[Math.min(index + 1, links.length - 1)]?.focus(); } if (event.key === 'ArrowUp') { event.preventDefault(); index <= 0 ? docsSearchInput.focus() : links[index - 1]?.focus(); } if (event.key === 'Escape') { event.preventDefault(); docsSearchInput.value = ''; docsSearchInput.dispatchEvent(new Event('input')); docsSearchInput.focus(); } });
  document.addEventListener('pointerdown', (event) => { if (!box?.contains(event.target)) { results.hidden = true; docsSearchInput.setAttribute('aria-expanded', 'false'); } });
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
