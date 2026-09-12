const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const finePointer = window.matchMedia('(pointer: fine)').matches;

const revealItems = document.querySelectorAll('.reveal');
if (reduceMotion) {
  revealItems.forEach((item) => item.classList.add('is-visible'));
} else {
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        revealObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.14 });
  revealItems.forEach((item) => revealObserver.observe(item));
}

const showCopyResult = (button, result) => {
  const label = button.querySelector('span:last-child') || button;
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

document.querySelectorAll('[data-stack] .verdict-card').forEach((card) => {
  card.addEventListener('click', () => {
    document.querySelectorAll('[data-stack] .verdict-card').forEach((item) => item.classList.remove('is-active'));
    card.classList.add('is-active');
  });
});

document.querySelectorAll('[data-format]').forEach((format) => {
  format.addEventListener('click', () => {
    document.querySelectorAll('[data-format]').forEach((item) => item.classList.remove('is-selected'));
    format.classList.add('is-selected');
  });
});

document.querySelectorAll('[data-install-tabs]').forEach((panel) => {
  const tabs = [...panel.querySelectorAll('[data-install-command]')];
  const output = panel.querySelector('[data-install-output]');
  const copy = panel.querySelector('[data-install-copy]');

  const select = (tab) => {
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle('is-active', active);
      item.setAttribute('aria-selected', String(active));
    });
    output.textContent = tab.dataset.installCommand;
  };

  tabs.forEach((tab) => tab.addEventListener('click', () => select(tab)));
  copy.addEventListener('click', () => copyText(copy, output.textContent));
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
    const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    links.forEach((link) => link.classList.remove('is-current'));
    const current = linkById.get(visible.target.id);
    if (current) current.classList.add('is-current');
  }, { rootMargin: '-18% 0px -68%', threshold: [0, .2, .5] });
  sections.forEach((section) => sectionObserver.observe(section));
}

if (!reduceMotion && finePointer) {
  document.querySelectorAll('[data-tilt]').forEach((surface) => {
    let frame;
    surface.addEventListener('pointermove', (event) => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const rect = surface.getBoundingClientRect();
        const x = (event.clientX - rect.left) / rect.width - 0.5;
        const y = (event.clientY - rect.top) / rect.height - 0.5;
        surface.style.setProperty('--tilt-x', `${-y * 2.2}deg`);
        surface.style.setProperty('--tilt-y', `${x * 2.2}deg`);
      });
    });
    surface.addEventListener('pointerleave', () => {
      cancelAnimationFrame(frame);
      surface.style.setProperty('--tilt-x', '0deg');
      surface.style.setProperty('--tilt-y', '0deg');
    });
  });

  document.querySelectorAll('.magnetic').forEach((button) => {
    let x = 0;
    let y = 0;
    let targetX = 0;
    let targetY = 0;
    let velocityX = 0;
    let velocityY = 0;
    let frame;

    const animate = () => {
      velocityX = (velocityX + (targetX - x) * .18) * .72;
      velocityY = (velocityY + (targetY - y) * .18) * .72;
      x += velocityX;
      y += velocityY;
      button.style.transform = `translate3d(${x}px,${y}px,0)`;
      if (Math.abs(targetX - x) + Math.abs(targetY - y) + Math.abs(velocityX) + Math.abs(velocityY) > .05) {
        frame = requestAnimationFrame(animate);
      }
    };

    const setTarget = (nextX, nextY) => {
      targetX = nextX;
      targetY = nextY;
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(animate);
    };

    button.addEventListener('pointermove', (event) => {
      const rect = button.getBoundingClientRect();
      setTarget((event.clientX - rect.left - rect.width / 2) * .18, (event.clientY - rect.top - rect.height / 2) * .24);
    });
    button.addEventListener('pointerleave', () => setTarget(0, 0));
  });
}

document.querySelectorAll('[data-drag-rail]').forEach((viewport) => {
  const rail = viewport.querySelector('.situation-rail');
  let position = 0;
  let target = 0;
  let velocity = 0;
  let frame;
  let pointerId;
  let lastX = 0;
  let lastTime = 0;

  const bounds = () => Math.min(0, viewport.clientWidth - rail.scrollWidth);
  const rubberband = (value) => {
    const min = bounds();
    if (value > 0) return value * .22;
    if (value < min) return min + (value - min) * .22;
    return value;
  };
  const render = () => rail.style.setProperty('--rail-x', `${position}px`);
  const settle = () => {
    const min = bounds();
    target = Math.max(min, Math.min(0, target));
    velocity = (velocity + (target - position) * .11) * .78;
    position += velocity;
    render();
    if (Math.abs(target - position) + Math.abs(velocity) > .1) frame = requestAnimationFrame(settle);
  };
  const animateTo = (next) => {
    target = next;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(settle);
  };

  viewport.addEventListener('pointerdown', (event) => {
    if (reduceMotion) return;
    pointerId = event.pointerId;
    viewport.setPointerCapture(pointerId);
    lastX = event.clientX;
    lastTime = performance.now();
    velocity = 0;
    cancelAnimationFrame(frame);
  });
  viewport.addEventListener('pointermove', (event) => {
    if (event.pointerId !== pointerId) return;
    const now = performance.now();
    const delta = event.clientX - lastX;
    position = rubberband(position + delta);
    velocity = delta / Math.max(8, now - lastTime) * 16;
    lastX = event.clientX;
    lastTime = now;
    render();
  });
  const release = (event) => {
    if (event.pointerId !== pointerId) return;
    viewport.releasePointerCapture(pointerId);
    pointerId = undefined;
    animateTo(position + velocity * 12);
  };
  viewport.addEventListener('pointerup', release);
  viewport.addEventListener('pointercancel', release);
  viewport.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Home') animateTo(0);
    else if (event.key === 'End') animateTo(bounds());
    else animateTo(position + (event.key === 'ArrowLeft' ? 320 : -320));
  });
  window.addEventListener('resize', () => animateTo(position));
});
