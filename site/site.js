const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const revealItems = document.querySelectorAll('.reveal');
if (reduceMotion) {
  revealItems.forEach((item) => item.classList.add('is-visible'));
} else {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.14 });
  revealItems.forEach((item) => observer.observe(item));
}

document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    const label = button.querySelector('span:last-child') || button;
    const original = label.textContent;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      label.textContent = 'Copied';
    } catch {
      label.textContent = 'Select and copy';
    }
    window.setTimeout(() => { label.textContent = original; }, 1600);
  });
});

document.querySelectorAll('[data-stack] .verdict-card').forEach((card) => {
  card.addEventListener('pointerdown', () => {
    document.querySelectorAll('[data-stack] .verdict-card').forEach((item) => item.classList.remove('is-active'));
    card.classList.add('is-active');
  });
});

document.querySelectorAll('[data-format]').forEach((format) => {
  format.addEventListener('pointerdown', () => {
    document.querySelectorAll('[data-format]').forEach((item) => item.classList.remove('is-selected'));
    format.classList.add('is-selected');
  });
});

const docsSearch = document.querySelector('#docs-search');
if (docsSearch) {
  const sections = [...document.querySelectorAll('.docs-searchable')];
  const empty = document.querySelector('#docs-empty');
  docsSearch.addEventListener('input', () => {
    const query = docsSearch.value.trim().toLowerCase();
    let visibleCount = 0;
    sections.forEach((section) => {
      const text = (section.dataset.search + ' ' + section.textContent).toLowerCase();
      const matches = !query || text.includes(query);
      section.hidden = !matches;
      if (matches) visibleCount += 1;
    });
    empty.hidden = visibleCount !== 0;
  });
}

if (!reduceMotion && window.matchMedia('(pointer: fine)').matches) {
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
}
