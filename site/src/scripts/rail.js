const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
document.querySelectorAll("[data-drag-rail]").forEach((viewport) => {
  const rail = viewport.querySelector(".situation-rail");
  const nativeScroll = window.matchMedia("(max-width: 640px)").matches || reduceMotion;
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
    const constant = 0.55;
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
    const dt = Math.min((time - lastFrame) / 1000, 0.032);
    lastFrame = time;
    const acceleration = (-spring.stiffness * (position - target) - spring.damping * velocity) / spring.mass;
    velocity += acceleration * dt;
    position += velocity * dt;
    render();
    if (Math.abs(target - position) > 0.1 || Math.abs(velocity) > 0.1) {
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
  const project = (initialVelocity, decelerationRate = 0.99) => ((initialVelocity / 1000) * decelerationRate) / (1 - decelerationRate);

  viewport.addEventListener("pointerdown", (event) => {
    if (pointerId !== undefined) return;
    pointerId = event.pointerId;
    pressX = event.clientX;
    lastX = event.clientX;
    dragging = false;
    history = [{ x: event.clientX, time: performance.now() }];
    cancelAnimationFrame(frame);
    viewport.setPointerCapture(pointerId);
  });

  viewport.addEventListener("pointermove", (event) => {
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
    const releaseVelocity = ((last.x - first.x) / Math.max(last.time - first.time, 1)) * 1000;
    animateTo(position + project(releaseVelocity), releaseVelocity);
  };

  viewport.addEventListener("pointerup", release);
  viewport.addEventListener("pointercancel", release);
  viewport.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    if (event.key === "Home") setInstantly(0);
    else if (event.key === "End") setInstantly(lowerBound());
    else setInstantly(position + (event.key === "ArrowLeft" ? 320 : -320));
  });
  window.addEventListener("resize", () => setInstantly(position));
});
