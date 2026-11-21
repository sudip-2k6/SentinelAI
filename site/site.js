"use strict";

const formats = {
  pe: {
    label: "PE / COFF",
    file: "viewer.exe",
    sections: "6",
    arch: "x86-64",
    entry: "0x00001420",
    accent: [133, 169, 255],
    layers: ["PE header", "Sections", "SHA-256"],
  },
  elf: {
    label: "LINUX ELF",
    file: "viewer.elf",
    sections: "28",
    arch: "x86-64",
    entry: "0x00001050",
    accent: [112, 226, 209],
    layers: ["ELF header", "Sections", "SHA-256"],
  },
};

const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");
const canvas = document.querySelector(".scan-art");
const ctx = canvas.getContext("2d", { alpha: true });
const motionButton = document.querySelector(".motion");
const stageLabel = document.querySelector(".stage-format");
const sampleButtons = [...document.querySelectorAll("[data-sample]")];
const fields = [...document.querySelectorAll("[data-field]")];

let sample = formats.pe;
let paused = reduceMotion.matches;
let inView = false;
let frame = 0;
let lastFrame = 0;
let elapsed = 0;
let width = 0;
let height = 0;
let ratio = 1;

function color(rgb, alpha) {
  return "rgba(" + rgb.join(",") + "," + alpha + ")";
}

function dot(x, y, radius, style) {
  ctx.fillStyle = style;
  ctx.beginPath();
  ctx.arc(x, y, radius, 0, Math.PI * 2);
  ctx.fill();
}

function polyline(points, style, lineWidth = 1) {
  ctx.beginPath();
  ctx.moveTo(points[0][0], points[0][1]);
  for (const [x, y] of points.slice(1)) ctx.lineTo(x, y);
  ctx.strokeStyle = style;
  ctx.lineWidth = lineWidth;
  ctx.stroke();
}

function draw() {
  if (!width || !height || !ctx) return;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const accent = sample.accent;
  const turn = -0.57 + Math.sin(elapsed * 0.57) * 0.16;
  const sine = Math.sin(turn);
  const cosine = Math.cos(turn);
  const unit = Math.min(width / 3.95, height / 2.58);
  const float = Math.sin(elapsed * 1.15) * 3;
  const cx = width * 0.51;
  const cy = height * 0.49 + float;
  const project = (x, y, z) => [
    cx + (x * cosine - z * sine) * unit,
    cy - (y + (x * sine + z * cosine) * 0.46) * unit,
  ];

  for (let n = 0; n < 64; n++) {
    const x = ((n * 263 + 117) % 1019) / 1019 * width;
    const y = ((n * 379 + 101) % 997) / 997 * height;
    dot(x, y, n % 7 === 0 ? 1.2 : 0.62, color(accent, n % 7 === 0 ? 0.43 : 0.16));
  }

  const outline = [[-1.13, -0.68], [0.83, -0.68], [1.13, -0.38], [1.13, 0.68], [-1.13, 0.68]];
  const levels = [-0.61, -0.2, 0.2, 0.61];
  const sweep = 0.62 * Math.sin(elapsed * 0.89);

  for (const [index, level] of levels.entries()) {
    const corners = outline.map(([x, z]) => project(x, level, z));
    const pulse = Math.exp(-Math.abs(sweep - level) * 6);
    const shine = 0.18 + 0.4 * pulse;
    const face = ctx.createLinearGradient(cx - unit, 0, cx + unit, 0);
    face.addColorStop(0, "rgba(20,32,56,.92)");
    face.addColorStop(0.6, color(accent, 0.14 + pulse * 0.12));
    face.addColorStop(1, "rgba(14,22,39,.85)");
    ctx.beginPath();
    for (const [x, y] of corners) ctx.lineTo(x, y);
    ctx.closePath();
    ctx.fillStyle = face;
    ctx.fill();
    ctx.strokeStyle = color(accent, shine + 0.15);
    ctx.lineWidth = 1.05;
    ctx.stroke();

    for (let track = 0; track < 5; track++) {
      const z = -0.45 + track * 0.22;
      const start = -0.95 + (track % 2) * 0.14;
      const end = 0.72 - ((track * 3 + index) % 5) * 0.17;
      polyline([project(start, level, z), project(end, level, z)], color(accent, shine * 0.55));
      for (let part = 0; part < 13; part++) {
        const x = start + (end - start) * part / 12;
        const [px, py] = project(x, level, z);
        const bright = (part * 11 + track * 7 + index * 9) % 8 < 2;
        dot(px, py, bright ? 1.45 : 0.8, color(accent, bright ? 0.7 : shine));
      }
    }
    for (const [x, y] of corners) dot(x, y, 2, color(accent, shine + 0.26));
  }

  const scan = [project(-1.21, sweep, 0.71), project(1.21, sweep, 0.71)];
  ctx.shadowBlur = 12;
  ctx.shadowColor = color(accent, 0.8);
  polyline(scan, color(accent, 0.85), 1.6);
  ctx.shadowBlur = 0;
  for (const [x, y] of scan) dot(x, y, 2.6, color(accent, 0.92));

  const narrow = width < 490;
  const guide = (target, x, y, title, fromLeft) => {
    const inset = fromLeft ? 0 : -37;
    polyline([target, [x + inset, y + 6], [x + inset + 36, y + 6]], color(accent, 0.42));
    dot(target[0], target[1], 2.8, color(accent, 0.95));
    ctx.font = (narrow ? "10px" : "12px") + " Consolas, monospace";
    ctx.textAlign = fromLeft ? "left" : "right";
    ctx.fillStyle = "#d0defa";
    ctx.fillText(title, x, y);
  };
  guide(project(-1.02, levels[3], 0.65), narrow ? 13 : 24, height * 0.24, sample.layers[0], true);
  guide(project(1.08, levels[2], -0.3), width - (narrow ? 13 : 24), height * 0.18, sample.layers[1], false);
  if (!narrow) guide(project(1.06, levels[0], 0.6), width - 24, height * 0.78, sample.layers[2], false);
}

function syncMotion() {
  motionButton.textContent = paused ? "Play motion" : "Pause motion";
  if (!paused && inView && !document.hidden && !frame) {
    frame = requestAnimationFrame(tick);
  } else if (paused || !inView || document.hidden) {
    cancelAnimationFrame(frame);
    frame = 0;
    lastFrame = 0;
  }
}

function tick(now) {
  if (lastFrame) elapsed += Math.min((now - lastFrame) / 1000, 0.06);
  lastFrame = now;
  draw();
  frame = requestAnimationFrame(tick);
}

function resize() {
  width = canvas.clientWidth;
  height = canvas.clientHeight;
  ratio = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  draw();
}

for (const button of sampleButtons) {
  button.addEventListener("click", () => {
    sample = formats[button.dataset.sample];
    for (const option of sampleButtons) option.setAttribute("aria-pressed", String(option === button));
    for (const field of fields) field.textContent = sample[field.dataset.field];
    stageLabel.textContent = sample.label;
    draw();
  });
}

if (ctx) {
  motionButton.hidden = false;
  motionButton.addEventListener("click", () => {
    paused = !paused;
    syncMotion();
  });
  reduceMotion.addEventListener("change", () => {
    paused = reduceMotion.matches;
    syncMotion();
  });
  document.addEventListener("visibilitychange", syncMotion);
  new ResizeObserver(resize).observe(canvas);
  new IntersectionObserver(([entry]) => {
    inView = entry.isIntersecting;
    syncMotion();
  }).observe(canvas);
  resize();
  syncMotion();
}

if (!reduceMotion.matches && "IntersectionObserver" in window) {
  const reveal = new IntersectionObserver((entries, observer) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        entry.target.classList.remove("is-waiting");
        observer.unobserve(entry.target);
      }
    }
  }, { threshold: 0.1 });
  for (const section of document.querySelectorAll(".reveal")) {
    if (section.getBoundingClientRect().top >= window.innerHeight) section.classList.add("is-waiting");
    reveal.observe(section);
  }
}
