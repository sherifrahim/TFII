import { useEffect, useRef } from "react";
import { useToast } from "../components/ui";
import { readPrefs } from "../lib/prefs";

// Small, tasteful surprises. None of it touches data, all of it is skipped for people who ask their system
// for reduced motion, and nothing here is needed to use the product.

const reduced = () => typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Five quick clicks on the logo.
let clicks = [];
export function logoClicked() {
  const now = Date.now();
  clicks = [...clicks.filter(t => now - t < 1800), now];
  if (clicks.length >= 5) {
    clicks = [];
    window.dispatchEvent(new CustomEvent("tf:egg", { detail: "logo" }));
    return true;
  }
  return false;
}

const LINES = [
  "Threat level: delightfully low.",
  "You found the signal in the noise.",
  "No indicators of compromise. Just indicators of curiosity.",
  "Shields up. Coffee on.",
];

// Commands the palette answers to (typed exactly), each fires one named effect.
export const EGG_COMMANDS = {
  matrix: ["Enter the matrix", "matrix"],
  disco: ["Disco mode", "disco"],
  party: ["Confetti", "confetti"],
  confetti: ["Confetti", "confetti"],
  snap: ["Perfectly balanced", "snap"],
  coffee: ["Brew coffee", "coffee"],
  sudo: ["sudo make me an admin", "sudo"],
  hack: ["Hack the planet", "matrix"],
  "42": ["The answer", "answer"],
};
export function eggFor(q) {
  const k = String(q || "").trim().toLowerCase().replace(/^[!/>]/, "");
  return EGG_COMMANDS[k] ? { key: k, label: EGG_COMMANDS[k][0], effect: EGG_COMMANDS[k][1] } : null;
}
export function fireEgg(effect) { window.dispatchEvent(new CustomEvent("tf:egg", { detail: effect })); }

function runMatrix(canvas, ms = 6500) {
  const ctx = canvas.getContext("2d");
  const w = (canvas.width = window.innerWidth), h = (canvas.height = window.innerHeight);
  const size = 16, cols = Math.ceil(w / size);
  const drops = Array.from({ length: cols }, () => Math.random() * -40);
  const chars = "TFII01アイウエオカキクケコ#$%<>/ABCDEF".split("");
  const t0 = performance.now();
  let raf;
  const draw = t => {
    const age = t - t0;
    ctx.fillStyle = "rgba(5,6,10,.14)";
    ctx.fillRect(0, 0, w, h);
    ctx.font = `${size}px 'JetBrains Mono Variable', monospace`;
    drops.forEach((y, i) => {
      const c = chars[(Math.random() * chars.length) | 0];
      ctx.fillStyle = Math.random() > .96 ? "#ffffff" : "#5EEAD4";
      ctx.fillText(c, i * size, y * size);
      drops[i] = y * size > h && Math.random() > .975 ? 0 : y + 1;
    });
    canvas.style.opacity = String(Math.max(0, Math.min(.85, (ms - age) / 1200)));
    if (age < ms) raf = requestAnimationFrame(draw);
    else canvas.remove();
  };
  raf = requestAnimationFrame(draw);
  return () => { cancelAnimationFrame(raf); canvas.remove(); };
}

function runConfetti(canvas, ms = 2600) {
  const ctx = canvas.getContext("2d");
  const w = (canvas.width = window.innerWidth), h = (canvas.height = window.innerHeight);
  const colors = ["#5EEAD4", "#7AA2FF", "#A78BFA", "#FFB020", "#FF5C6C", "#F3F6FB"];
  const ps = Array.from({ length: 150 }, () => ({ x: w / 2 + (Math.random() - .5) * 120, y: h * .62, vx: (Math.random() - .5) * 16, vy: -Math.random() * 17 - 5,
    s: Math.random() * 7 + 4, c: colors[(Math.random() * colors.length) | 0], r: Math.random() * 6, vr: (Math.random() - .5) * .4 }));
  const t0 = performance.now();
  let raf;
  const draw = t => {
    ctx.clearRect(0, 0, w, h);
    ps.forEach(p => {
      p.vy += .42; p.x += p.vx; p.y += p.vy; p.r += p.vr; p.vx *= .992;
      ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(p.r); ctx.fillStyle = p.c; ctx.fillRect(-p.s / 2, -p.s / 4, p.s, p.s / 2); ctx.restore();
    });
    if (t - t0 < ms) raf = requestAnimationFrame(draw); else canvas.remove();
  };
  raf = requestAnimationFrame(draw);
  return () => { cancelAnimationFrame(raf); canvas.remove(); };
}

export function Eggs() {
  const toast = useToast();
  const seq = useRef([]);
  const stop = useRef(null);

  useEffect(() => {
    // For anyone who opens the console.
    if (!window.__tfii_hello) {
      window.__tfii_hello = true;
      try {
        console.log("%c TFII ", "background:linear-gradient(135deg,#5EEAD4,#A78BFA);color:#03130F;font-weight:800;font-size:16px;border-radius:6px;padding:4px 8px", "threat intelligence that shows its work.");
        console.log("%cLooking for bugs? SECURITY.md has the private way to tell us. Looking for fun? Try the Konami code.", "color:#8C95A8");
      } catch { /* console may be locked down */ }
    }
  }, []);

  useEffect(() => {
    const prev = document.title;
    const onBlur = () => { document.title = "👀 TFII · still watching"; };
    const onFocus = () => { document.title = prev; };
    window.addEventListener("blur", onBlur); window.addEventListener("focus", onFocus);
    return () => { window.removeEventListener("blur", onBlur); window.removeEventListener("focus", onFocus); document.title = prev; };
  }, []);

  useEffect(() => {
    const KONAMI = ["arrowup", "arrowup", "arrowdown", "arrowdown", "arrowleft", "arrowright", "arrowleft", "arrowright", "b", "a"];
    const onKey = e => {
      const t = e.target;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      seq.current = [...seq.current, String(e.key).toLowerCase()].slice(-KONAMI.length);
      if (seq.current.join() === KONAMI.join()) { seq.current = []; window.dispatchEvent(new CustomEvent("tf:egg", { detail: "matrix" })); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const overlay = kind => {
      const c = document.createElement("canvas");
      c.className = "matrix-canvas";
      c.setAttribute("aria-hidden", "true");
      document.body.appendChild(c);
      if (stop.current) stop.current();
      stop.current = kind === "matrix" ? runMatrix(c) : runConfetti(c);
    };
    const on = e => {
      if (readPrefs().fun === false) return;           // turned off under Settings → Display
      const k = e.detail;
      if (k === "matrix") { toast("Wake up. The signal has you.", "ok"); if (!reduced()) overlay("matrix"); }
      else if (k === "confetti") { toast("🎉 Nothing to celebrate, and yet.", "ok"); if (!reduced()) overlay("confetti"); }
      else if (k === "logo") { toast(LINES[(Math.random() * LINES.length) | 0], "ok"); if (!reduced()) overlay("confetti"); }
      else if (k === "disco") {
        toast("Disco mode. Reload to stop.", "ok");
        document.documentElement.classList.add("disco");
        setTimeout(() => document.documentElement.classList.remove("disco"), 9000);
      } else if (k === "snap") {
        toast("Perfectly balanced, as all things should be.", "ok");
        const els = [...document.querySelectorAll(".panel, .kpi, .tool-card")].filter(() => Math.random() > .5);
        els.forEach(el => el.classList.add("snap-away"));
        setTimeout(() => els.forEach(el => el.classList.remove("snap-away")), 2800);
      } else if (k === "coffee") toast("☕ Brewing… ERROR 418: this server is a teapot.", "info");
      else if (k === "sudo") toast("Nice try. This incident will be reported. (To nobody. We checked.)", "info");
      else if (k === "answer") toast("42: the number of indicators it takes to feel productive.", "info");
    };
    window.addEventListener("tf:egg", on);
    return () => { window.removeEventListener("tf:egg", on); if (stop.current) stop.current(); };
  }, [toast]);

  return null;
}
