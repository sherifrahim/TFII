import { useCallback, useEffect, useState } from "react";

// Personal display preferences. Stored in this browser only; applied as classes on <html> so every screen follows.
const KEY = "tf_prefs";
export const DEFAULT_PREFS = { density: "comfortable", motion: true, fun: true };

export function readPrefs() {
  try { return { ...DEFAULT_PREFS, ...JSON.parse(localStorage.getItem(KEY) || "{}") }; } catch { return { ...DEFAULT_PREFS }; }
}

export function applyPrefs(p = readPrefs()) {
  const el = document.documentElement;
  el.classList.toggle("density-compact", p.density === "compact");
  el.classList.toggle("no-motion", p.motion === false);
}

export function usePrefs() {
  const [prefs, setPrefs] = useState(readPrefs);
  useEffect(() => {
    const on = () => setPrefs(readPrefs());
    window.addEventListener("tf:prefs", on);
    return () => window.removeEventListener("tf:prefs", on);
  }, []);
  const set = useCallback((patch) => {
    const next = { ...readPrefs(), ...patch };
    try { localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* private mode: applies for this visit only */ }
    applyPrefs(next);
    window.dispatchEvent(new Event("tf:prefs"));
  }, []);
  return [prefs, set];
}
