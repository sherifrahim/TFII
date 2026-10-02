// A tab that has been open across a deploy keeps running the old JavaScript: a fix that is live on the server
// looks "still broken" until the page is reloaded. Compare the bundle this tab is running with what the server
// serves now, and offer a reload when they differ.
import { useEffect, useState } from "react";

const MAIN = /static\/js\/(main\.[\w-]+\.js)/;

// The main bundle this page was loaded with (null in dev, or if it cannot be told).
export function runningBundle(scripts) {
  for (const s of scripts || []) {
    const m = MAIN.exec((s && s.getAttribute ? s.getAttribute("src") : s) || "");
    if (m) return m[1];
  }
  return null;
}

// The main bundle named by the index.html the server serves now.
export function servedBundle(html) {
  const m = MAIN.exec(html || "");
  return m ? m[1] : null;
}

export function isStale(running, served) {
  return !!running && !!served && running !== served;
}

export function useNewVersion() {
  const [stale, setStale] = useState(false);
  useEffect(() => {
    const running = runningBundle(Array.from(document.scripts));
    if (!running) return undefined;                       // dev server: nothing to compare
    let alive = true;
    const check = async () => {
      if (document.hidden) return;
      try {
        const r = await fetch(window.location.pathname, { cache: "no-store", credentials: "omit" });
        if (r.ok && alive && isStale(running, servedBundle(await r.text()))) setStale(true);
      } catch { /* offline or blocked: try again later */ }
    };
    check();
    const t = setInterval(check, 10 * 60 * 1000);
    document.addEventListener("visibilitychange", check);
    return () => { alive = false; clearInterval(t); document.removeEventListener("visibilitychange", check); };
  }, []);
  return stale;
}
