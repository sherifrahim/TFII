// Third-party data (feed items, NVD references, MITRE links, enrichment links)
// must never become a clickable non-http(s) URL — `javascript:` in an <a href>
// executes in the app's origin, where the session token lives.
export function safeUrl(u) {
  if (typeof u !== "string") return undefined;
  const s = u.trim();
  // eslint-disable-next-line no-control-regex
  if (!s || s.length > 2048 || /[\s\u0000-\u001f]/.test(s)) return undefined;
  try {
    const p = new URL(s);
    return (p.protocol === "http:" || p.protocol === "https:") && p.hostname ? s : undefined;
  } catch {
    return undefined;
  }
}

// Defence in depth for the legacy components, which render data-driven hrefs
// in many places: refuse to follow any anchor that is not http(s), mailto or an
// in-app hash link.
export function installLinkGuard() {
  const h = e => {
    const a = e.target && e.target.closest && e.target.closest("a[href]");
    if (!a) return;
    const href = a.getAttribute("href") || "";
    if (href.startsWith("#") || href.startsWith("/")) return;
    if (!/^(https?:|mailto:)/i.test(href.trim())) {
      e.preventDefault();
      e.stopPropagation();
    }
  };
  document.addEventListener("click", h, true);
  document.addEventListener("auxclick", h, true);
  return () => {
    document.removeEventListener("click", h, true);
    document.removeEventListener("auxclick", h, true);
  };
}
