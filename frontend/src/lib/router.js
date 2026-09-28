import React, { useEffect, useState } from "react";

// Hash routing (#/ioc/indicator--…). The app is served from /ui/ by nginx and
// the backend owns every other path, so hash routes give real deep links and
// back/forward navigation without any server change or router dependency.

function parse() {
  const raw = window.location.hash.replace(/^#/, "") || "/";
  const [pathPart, queryPart = ""] = raw.split("?");
  const path = pathPart.startsWith("/") ? pathPart : `/${pathPart}`;
  const query = Object.fromEntries(new URLSearchParams(queryPart));
  const segments = path.split("/").filter(Boolean).map(s => {
    try { return decodeURIComponent(s); } catch { return s; }
  });
  return { path, query, segments };
}

export function useRoute() {
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const on = () => setRoute(parse());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export function href(path, query) {
  const q = query ? new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined && v !== null && v !== "")).toString() : "";
  return `#${path}${q ? `?${q}` : ""}`;
}

export function navigate(path, query, { replace = false } = {}) {
  const target = href(path, query);
  if (replace) {
    window.history.replaceState(null, "", target);
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  } else if (window.location.hash !== target) {
    window.location.hash = target.slice(1);
  }
}

// Update query params of the current route without adding history entries —
// used for table filters so the URL is shareable but Back is not polluted.
export function setQuery(patch) {
  const { path, query } = parse();
  navigate(path, { ...query, ...patch }, { replace: true });
}

export const enc = encodeURIComponent;

export function Link({ to, query, children, className, style, title, onClick, stop }) {
  return (
    <a href={href(to, query)} className={className} style={style} title={title}
      onClick={e => { if (stop) e.stopPropagation(); onClick && onClick(e); }}>
      {children}
    </a>
  );
}

// Canonical routes for entity kinds, shared by search, graph and tables.
export function entityRoute(kind, ref) {
  switch (kind) {
    case "ioc": return `/ioc/${enc(ref)}`;
    case "observable": return `/observable/${enc(ref)}`;
    case "cve": return `/cve/${enc(ref)}`;
    case "campaign": return `/campaigns/${enc(ref)}`;
    case "actor": return `/actors/${enc(ref)}`;
    case "malware": return `/malware/${enc(ref)}`;
    case "software": case "asset": return `/software/${enc(ref)}`;
    case "investigation": return `/investigations/${enc(ref)}`;
    default: return "/";
  }
}
