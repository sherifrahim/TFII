// Entity kinds as the backend's entity model defines them (backend/entities.py).
// One place for labels, icons and routes so every list, graph, search hit and
// relationship row speaks the same language.
const enc = encodeURIComponent;

export const KINDS = {
  indicator: { label: "Indicator", plural: "Indicators", icon: "crosshair", tone: "gold" },
  cve: { label: "Vulnerability", plural: "CVEs", icon: "shieldAlert", tone: "critical" },
  malware: { label: "Malware family", plural: "Malware", icon: "bug", tone: "violet" },
  actor: { label: "Threat actor", plural: "Threat actors", icon: "skull", tone: "critical" },
  campaign: { label: "Campaign", plural: "Campaigns", icon: "flag", tone: "high" },
  software: { label: "Software", plural: "Software", icon: "package", tone: "medium" },
  investigation: { label: "Investigation", plural: "Investigations", icon: "briefcase", tone: "gold" },
  source: { label: "Source", plural: "Sources", icon: "rss", tone: "low" },
  note: { label: "Note", plural: "Notes", icon: "note", tone: "low" },
};

// Legacy kind names used by older code paths.
const ALIAS = { ioc: "indicator", observable: "indicator", asset: "software" };
export const canonicalKind = k => ALIAS[k] || k;

// Where an entity lives. `inv` carries workspace context so the page can say
// "relevant because…" and offer a way back.
export function entityPath(kind, ref, inv) {
  const k = canonicalKind(kind);
  const q = inv ? `?inv=${enc(inv)}` : "";
  switch (k) {
    case "indicator": return `/observable/${enc(ref)}${q}`;
    case "cve": return `/cve/${enc(ref)}${q}`;
    case "campaign": return `/campaigns/${enc(ref)}${q}`;
    case "actor": return `/actors/${enc(ref)}${q}`;
    case "malware": return `/malware/${enc(ref)}${q}`;
    case "software": return `/software/${enc(ref)}${q}`;
    case "investigation": return `/investigations/${enc(ref)}`;
    default: return null;                 // sources have no page of their own
  }
}

