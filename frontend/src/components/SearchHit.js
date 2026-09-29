import React from "react";
import { Badge, TypeBadge, SevBadge, StatusBadge, Conf } from "./ui";
import { KINDS, entityPath } from "../lib/entity";
import { timeAgo } from "../lib/format";

// Where a search hit leads. Search is provider-driven on the server, so a new
// entity kind needs no change here beyond its entry in lib/entity.js.
export function hitRoute(h) {
  if (h.kind === "note") return [h.investigation_id ? `/investigations/${encodeURIComponent(h.investigation_id)}` : "/workspace", { tab: "notes" }];
  return [entityPath(h.kind, h.ref) || "/", undefined];
}

// Kind-specific decoration next to the title. Unknown kinds render title only.
export function HitBadges({ h }) {
  switch (h.kind) {
    case "indicator": return <>
      <TypeBadge type={h.type} />
      {h.malware_family && <Badge tone="violet">{h.malware_family}</Badge>}
    </>;
    case "cve": return <>{h.kev && <Badge tone="critical">KEV</Badge>}<SevBadge severity={h.severity} score={h.cvss} /></>;
    case "investigation": return h.key ? <span className="mono faint xs">{h.key}</span> : null;
    default: return null;
  }
}

export function HitTail({ h }) {
  if (h.kind === "indicator") return <><Conf value={h.confidence} /><StatusBadge status={h.status} /><span className="faint xs" style={{ width: 64, textAlign: "right" }}>{timeAgo(h.created_at)}</span></>;
  return null;
}

export const hitIcon = h => (KINDS[h.kind] || KINDS.note).icon;
