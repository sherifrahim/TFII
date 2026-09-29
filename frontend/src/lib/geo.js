// Location facts from /iocs/bulk-lookup, each labelled with what it is. A bare country next to a domain reads as
// "where it comes from"; what TFII actually knows is where its web host is (or that a CDN hides that), and the
// registry country of a country-code TLD, which is only a hint.
import { timeAgo } from "./format";

export function regionName(code) {
  if (!code || typeof code !== "string") return "";
  try { return new Intl.DisplayNames(["en"], { type: "region" }).of(code.toUpperCase()) || code; }
  catch { return code; }
}

// -> [{ label, value, tone: "primary" | "muted" | "warn", title }]
export function geoFacts(geo) {
  if (!geo) return [];
  const out = [];
  const names = (geo.countries && geo.countries.length ? geo.countries.map(c => c.name || regionName(c.code)) : [geo.country]).filter(Boolean);
  if (geo.kind === "ip" && geo.country) {
    out.push({ label: "IP location", value: geo.country, tone: "primary", title: geo.note });
  } else if (geo.kind === "hosting" && names.length) {
    out.push({ label: "Hosted in", value: names.join(", "), tone: "primary", title: geo.note });
  } else if (geo.kind === "cdn_edge") {
    out.push({ label: "Behind CDN", value: `${geo.cdn} — the real host is hidden`, tone: "warn", title: geo.note });
    // Still shown, but for what it is: the CDN node nearest to TFII's server, not where the site is.
    if (geo.edge_country) out.push({ label: "CDN edge node", value: geo.edge_country, tone: "muted", title: "Where the CDN node that answered is. It follows the asker, so it says nothing about where the site is hosted." });
  } else if (geo.kind === undefined && geo.country) {           // an older cached response: no label to add
    out.push({ label: "Location", value: geo.country, tone: "primary" });
  }
  if (geo.cctld_country_code) {
    out.push({ label: "TLD registry", value: `${regionName(geo.cctld_country_code)} (.${String(geo.cctld_country_code).toLowerCase() === "gb" ? "uk" : String(geo.cctld_country_code).toLowerCase()})`,
      tone: "muted", title: "The country that runs this top-level domain. Registrants and hosts are often elsewhere." });
  }
  const reg = geo.registration;
  if (reg && (reg.registrar || reg.created)) {
    const age = reg.created ? ` (${timeAgo(reg.created)})` : "";
    out.push({ label: "Registered", value: [reg.registrar, reg.created && `${reg.created}${age}`].filter(Boolean).join(" · "), tone: "muted",
      title: "Registrar and creation date from the WHOIS record VirusTotal holds. A very recent date is worth a look." });
  }
  if (reg && reg.country) {
    out.push({ label: "Registrant country", value: regionName(reg.country), tone: "muted", title: "Self-declared by whoever registered the domain, and often redacted or false." });
  }
  if (geo.agreement && geo.other_sources) {
    const detail = Object.entries(geo.other_sources).map(([k, v]) => `${k}: ${regionName(v)}`).join(", ");
    out.push({ label: geo.agreement === "agree" ? "Confirmed by" : "Disagrees with", value: detail,
      tone: geo.agreement === "agree" ? "muted" : "warn", title: "AbuseIPDB and VirusTotal country for this address, compared with GeoIP." });
  }
  return out;
}
