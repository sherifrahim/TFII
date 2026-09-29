// Formatting and domain helpers shared across pages.

export function toDate(v) {
  if (!v) return null;
  // Postgres TIMESTAMP (no zone) comes back naive; the server writes UTC.
  const s = typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(v) ? v + "Z" : v;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

export function timeAgo(v) {
  const d = toDate(v);
  if (!d) return "—";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)}d ago`;
  return fmtDate(d);
}

export function fmtDate(v) {
  const d = toDate(v);
  if (!d) return "—";
  return d.toISOString().slice(0, 10);
}

export function fmtDateTime(v) {
  const d = toDate(v);
  if (!d) return "—";
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

export function fmtNum(n) {
  if (n === null || n === undefined || n === "") return "—";
  const x = Number(n);
  if (!isFinite(x)) return String(n);
  if (Math.abs(x) >= 1e6) return (x / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
  if (Math.abs(x) >= 1e4) return (x / 1e3).toFixed(1).replace(/\.0$/, "") + "k";
  return x.toLocaleString();
}

export function trendPct(cur, prev) {
  cur = Number(cur) || 0; prev = Number(prev) || 0;
  if (!prev) return cur ? null : 0;
  return Math.round(((cur - prev) / prev) * 100);
}

export const IOC_TYPES = ["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256", "Email", "CVE"];
export const TLP_LEVELS = ["WHITE", "GREEN", "AMBER", "RED"];
export const INDUSTRIES = ["General", "Fintech", "Medical", "Gaming", "Retail", "Energy", "Government", "Telecom"];

export function typeGroup(t) {
  if (t === "IPv4" || t === "IPv6") return "ip";
  if (t === "Domain") return "domain";
  if (t === "URL") return "url";
  if (t === "MD5" || t === "SHA1" || t === "SHA256") return "hash";
  if (t === "Email") return "email";
  return "other";
}

export function confBand(c) {
  c = Number(c) || 0;
  if (c >= 90) return "critical";
  if (c >= 75) return "high";
  if (c >= 50) return "medium";
  return "low";
}

export function sevFromScore(score) {
  const s = Number(score);
  if (!isFinite(s) || s <= 0) return "none";
  if (s >= 9) return "critical";
  if (s >= 7) return "high";
  if (s >= 4) return "medium";
  return "low";
}

export function normSev(sev, score) {
  const s = String(sev || "").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(s)) return s;
  return sevFromScore(score);
}

export function defang(v, type) {
  if (!v) return v;
  if (type === "IPv4") return v.replace(/\./g, "[.]");
  if (type === "Domain") return v.replace(/\./g, "[.]");
  if (type === "Email") return v.replace("@", "[@]");
  if (type === "URL") return v.replace(/^http/i, "hxxp").replace(/\/\/([^/]+)/, (m, h) => "//" + h.replace(/\./g, "[.]"));
  return v;
}

export function detectType(raw) {
  const v = (raw || "").trim()
    .replace(/hxxp/ig, "http").replace(/\[\.\]|\(dot\)|\[dot\]/g, ".").replace(/\[@\]|\[at\]/g, "@").replace(/\[:\]/g, ":");
  if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return "CVE";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "IPv4";
  if (/^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(v)) return "IPv6";
  if (/^[0-9a-f]{32}$/i.test(v)) return "MD5";
  if (/^[0-9a-f]{40}$/i.test(v)) return "SHA1";
  if (/^[0-9a-f]{64}$/i.test(v)) return "SHA256";
  if (/^https?:\/\//i.test(v)) return "URL";
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return "Email";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return "Domain";
  return null;
}

export function refang(raw) {
  return (raw || "").trim()
    .replace(/hxxp/ig, "http").replace(/\[\.\]|\(dot\)|\[dot\]/g, ".").replace(/\[@\]|\[at\]/g, "@")
    .replace(/\[:\]/g, ":").replace(/\[\/\]/g, "/");
}

export function copy(text) {
  try { navigator.clipboard.writeText(text); return true; } catch { return false; }
}

// Hunting queries generated from the indicator itself. These are templates for
// an analyst to run, not claims about existing detection coverage.
export function detectionTemplates(type, value) {
  const v = String(value || "").replace(/'/g, "\\'");
  const g = typeGroup(type);
  const out = [];
  if (g === "ip") {
    out.push({ name: "Microsoft Sentinel / Defender (KQL)", lang: "kql", body:
`union isfuzzy=true
  (DeviceNetworkEvents | where RemoteIP == '${v}'),
  (CommonSecurityLog | where DestinationIP == '${v}' or SourceIP == '${v}'),
  (SigninLogs | where IPAddress == '${v}')
| project TimeGenerated, Type, DeviceName, RemoteIP, DestinationIP, SourceIP, IPAddress, InitiatingProcessFileName
| sort by TimeGenerated desc` });
    out.push({ name: "Splunk (SPL)", lang: "spl", body:
`index=* (dest_ip="${v}" OR src_ip="${v}" OR dest="${v}" OR src="${v}")
| stats count min(_time) as first_seen max(_time) as last_seen by index, sourcetype, src, dest
| convert ctime(first_seen) ctime(last_seen)` });
  } else if (g === "domain") {
    out.push({ name: "Microsoft Sentinel / Defender (KQL)", lang: "kql", body:
`union isfuzzy=true
  (DeviceNetworkEvents | where RemoteUrl has '${v}'),
  (DnsEvents | where Name has '${v}'),
  (CommonSecurityLog | where RequestURL has '${v}' or DestinationHostName has '${v}')
| sort by TimeGenerated desc` });
    out.push({ name: "Splunk (SPL)", lang: "spl", body:
`index=* (query="*${v}" OR url="*${v}*" OR dest="${v}" OR host="${v}")
| stats count min(_time) as first_seen max(_time) as last_seen by index, sourcetype, src` });
  } else if (g === "url") {
    out.push({ name: "Microsoft Sentinel / Defender (KQL)", lang: "kql", body:
`union isfuzzy=true
  (DeviceNetworkEvents | where RemoteUrl == '${v}'),
  (UrlClickEvents | where Url == '${v}'),
  (CommonSecurityLog | where RequestURL == '${v}')
| sort by TimeGenerated desc` });
    out.push({ name: "Splunk (SPL)", lang: "spl", body:
`index=* url="${v}"
| stats count min(_time) as first_seen max(_time) as last_seen by index, sourcetype, src, user` });
  } else if (g === "hash") {
    const col = type === "MD5" ? "MD5" : type === "SHA1" ? "SHA1" : "SHA256";
    out.push({ name: "Microsoft Defender (KQL)", lang: "kql", body:
`union isfuzzy=true DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where ${col} == '${v}'
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc` });
    out.push({ name: "Splunk (SPL)", lang: "spl", body:
`index=* (${col.toLowerCase()}="${v}" OR file_hash="${v}" OR hash="${v}")
| stats count by index, sourcetype, dest, file_name, file_path` });
    out.push({ name: "YARA (hash condition)", lang: "yara", body:
`import "hash"
rule tfii_${v.slice(0, 12)} {
  condition:
    hash.${col.toLowerCase()}(0, filesize) == "${v.toLowerCase()}"
}` });
  } else if (g === "email") {
    out.push({ name: "Microsoft Defender for Office (KQL)", lang: "kql", body:
`EmailEvents
| where SenderFromAddress == '${v}' or SenderMailFromAddress == '${v}' or RecipientEmailAddress == '${v}'
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| sort by Timestamp desc` });
  }
  return out;
}
