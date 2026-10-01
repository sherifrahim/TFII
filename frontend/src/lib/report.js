import { navigate } from "./router";

// The Detailed report screen is opened with the indicators it should show. A short list travels in the URL (shareable,
// survives a reload); a long one is parked in sessionStorage so the address bar stays sane.
const KEY = "tf_report_items";
export const MAX_REPORT_ITEMS = 25;

export function openReport(values) {
  const list = [...new Set((values || []).map(v => String(v).trim()).filter(Boolean))].slice(0, MAX_REPORT_ITEMS);
  if (!list.length) return;
  const json = JSON.stringify(list);
  if (json.length <= 1500) { navigate("/report", { items: json }); return; }
  try { sessionStorage.setItem(KEY, json); } catch { /* the report then shows its empty state */ }
  navigate("/report", { s: "1" });
}

export function readReportItems(query) {
  let raw = query && query.items;
  if (!raw && query && query.s) { try { raw = sessionStorage.getItem(KEY); } catch { raw = null; } }
  try {
    const arr = JSON.parse(raw || "[]");
    return Array.isArray(arr) ? arr.map(String).slice(0, MAX_REPORT_ITEMS) : [];
  } catch { return []; }
}

export const VERDICT_TONE = { malicious: "critical", suspicious: "high", clean: "success", unknown: "low", unrecognized: "low", info: "medium" };
export const VERDICT_LABEL = { malicious: "Malicious", suspicious: "Suspicious", clean: "Clean", unknown: "Unknown", unrecognized: "Not recognised", info: "Info" };

const cell = v => String(v ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

// Plain Markdown for pasting into a ticket or a report. Only what was actually returned is included.
export function reportToMarkdown(items) {
  const out = [`# TFII detailed report`, `_${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC · ${items.length} indicator${items.length === 1 ? "" : "s"}_`, ""];
  for (const it of items) {
    out.push(`## ${it.defanged || it.value}`);
    out.push(`- Type: ${it.type}`, `- Verdict: ${VERDICT_LABEL[it.verdict] || it.verdict}${it.score ? ` (${it.score})` : ""}`);
    if (it.reason) out.push(`- Why: ${it.reason}`);
    for (const p of it.providers || []) {
      if (p.status === "skipped" || p.status === "error") { out.push(`- ${p.name}: not scanned (${p.message})`); continue; }
      out.push(`- ${p.name}: ${p.headline || (p.status === "not_found" ? "no record" : "checked")}`);
    }
    const sections = [...(it.providers || []).filter(p => p.status === "ok").flatMap(p => p.sections.map(s => [p.name, s])), ...(it.tfii || []).map(s => ["TFII", s])];
    for (const [who, s] of sections) {
      out.push("", `### ${who}: ${s.title}`);
      if (s.type === "kv") s.rows.forEach(([k, v]) => out.push(`- **${k}:** ${v}`));
      else if (s.type === "table") { out.push(`| ${s.cols.join(" | ")} |`, `| ${s.cols.map(() => "---").join(" | ")} |`); s.rows.forEach(r => out.push(`| ${r.map(cell).join(" | ")} |`)); }
      else if (s.type === "tags") out.push(s.items.join(", "));
      else if (s.type === "text") out.push("```", s.text, "```");
    }
    out.push("");
  }
  return out.join("\n");
}
