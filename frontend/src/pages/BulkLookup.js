import React, { useMemo, useRef, useState } from "react";
import { api, apiJSON } from "../lib/api";
import { detectType, refang } from "../lib/format";
import { geoFacts, regionName } from "../lib/geo";
import { openReport, MAX_REPORT_ITEMS, VERDICT_TONE, VERDICT_LABEL } from "../lib/report";
import { Badge, Button, Callout, Check, CopyButton, Menu, SearchInput, SkeletonRows, TypeBadge, useToast } from "../components/ui";
import AiPanel from "../components/AiPanel";

const MAX = 150;
const EXAMPLE = `8.8.8.8
evil[.]com
hxxp://malicious-site[.]com/payload.php
test@phish[.]net
d41d8cd98f00b204e9800998ecf8427e
invoice.pdf.exe`;
const ADDABLE = ["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256", "Email"];
const TYPE_WORD = { IPv4: "IP", IPv6: "IP", Domain: "domain", URL: "URL", MD5: "hash", SHA1: "hash", SHA256: "hash", Email: "email", CVE: "CVE", Filename: "file", Unknown: "unrecognised" };

// What the pasted text will be treated as, before anything is sent. Mirrors the server's own tokenising closely enough
// to give honest live counts; the server stays the authority.
export function previewTokens(text) {
  const toks = [...new Set(String(text || "").split(/[\s,;]+/).map(t => t.replace(/^["'\-*•\d.)]+(?=[a-zA-Z0-9])/, m => (/^\d+\.\d/.test(m) ? m : "")).trim()).filter(Boolean))];
  const counts = {};
  toks.forEach(t => { const w = TYPE_WORD[detectType(refang(t))] || "other"; counts[w] = (counts[w] || 0) + 1; });
  return { total: toks.length, counts };
}

// What the AI digest is given: one compact line per result, nothing else.
export function digestRows(results) {
  return (results || []).slice(0, 150).map(r => ({ value: String(r.defanged || r.refanged || r.input || "").slice(0, 300), type: r.type || null, verdict: r.verdict || null,
    score: Number.isFinite(r.score) ? Math.round(r.score) : null, reason: r.reason ? String(r.reason).slice(0, 400) : null,
    country: (r.geo && (r.geo.country || r.geo.edge_country)) || null, owner: (r.geo && r.geo.org) || null }));
}

export function csvCell(cell) {
  let s = String(cell ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;                       // defuse spreadsheet formulas in pasted indicators
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function resultsToCsv(rows) {
  const headers = ["input", "refanged", "type", "verdict", "score", "reason", "location", "location_kind", "tld_registry_country", "org", "cloud_provider", "already_tracked"];
  const lines = rows.map(r => [
    r.input, r.refanged, r.type, r.verdict, r.score || "", r.reason || "",
    (r.geo?.countries?.length ? r.geo.countries.map(c => c.name || regionName(c.code)).join(", ") : r.geo?.country) || "", r.geo?.kind || "",
    r.geo?.cctld_country_code ? regionName(r.geo.cctld_country_code) : "", r.geo?.org || "", r.geo?.cloud_provider || "", r.already_tracked ? "yes" : "no",
  ]);
  return [headers, ...lines].map(row => row.map(csvCell).join(",")).join("\r\n");
}

function download(csv) {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `tfii-bulk-lookup-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function ProviderChips({ item }) {
  const e = item.enrichment || {};
  const chips = [];
  const vt = e.virustotal, ab = e.abuseipdb, uh = e.urlhaus;
  const add = (name, d, text, tone) => { if (d && !(d.skipped && !d.error)) chips.push(<Badge key={name} tone={tone} outline title={name}>{name} · {text}</Badge>); };
  if (vt) add("VirusTotal", vt, vt.error ? "error" : vt.malicious !== undefined ? `${vt.malicious}/${vt.total}` : vt.found === false ? "not seen" : "checked", vt.error ? "low" : vt.malicious >= 3 ? "critical" : vt.malicious > 0 ? "high" : "success");
  if (ab) add("AbuseIPDB", ab, ab.error ? "error" : `${ab.abuse_score}%`, ab.error ? "low" : ab.abuse_score >= 75 ? "critical" : ab.abuse_score >= 25 ? "high" : "success");
  if (uh) add("URLhaus", uh, uh.error ? "error" : uh.found ? "listed" : "not listed", uh.error ? "low" : uh.found ? "critical" : "success");
  return <>{chips}</>;
}

function ResultRow({ item, selected, onToggle, onDetails, onAdd, added, adding }) {
  const tone = VERDICT_TONE[item.verdict] || "low";
  const facts = geoFacts(item.geo).filter(f => f.tone !== "muted" || ["Registered", "TLD registry"].includes(f.label));
  const warns = (item.enrichment?.mail?.signals || []).filter(s => s.level === "warn").slice(0, 2);
  return (
    <div className={`res-row tone-${tone} ${selected ? "selected" : ""}`}>
      <div className="res-check"><input type="checkbox" checked={selected} onChange={onToggle} aria-label={`Select ${item.defanged || item.refanged}`} /></div>
      <div className="res-main">
        <div className="row wrap" style={{ gap: 8 }}>
          <Badge tone={tone} dot>{VERDICT_LABEL[item.verdict] || item.verdict}{item.score ? <span className="num" style={{ opacity: .75, fontWeight: 500 }}>{item.score}</span> : null}</Badge>
          <TypeBadge type={item.type} />
          {item.already_tracked && <Badge tone="accent" outline>Tracked</Badge>}
          <span className="mono res-value" title={item.refanged}>{item.defanged || item.refanged}</span>
          <CopyButton value={item.defanged || item.refanged} size="sm" />
        </div>
        {item.reason && <div className="res-reason">{item.reason}</div>}
        <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
          <ProviderChips item={item} />
          {facts.map(f => (
            <span key={f.label} className={`fact-chip ${f.tone === "warn" ? "warn" : ""}`} title={f.title}><span>{f.label}</span>{f.value}</span>
          ))}
          {item.geo?.cloud_provider && <span className="fact-chip"><span>Cloud</span>{item.geo.cloud_provider}</span>}
        </div>
        {item.geo?.org && <div className="xs faint" style={{ marginTop: 6 }}>Owner {item.geo.org}{item.geo.asn ? ` (${item.geo.asn})` : ""}{item.geo.resolved_ip ? ` · resolves to ${item.geo.resolved_ip}` : ""}</div>}
        {warns.length > 0 && <div className="xs" style={{ marginTop: 6, color: "var(--high)" }}>{warns.map(w => <div key={w.code || w.text}>⚠ {w.text}</div>)}</div>}
      </div>
      <div className="res-actions">
        {item.verdict !== "unrecognized" && item.verdict !== "info" && !item.not_checked && <Button size="sm" icon="layers" onClick={onDetails}>Details</Button>}
        {ADDABLE.includes(item.type) && (added
          ? <span className="xs" style={{ color: "var(--success)", fontWeight: 600 }}>✓ In feed</span>
          : <Button size="sm" variant="ghost" icon="plus" loading={adding} onClick={onAdd}>Add</Button>)}
      </div>
    </div>
  );
}

export default function BulkLookup() {
  const toast = useToast();
  const [input, setInput] = useState("");
  const [results, setResults] = useState(null);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(() => new Set());
  const [added, setAdded] = useState({});
  const [adding, setAdding] = useState(null);
  const [bulkAdding, setBulkAdding] = useState(false);
  const fileRef = useRef(null);
  const preview = useMemo(() => previewTokens(input), [input]);

  function reset() { setResults(null); setSummary(null); setSel(new Set()); setAdded({}); setFilter("all"); setQ(""); setErr(""); }

  async function run() {
    if (!input.trim() || preview.total > MAX) return;
    reset(); setLoading(true);
    try { const d = await apiJSON("/iocs/bulk-lookup", { method: "POST", body: { input } }); setResults(d.results); setSummary(d.summary); }
    catch (e) { setErr(e.message); }
    setLoading(false);
  }

  async function upload(e) {
    const file = e.target.files[0];
    if (!file) return;
    reset(); setLoading(true);
    try {
      const fd = new FormData(); fd.append("file", file);
      const r = await api("/iocs/bulk-lookup/file", { method: "POST", body: fd });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof d.detail === "string" ? d.detail : "File upload failed.");
      setResults(d.results); setSummary(d.summary); setInput(`(loaded from file: ${file.name})`);
    } catch (e2) { setErr(e2.message || "Cannot reach server."); }
    setLoading(false);
    if (fileRef.current) fileRef.current.value = "";
  }

  const shown = useMemo(() => (results || []).filter(r => (filter === "all" || r.verdict === filter)
    && (!q.trim() || `${r.input} ${r.refanged} ${r.reason || ""} ${r.type}`.toLowerCase().includes(q.trim().toLowerCase()))), [results, filter, q]);
  const allShownSelected = shown.length > 0 && shown.every(r => sel.has(r.refanged));
  const someShownSelected = shown.some(r => sel.has(r.refanged));
  const chosen = (results || []).filter(r => sel.has(r.refanged));

  function toggle(v) { setSel(s => { const n = new Set(s); n.has(v) ? n.delete(v) : n.add(v); return n; }); }
  function selectWhere(fn) { setSel(new Set((results || []).filter(fn).map(r => r.refanged))); }

  async function addOne(item) {
    setAdding(item.refanged);
    try {
      const d = await apiJSON("/iocs", { method: "POST", body: { type: item.type, value: item.refanged, industry: "General", tlp: "AMBER", confidence: item.score || 50,
        description: `Added from Bulk Lookup — ${item.reason || ""}`.slice(0, 500), tags: [item.verdict, "bulk-lookup"] } });
      setAdded(a => ({ ...a, [item.refanged]: d.id }));
    } catch (e) { toast(e.message, "error"); }
    setAdding(null);
  }

  async function addChosen() {
    const items = chosen.filter(r => ADDABLE.includes(r.type));
    if (!items.length) { toast("None of the selected values can be added to the feed.", "info"); return; }
    setBulkAdding(true);
    try {
      const d = await apiJSON("/iocs/bulk-create", { method: "POST", body: { items: items.map(r => ({ type: r.type, value: r.refanged, confidence: r.score || 50,
        description: `Added from Bulk Lookup — ${r.reason || ""}`.slice(0, 500), tags: [r.verdict, "bulk-lookup"], enrichment: r.enrichment })) } });
      setAdded(a => { const n = { ...a }; items.forEach(r => { n[r.refanged] = true; }); return n; });
      toast(`Added ${d.created_count} to the feed${d.skipped_count ? `, ${d.skipped_count} already existed` : ""}.`, "ok");
      setSel(new Set());
    } catch (e) { toast(e.message, "error"); }
    setBulkAdding(false);
  }

  const reportable = chosen.filter(r => r.verdict !== "unrecognized" && r.verdict !== "info");
  const tooMany = preview.total > MAX;

  return (
    <div className="stack" style={{ gap: 20 }}>
      <section className="panel">
        <div className="panel-b" style={{ paddingTop: 20 }}>
          <div className="row between wrap" style={{ marginBottom: 12, gap: 12 }}>
            <div>
              <div className="strong" style={{ fontSize: 15 }}>Indicators</div>
              <div className="small muted" style={{ marginTop: 2 }}>One per line, or separated by commas. Defanged is fine: <span className="mono">evil[.]com</span>, <span className="mono">hxxp://</span>, <span className="mono">user[at]host</span>.</div>
            </div>
            <div className="row" style={{ gap: 8 }}>
              <Button size="sm" variant="ghost" onClick={() => setInput(EXAMPLE)}>Load example</Button>
              <input ref={fileRef} type="file" accept=".txt,.csv,.log" onChange={upload} style={{ display: "none" }} />
              <Button size="sm" icon="upload" onClick={() => fileRef.current?.click()} disabled={loading}>Upload a file</Button>
            </div>
          </div>
          <textarea className="textarea mono bulk-input" rows={7} value={input} onChange={e => setInput(e.target.value)} spellCheck={false}
            onKeyDown={e => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); }}
            placeholder={"8.8.8.8\nevil[.]com\nhxxp://bad-site[.]com/payload\ntest@phish[.]net\nd41d8cd98f00b204e9800998ecf8427e"} aria-label="Indicators to look up" />
          <div className="row between wrap" style={{ marginTop: 12, gap: 12 }}>
            <div className="row wrap" style={{ gap: 6, minHeight: 28 }}>
              {preview.total === 0
                ? <span className="small faint">Up to {MAX} indicators per lookup. Files: .txt, .csv, .log (max 2 MB).</span>
                : <>
                    <span className="small" style={{ color: tooMany ? "var(--critical)" : "var(--text-2)", fontWeight: 550 }}>{preview.total} detected{tooMany ? ` — over the ${MAX} limit` : ""}</span>
                    {Object.entries(preview.counts).map(([w, n]) => <span key={w} className="tag">{n} {w}{n === 1 ? "" : w === "IP" ? "s" : "s"}</span>)}
                  </>}
            </div>
            <div className="row" style={{ gap: 10 }}>
              {input && <Button size="sm" variant="ghost" onClick={() => { setInput(""); reset(); }}>Clear</Button>}
              <Button variant="primary" icon="search" loading={loading} disabled={!input.trim() || tooMany} onClick={run}>Run lookup <kbd style={{ marginLeft: 4, opacity: .7 }}>Ctrl ↵</kbd></Button>
            </div>
          </div>
        </div>
      </section>

      {err && <Callout tone="error">{err}</Callout>}

      {loading && (
        <section className="panel"><div className="panel-b tight">
          <div className="row" style={{ padding: "14px 20px 4px", gap: 10 }}><span className="spinner" /><span className="small muted">Checking {preview.total || "your"} indicators against VirusTotal, AbuseIPDB, URLhaus and DNS… larger batches take a little longer.</span></div>
          <SkeletonRows rows={5} cols={4} />
        </div></section>
      )}

      {summary && results && (
        <>
          {results.length > 1 && <AiPanel title="AI digest" cta="Digest this batch" hint="Groups the results into themes and points out the few worth attention first."
            path="/v2/ai/bulk-digest" body={{ rows: digestRows(results) }} />}
          <div className="row between wrap" style={{ gap: 12 }}>
            <div className="row wrap" style={{ gap: 8 }}>
              {[["all", "All", summary.total], ["malicious", "Malicious", summary.malicious], ["suspicious", "Suspicious", summary.suspicious], ["clean", "Clean", summary.clean], ["unknown", "Unknown", summary.unknown]].map(([id, label, n]) => (
                <button key={id} className={`chip ${filter === id ? "on" : ""}`} onClick={() => setFilter(id)} aria-pressed={filter === id}>
                  {id !== "all" && <span className="sev-dot" style={{ background: `var(--${VERDICT_TONE[id] === "success" ? "success" : VERDICT_TONE[id]})` }} />}{label} <span className="n">{n}</span>
                </button>
              ))}
            </div>
            <div className="row" style={{ gap: 8 }}>
              <SearchInput value={q} onChange={setQ} placeholder="Filter results…" style={{ width: 220 }} />
              <Button size="sm" icon="download" onClick={() => download(resultsToCsv(results))}>Download CSV</Button>
            </div>
          </div>

          <div className="row between" style={{ gap: 12, padding: "0 4px" }}>
            <Check checked={allShownSelected} indeterminate={someShownSelected} onChange={c => setSel(s => { const n = new Set(s); shown.forEach(r => (c ? n.add(r.refanged) : n.delete(r.refanged))); return n; })}>
              <span className="small">{sel.size ? `${sel.size} selected` : `Select all ${shown.length} shown`}</span>
            </Check>
            <Menu width={240} trigger={t => <Button size="sm" variant="ghost" iconRight="chevronDown" onClick={t}>Quick select</Button>} items={[
              { label: "Malicious and suspicious", icon: "alert", onClick: () => selectWhere(r => r.verdict === "malicious" || r.verdict === "suspicious") },
              { label: "Everything not yet in the feed", icon: "plus", onClick: () => selectWhere(r => ADDABLE.includes(r.type) && !r.already_tracked && !added[r.refanged]) },
              "sep",
              { label: "Clear selection", icon: "x", onClick: () => setSel(new Set()) },
            ]} />
          </div>

          <div className="stack" style={{ gap: 10 }}>
            {shown.length === 0 && <div className="panel"><div className="state"><div className="d">No indicators match this filter.</div></div></div>}
            {shown.map(item => (
              <ResultRow key={item.refanged + item.input} item={item} selected={sel.has(item.refanged)} onToggle={() => toggle(item.refanged)}
                onDetails={() => openReport([item.refanged])} onAdd={() => addOne(item)} added={added[item.refanged]} adding={adding === item.refanged} />
            ))}
          </div>
        </>
      )}

      {sel.size > 0 && (
        <div className="sel-bar" role="region" aria-label="Selection actions">
          <strong style={{ color: "var(--text)" }}>{sel.size} selected</strong>
          <span className="spacer" />
          <Button variant="primary" icon="layers" disabled={!reportable.length} onClick={() => openReport(reportable.map(r => r.refanged))}
            title={reportable.length > MAX_REPORT_ITEMS ? `The report shows the first ${MAX_REPORT_ITEMS}` : undefined}>
            Detailed report{reportable.length > MAX_REPORT_ITEMS ? ` (first ${MAX_REPORT_ITEMS})` : reportable.length ? ` · ${reportable.length}` : ""}
          </Button>
          <Button icon="plus" loading={bulkAdding} onClick={addChosen}>Add to feed</Button>
          <Button icon="download" onClick={() => download(resultsToCsv(chosen))}>CSV</Button>
          <Button variant="ghost" onClick={() => setSel(new Set())}>Clear</Button>
        </div>
      )}
    </div>
  );
}
