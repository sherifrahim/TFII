import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api, apiJSON } from "../lib/api";
import { Badge, Button, Callout, Field, PageHeader, Panel, Segmented, Select, SkeletonRows, TypeBadge, useToast } from "../components/ui";

const MAX_IOCS = 5, MAX_CVES = 2;
const TLP = ["WHITE", "GREEN", "AMBER", "RED"];
const SEV_TONE = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };

function IocPicker({ selected, onToggle }) {
  const toast = useToast();
  const [pool, setPool] = useState(null);
  const [family, setFamily] = useState("fintech");
  const [type, setType] = useState("");
  const [busy, setBusy] = useState({});
  const [scan, setScan] = useState({});

  const load = useCallback(async () => {
    setPool(null);
    const params = new URLSearchParams({ sector: family === "fintech" ? "fintech" : "", family: family === "fintech" ? "" : family, limit: 80 });
    if (type) params.set("ioc_type", type);
    try { setPool(await apiJSON(`/advisory/iocs?${params}`)); } catch (e) { setPool([]); toast(e.message, "error"); }
  }, [family, type, toast]);
  useEffect(() => { load(); }, [load]);

  // Re-check a value against live sources so a score captured days ago is not what goes to a client. One at a time:
  // each call spends third-party quota.
  async function rescan(ioc) {
    setBusy(b => ({ ...b, [ioc.id]: true }));
    try {
      const d = await apiJSON(`/iocs/${ioc.id}/re-enrich`, { method: "POST" });
      const conf = typeof d.confidence === "number" ? d.confidence : ioc.confidence;
      setScan(m => ({ ...m, [ioc.id]: { conf, verdict: conf >= 70 ? "malicious" : conf >= 40 ? "suspicious" : "clean" } }));
      setPool(p => p.map(x => (x.id === ioc.id ? { ...x, confidence: conf } : x)));
    } catch (e) { setScan(m => ({ ...m, [ioc.id]: { error: e.message } })); }
    setBusy(b => { const n = { ...b }; delete n[ioc.id]; return n; });
  }
  async function rescanSelected() { for (const i of (pool || []).filter(x => selected.has(x.id))) await rescan(i); }

  const families = useMemo(() => [...new Set((pool || []).map(i => i.family).filter(Boolean))].sort(), [pool]);
  const anyBusy = Object.keys(busy).length > 0;
  return (
    <Panel title="Threat indicators" sub={`pick up to ${MAX_IOCS} · ${selected.size} chosen`}
      actions={<Button size="xs" variant="ghost" loading={anyBusy} disabled={!selected.size} onClick={rescanSelected} data-tip="Re-check the chosen indicators against live sources first">Re-check chosen</Button>}>
      <div className="row" style={{ gap: 8, marginBottom: 12 }}>
        <Select value={family} onChange={setFamily} options={[["fintech", "Fintech / GCC"], ...families.map(f => [f, f]), ["", "All families"]]} />
        <Select value={type} onChange={setType} options={[["", "All types"], ...["IPv4", "Domain", "URL", "MD5", "SHA256"].map(t => [t, t])]} />
      </div>
      <div className="pick-list">
        {pool === null && <SkeletonRows rows={4} cols={2} />}
        {pool && pool.length === 0 && <div className="state" style={{ padding: "24px 0" }}><div className="d">No connector indicators match. Run a sync from Connectors first.</div></div>}
        {(pool || []).map(i => {
          const on = selected.has(i.id), off = !on && selected.size >= MAX_IOCS, r = scan[i.id];
          return (
            <div key={i.id} className={`pick ${on ? "on" : ""} ${off ? "off" : ""}`} onClick={() => !off && onToggle(i.id)}>
              <input type="checkbox" checked={on} readOnly tabIndex={-1} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="row wrap" style={{ gap: 6 }}><TypeBadge type={i.type} />{i.family && <Badge tone="critical">{i.family}</Badge>}<span className="xs faint">{i.source}</span></div>
                <div className="mono-soft" style={{ marginTop: 4, overflowWrap: "anywhere" }}>{i.value}</div>
              </div>
              <div className="row" style={{ gap: 8, flexShrink: 0 }}>
                {r?.error ? <Badge tone="low" outline title={r.error}>failed</Badge>
                  : r ? <Badge tone={r.verdict === "malicious" ? "critical" : r.verdict === "suspicious" ? "high" : "success"} dot>{r.verdict} {r.conf}%</Badge>
                  : <span className="xs faint num">{i.confidence}%</span>}
                <Button size="xs" variant="ghost" loading={!!busy[i.id]} onClick={e => { e.stopPropagation(); rescan(i); }}>Re-check</Button>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function CvePicker({ chosen, setChosen }) {
  const [suggested, setSuggested] = useState(null);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => { apiJSON("/advisory/suggested-cves?limit=15&days=45").then(setSuggested).catch(() => setSuggested([])); }, []);

  async function addTyped() {
    const id = q.trim().toUpperCase();
    if (!id.startsWith("CVE-") || chosen.some(c => c.id === id)) return;
    if (chosen.length >= MAX_CVES) { setErr(`At most ${MAX_CVES} CVEs per advisory.`); return; }
    setBusy(true); setErr("");
    try {
      const d = await apiJSON(`/cve/lookup?id=${encodeURIComponent(id)}`);
      const nvd = d.sources?.find(s => s.source === "NVD") || d.sources?.[0] || {};
      setChosen(p => [...p, { id, description: (nvd.description || "No description available.").slice(0, 400), cvss_score: nvd.cvss_score || "N/A", severity: nvd.severity || "UNKNOWN" }]);
      setQ("");
    } catch { setErr("That CVE wasn't found."); }
    setBusy(false);
  }
  return (
    <Panel title="CVEs" sub={`pick up to ${MAX_CVES} · ${chosen.length} chosen`}>
      <div className="row" style={{ gap: 8, marginBottom: 12 }}>
        <input className="input mono" style={{ flex: 1 }} value={q} onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === "Enter" && addTyped()} placeholder="Add a specific CVE-2025-12345" aria-label="CVE id" />
        <Button loading={busy} disabled={chosen.length >= MAX_CVES} onClick={addTyped}>Add</Button>
      </div>
      {err && <div className="small" style={{ color: "var(--critical)", marginBottom: 10 }}>{err}</div>}
      <div className="eyebrow" style={{ marginBottom: 8 }}>Suggested: actively exploited (CISA KEV) and likely to be exploited (EPSS)</div>
      <div className="pick-list">
        {suggested === null && <div className="state" style={{ padding: "24px 0" }}><span className="spinner" /><div className="d">Cross-referencing CISA KEV and EPSS. This can take 10 to 20 seconds.</div></div>}
        {suggested && suggested.length === 0 && <div className="state" style={{ padding: "24px 0" }}><div className="d">No recent KEV matches. Type a CVE above.</div></div>}
        {(suggested || []).map(c => {
          const on = chosen.some(s => s.id === c.id), off = !on && chosen.length >= MAX_CVES;
          return (
            <div key={c.id} className={`pick ${on ? "on" : ""} ${off ? "off" : ""}`}
              onClick={() => { if (off) return; setChosen(p => (on ? p.filter(s => s.id !== c.id) : [...p, c])); }}>
              <input type="checkbox" checked={on} readOnly tabIndex={-1} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="row wrap" style={{ gap: 6 }}>
                  <span className="mono strong" style={{ fontSize: 12.5 }}>{c.id}</span>
                  {c.severity && <Badge tone={SEV_TONE[c.severity] || "low"} dot>{c.severity}{c.cvss_score ? ` ${c.cvss_score}` : ""}</Badge>}
                  {c.ransomware && <Badge tone="critical">Ransomware</Badge>}
                  {c.epss_pct != null && <span className="xs faint">EPSS {c.epss_pct}%</span>}
                </div>
                <div className="small muted" style={{ marginTop: 4 }}><b style={{ color: "var(--text-2)" }}>{c.vendor}</b> {c.product} · {(c.name || "").slice(0, 90)}</div>
              </div>
              {c.kev_date && <span className="xs faint" style={{ flexShrink: 0 }}>KEV {c.kev_date}</span>}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function downloadEml(result, client) {
  const boundary = "----=_Part_TFII_" + Date.now();
  const eml = ["MIME-Version: 1.0", `Content-Type: multipart/alternative; boundary="${boundary}"`, `Subject: ${result.subject}`, "From: TFII Advisory <noreply@tfii.dev>", "", `--${boundary}`,
    "Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: 7bit", "", result.plain_text || "", "", `--${boundary}`, "Content-Type: text/html; charset=UTF-8", "Content-Transfer-Encoding: 7bit", "", result.html || "", "", `--${boundary}--`].join("\r\n");
  const url = URL.createObjectURL(new Blob([eml], { type: "message/rfc822" }));
  const a = document.createElement("a"); a.href = url; a.download = `TFII-Advisory-${client.replace(/\s+/g, "-")}.eml`; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
}

export default function AdvisoriesPage() {
  const [iocs, setIocs] = useState(new Set());
  const [cves, setCves] = useState([]);
  const [client, setClient] = useState("");
  const [analyst, setAnalyst] = useState("");
  const [sector, setSector] = useState("Financial Services / Fintech");
  const [tlp, setTlp] = useState("AMBER");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [result, setResult] = useState(null);

  async function generate() {
    if (!client.trim()) { setErr("Add the client or organisation name."); return; }
    if (!iocs.size && !cves.length) { setErr("Choose at least one indicator or CVE."); return; }
    setBusy(true); setErr(""); setResult(null);
    const r = await api("/advisory/generate", { method: "POST", body: JSON.stringify({ ioc_ids: [...iocs], cve_ids: cves.map(c => c.id), client_name: client, analyst_name: analyst || "TFII Analyst", sector, tlp, custom_note: note }) });
    if (r.ok) setResult(await r.json()); else { const d = await r.json().catch(() => ({})); setErr(typeof d.detail === "string" ? d.detail : "Generation failed."); }
    setBusy(false);
  }

  if (result) {
    return (
      <div className="page narrow">
        <PageHeader title="Advisory preview" sub={result.subject} actions={<>
          <Button variant="ghost" icon="arrowRight" onClick={() => setResult(null)} style={{ transform: "none" }}>Back to edit</Button>
          <Button variant="primary" icon="download" onClick={() => downloadEml(result, client)}>Download .eml</Button>
        </>} />
        <div className="advisory-frame"><iframe srcDoc={result.html} title="Advisory preview" sandbox="allow-same-origin" /></div>
        <div className="small faint" style={{ textAlign: "center", marginTop: 12 }}>Open the .eml in Outlook, Apple Mail or Thunderbird to send it to your client.</div>
      </div>
    );
  }
  return (
    <div className="page">
      <PageHeader title="Advisories" sub="Build a client advisory email from live indicators and actively exploited CVEs." />
      <div className="stack" style={{ gap: 20 }}>
        <div className="grid g2" style={{ alignItems: "start" }}>
          <IocPicker selected={iocs} onToggle={id => setIocs(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; })} />
          <CvePicker chosen={cves} setChosen={setCves} />
        </div>
        <Panel title="Advisory details">
          <div className="grid g2" style={{ gap: "0 20px" }}>
            <Field label="Client or organisation"><input className="input" value={client} onChange={e => setClient(e.target.value)} placeholder="ACME Fintech Ltd" /></Field>
            <Field label="Your name"><input className="input" value={analyst} onChange={e => setAnalyst(e.target.value)} placeholder="Shown as the author" /></Field>
            <Field label="Sector"><input className="input" value={sector} onChange={e => setSector(e.target.value)} /></Field>
            <Field label="Sharing level (TLP)" hint="How widely the recipient may share it."><Segmented value={tlp} onChange={setTlp} options={TLP.map(t => [t, t])} /></Field>
          </div>
          <Field label="Extra context" hint="Optional. For example: the client is expanding into a new market, so focus on mobile banking threats."><textarea className="textarea" rows={2} value={note} onChange={e => setNote(e.target.value)} /></Field>
        </Panel>
        {err && <Callout tone="error">{err}</Callout>}
        <div className="sel-bar" style={{ position: "sticky" }}>
          <span className="small"><b style={{ color: "var(--text)" }}>{iocs.size}</b> indicator{iocs.size === 1 ? "" : "s"} · <b style={{ color: "var(--text)" }}>{cves.length}</b> CVE{cves.length === 1 ? "" : "s"} · <Badge tone={tlp === "RED" ? "critical" : tlp === "AMBER" ? "high" : tlp === "GREEN" ? "success" : "low"} outline>TLP:{tlp}</Badge>{client && <> for <b style={{ color: "var(--text)" }}>{client}</b></>}</span>
          <span className="spacer" />
          <Button variant="primary" size="lg" icon="megaphone" loading={busy} disabled={(!iocs.size && !cves.length) || !client} onClick={generate}>Generate advisory</Button>
        </div>
      </div>
    </div>
  );
}
