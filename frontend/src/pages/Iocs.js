import React, { useEffect, useMemo, useState } from "react";
import { useApi, apiJSON, api, qs, downloadJSON } from "../lib/api";
import { navigate, setQuery, entityRoute, enc } from "../lib/router";
import { useSession } from "../lib/session";
import { fmtNum, fmtDate, timeAgo, toDate, IOC_TYPES, TLP_LEVELS, INDUSTRIES, detectType, refang } from "../lib/format";
import {
  PageHeader, Panel, Button, IconButton, Badge, TypeBadge, TLPBadge, Conf, StatusBadge, SearchInput, Select, Pagination, Th,
  SkeletonRows, EmptyState, ErrorState, Menu, Modal, Field, Callout, Tabs, useDebounced, useToast, CopyButton, rowAction,
} from "../components/ui";
import InvestigationPicker from "../components/InvestigationPicker";
import Icon from "../components/Icon";
import { API_BASE } from "../config";

const TYPE_CHIPS = [["", "All"], ["ip", "IPs"], ["domain", "Domains"], ["url", "URLs"], ["hash", "Hashes"], ["email", "Emails"]];
const STATUS_OPTS = [["live", "Live (all but expired / FP)"], ["active", "Active"], ["suspicious", "Suspicious"], ["confirmed", "Confirmed"], ["unknown", "Unknown"],
  ["expired", "Expired"], ["false_positive", "False positive"], ["all", "All statuses"]];
const ENRICH_LABEL = { enriched: "Enriched", not_enriched: "Not enriched", error: "Lookup failed" };
const LIVE = ["active", "suspicious", "confirmed", "unknown"];
const TYPE_GROUP_OF = { IPv4: "ip", IPv6: "ip", Domain: "domain", URL: "url", MD5: "hash", SHA1: "hash", SHA256: "hash", Email: "email" };

function FilterField({ label, children }) {
  return <div className="filter-field"><label>{label}</label>{children}</div>;
}

const FILTER_LABEL = { tlp: v => `TLP:${v}`, source: v => `Source: ${v}`, tag: v => `#${v}`, campaign_id: () => "Campaign", min_conf: v => `Confidence ≥ ${v}`, since_days: v => `First seen ≤ ${v}d`,
  severity: v => `Severity: ${v}`, enrichment: v => ENRICH_LABEL[v] || v, last_seen_days: v => `Seen ≤ ${v}d`, expiring_days: v => `Expires ≤ ${v}d`, analyst: v => `Analyst: ${v}` };

export function IocIntel({ query }) {
  const { me, can } = useSession();
  const toast = useToast();
  const q = query.q || "";
  const [text, setText] = useState(q);
  const dtext = useDebounced(text, 300);
  useEffect(() => { if (dtext !== q) setQuery({ q: dtext, offset: "" }); }, [dtext]); // eslint-disable-line react-hooks/exhaustive-deps

  const filters = {
    q, type: query.type || "", tlp: query.tlp || "", source: query.source || "", tag: query.tag || "",
    campaign_id: query.campaign_id || "", min_conf: query.min_conf || "", status: query.status || "live",
    severity: query.severity || "", enrichment: query.enrichment || "", since_days: query.since_days || "",
    last_seen_days: query.last_seen_days || "", expiring_days: query.expiring_days || "", analyst: query.analyst || "",
  };
  const params = { ...filters, sort: query.sort || "created", dir: query.dir || "desc", limit: query.limit || 50, offset: query.offset || 0 };
  const { data, error, loading, reload } = useApi(`/v2/iocs${qs(params)}`);
  // Counts and option lists load separately: paging and sorting never repeat them.
  const facets = useApi(`/v2/iocs/facets${qs(filters)}`);
  const options = useApi("/v2/iocs/filter-options");
  const campaigns = useApi("/campaigns");
  const [sel, setSel] = useState(new Set());
  const [picker, setPicker] = useState(null);
  const [tagModal, setTagModal] = useState(false);
  useEffect(() => { setSel(new Set()); }, [data]);

  const items = data?.items || [];
  const set = patch => setQuery({ ...patch, offset: "" });
  const onSort = id => set({ sort: id, dir: params.sort === id && params.dir === "desc" ? "asc" : "desc" });
  const allSel = items.length > 0 && items.every(i => sel.has(i.id));
  const typeFacet = useMemo(() => {
    const out = {};
    (facets.data?.types || []).forEach(t => { const g = TYPE_GROUP_OF[t.k] || "other"; out[g] = (out[g] || 0) + Number(t.n); });
    return out;
  }, [facets.data]);
  const activeFilters = ["type", "tlp", "source", "tag", "campaign_id", "min_conf", "since_days", "severity", "enrichment", "last_seen_days", "expiring_days", "analyst"].filter(k => params[k]);
  const advanced = activeFilters.filter(k => k !== "type");
  const [showFilters, setShowFilters] = useState(advanced.length > 0);

  async function bulk(action, extra = {}) {
    try {
      const r = await apiJSON("/v2/iocs/bulk-action", { method: "POST", body: { ids: [...sel], action, ...extra } });
      toast(`${r.affected} indicator${r.affected === 1 ? "" : "s"} updated`, "ok");
      reload(true);
    } catch (e) { toast(e.message, "error"); }
  }
  async function del(ioc) {
    if (!window.confirm(`Delete ${ioc.value}? This cannot be undone.`)) return;
    const r = await api(`/iocs/${enc(ioc.id)}`, { method: "DELETE" });
    if (r.ok) { toast("Indicator deleted", "ok"); reload(true); } else toast((await r.json().catch(() => ({}))).detail || "Delete failed", "error");
  }
  async function setStatus(ioc, status) {
    try { await apiJSON("/v2/entity/status", { method: "POST", body: { ref: ioc.id, status, reason: "Set from IOC table" } }); toast(`Status set to ${status}`, "ok"); reload(true); facets.reload(true); }
    catch (e) { toast(e.message, "error"); }
  }
  async function toggleFp(ioc) {
    const fp = ioc.status !== "false_positive";
    const r = await api(`/iocs/${enc(ioc.id)}/false-positive`, { method: "PATCH", body: JSON.stringify({ false_positive: fp, reason: fp ? "Marked from IOC table" : "" }) });
    if (r.ok) { toast(fp ? "Marked as false positive" : "False-positive flag removed", "ok"); reload(true); }
    else toast((await r.json().catch(() => ({}))).detail || "Update failed", "error");
  }

  return (
    <div className="page">
      <PageHeader title="IOC Intelligence" sub={data ? `${fmtNum(data.total)} indicators match` : "Indicators across every source"}
        actions={<>
          <Button size="sm" icon="upload" onClick={() => navigate("/iocs/import")}>Import</Button>
          <Button size="sm" icon="download" onClick={() => navigate("/iocs/export")}>Export</Button>
          <Button size="sm" icon="layers" onClick={() => navigate("/osint/bulk")}>Bulk lookup</Button>
          <Button size="sm" variant="primary" icon="plus" onClick={() => navigate("/iocs/new")}>Add IOC</Button>
        </>} />

      <div className="row wrap" style={{ gap: 10, marginBottom: 12 }}>
        <SearchInput value={text} onChange={setText} placeholder="Search value, description, tag, malware family… (fanged or defanged)" style={{ flex: "1 1 340px", maxWidth: 560 }} />
        <Select value={params.status} onChange={v => set({ status: v })} options={STATUS_OPTS} />
        <Button icon="filter" className={showFilters ? "on-filter" : ""} aria-expanded={showFilters} onClick={() => setShowFilters(v => !v)}>
          Filters{advanced.length > 0 && <span className="filter-count">{advanced.length}</span>}
        </Button>
        {activeFilters.length > 0 && <Button size="sm" variant="ghost" icon="x" onClick={() => set(Object.fromEntries(activeFilters.map(k => [k, ""])))}>Clear all</Button>}
      </div>

      {showFilters && (
        <div className="panel filter-panel">
          <FilterField label="TLP"><Select value={params.tlp} onChange={v => set({ tlp: v })} options={[["", "Any"], ...TLP_LEVELS.map(t => [t, `TLP:${t}`])]} /></FilterField>
          <FilterField label="Source"><Select value={params.source} onChange={v => set({ source: v })}
            options={[["", "Any"], ...((options.data?.sources || []).map(s => [s.k, `${s.k} (${fmtNum(s.n)})`])), ...(params.source && !(options.data?.sources || []).some(s => s.k === params.source) ? [[params.source, params.source]] : [])]} /></FilterField>
          <FilterField label="Severity"><Select value={params.severity} onChange={v => set({ severity: v })} options={[["", "Any"], ["critical", "Critical (≥90)"], ["high", "High (75–89)"], ["medium", "Medium (50–74)"], ["low", "Low (<50)"]]} /></FilterField>
          <FilterField label="Confidence"><Select value={params.min_conf} onChange={v => set({ min_conf: v })} options={[["", "Any"], ["50", "≥ 50"], ["75", "≥ 75"], ["80", "≥ 80"], ["90", "≥ 90"]]} /></FilterField>
          <FilterField label="First seen"><Select value={params.since_days} onChange={v => set({ since_days: v })} options={[["", "Any time"], ["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"]]} /></FilterField>
          <FilterField label="Last seen"><Select value={params.last_seen_days} onChange={v => set({ last_seen_days: v })} options={[["", "Any time"], ["1", "Within 24 hours"], ["7", "Within 7 days"], ["30", "Within 30 days"]]} /></FilterField>
          <FilterField label="Expires"><Select value={params.expiring_days} onChange={v => set({ expiring_days: v })} options={[["", "Any time"], ["7", "Within 7 days"], ["30", "Within 30 days"]]} /></FilterField>
          <FilterField label="Enrichment"><Select value={params.enrichment} onChange={v => set({ enrichment: v })} options={[["", "Any"], ["enriched", "Enriched"], ["not_enriched", "Not enriched"], ["error", "Lookup failed"]]} /></FilterField>
          <FilterField label="Campaign"><Select value={params.campaign_id} onChange={v => set({ campaign_id: v })} options={[["", "Any"], ...((campaigns.data || []).map(c => [c.id, c.name]))]} /></FilterField>
          {(options.data?.analysts || []).length > 0 && <FilterField label="Analyst"><Select value={params.analyst} onChange={v => set({ analyst: v })} options={[["", "Any"], ...options.data.analysts.map(a => [a.k, a.k])]} /></FilterField>}
        </div>
      )}
      <div className="row wrap" style={{ gap: 6, marginBottom: 12 }}>
        {TYPE_CHIPS.map(([id, label]) => (
          <button key={id} className={`chip ${params.type === id || (!id && !params.type) ? "on" : ""}`} onClick={() => set({ type: id })}>
            {label}{id && typeFacet[id] !== undefined && <span className="n">{fmtNum(typeFacet[id])}</span>}
          </button>
        ))}
        {params.type && !TYPE_CHIPS.some(([id]) => id === params.type) && <button className="chip on" onClick={() => set({ type: "" })}>{params.type} ×</button>}
        {Object.keys(FILTER_LABEL).filter(k => params[k]).map(k => (
          <button key={k} className="chip on" onClick={() => set({ [k]: "" })} title="Remove this filter">{FILTER_LABEL[k](params[k])} <Icon name="x" size={11} /></button>
        ))}
      </div>

      {sel.size > 0 && (
        <div className="panel row wrap" style={{ padding: "8px 12px", marginBottom: 10, gap: 8, borderColor: "var(--accent-line)" }}>
          <span className="strong small">{sel.size} selected</span>
          <span className="spacer" />
          <Button size="sm" icon="briefcase" onClick={() => setPicker("bulk")}>Add to investigation</Button>
          <Select value="" onChange={v => v && bulk("assign_campaign", { campaign_id: v === "__none" ? null : v })}
            options={[["", "Assign campaign…"], ["__none", "— Remove campaign —"], ...((campaigns.data || []).map(c => [c.id, c.name]))]} />
          <Select value="" onChange={v => v && bulk("set_status", { status: v })}
            options={[["", "Set status…"], ["suspicious", "Suspicious"], ["confirmed", "Confirmed"], ["unknown", "Unknown"], ["active", "Active (clear verdict)"]]} />
          <Button size="sm" icon="hash" onClick={() => setTagModal(true)}>Add tag</Button>
          <Button size="sm" icon="alert" onClick={() => bulk("mark_fp", { reason: "Bulk-marked from IOC table" })}>Mark FP</Button>
          <Button size="sm" variant="ghost" onClick={() => setSel(new Set())}>Clear</Button>
        </div>
      )}

      <Panel tight bodyStyle={{ padding: 0 }}
        footer={data && <>
          <span className="faint">Click a row to open the entity</span>
          <Pagination total={data.total} limit={Number(params.limit)} offset={Number(params.offset)}
            onChange={o => setQuery({ offset: o || "" })} onLimit={l => set({ limit: l })} />
        </>}>
        {error ? <ErrorState error={error} onRetry={reload} /> : (
          <div className="tbl-wrap" style={{ maxHeight: "calc(100vh - 300px)", minHeight: 320 }}>
            <table className="tbl">
              <thead><tr>
                <th style={{ width: 34 }}><input type="checkbox" checked={allSel} onChange={() => setSel(allSel ? new Set() : new Set(items.map(i => i.id)))} aria-label="Select all" /></th>
                <Th id="value" label="Indicator" sort={params.sort} dir={params.dir} onSort={onSort} />
                <Th id="type" label="Type" sort={params.sort} dir={params.dir} onSort={onSort} />
                <Th id="confidence" label="Confidence" sort={params.sort} dir={params.dir} onSort={onSort} />
                <Th id="source" label="Source" sort={params.sort} dir={params.dir} onSort={onSort} className="opt-lg" />
                <th className="opt-xl">Tags</th>
                <th className="opt-lg">Campaign / Actor</th>
                <Th id="created" label="First seen" sort={params.sort} dir={params.dir} onSort={onSort} />
                <Th id="last_seen" label="Last seen" sort={params.sort} dir={params.dir} onSort={onSort} className="opt-lg" />
                <th className="opt-xl">Expires</th>
                <th className="opt-xl">Enrichment</th>
                <Th id="tlp" label="TLP" sort={params.sort} dir={params.dir} onSort={onSort} />
                <Th id="status" label="Status" sort={params.sort} dir={params.dir} onSort={onSort} />
                <th className="opt-xl">Analyst</th>
                <th style={{ width: 40 }} />
              </tr></thead>
              <tbody>
                {loading && !data && <tr><td colSpan={15} style={{ padding: 0 }}><SkeletonRows rows={12} cols={7} /></td></tr>}
                {data && items.length === 0 && (
                  <tr><td colSpan={15}><EmptyState icon="crosshair" title="No indicators match"
                    desc={q || activeFilters.length ? "Try widening the filters or searching a partial value." : "Add an IOC, import a STIX bundle, or enable a feed connector."}
                    action={<Button size="sm" variant="primary" icon="plus" onClick={() => navigate("/iocs/new", q ? { value: q } : undefined)}>Add IOC</Button>} /></td></tr>
                )}
                {items.map(i => {
                  const fresh = i.created_at && Date.now() - (toDate(i.created_at)?.getTime() || 0) < 864e5;
                  const tags = (i.tags || []).filter(t => !["connector", "bulk-lookup"].includes(t));
                  return (
                    <tr key={i.id} className={`clickable ${sel.has(i.id) ? "selected" : ""}`} {...rowAction(() => navigate(entityRoute("ioc", i.id)))}
                      style={{ opacity: LIVE.includes(i.status) ? 1 : 0.6 }}>
                      <td onClick={e => e.stopPropagation()}>
                        <input type="checkbox" checked={sel.has(i.id)} aria-label="Select"
                          onChange={() => setSel(s => { const n = new Set(s); n.has(i.id) ? n.delete(i.id) : n.add(i.id); return n; })} />
                      </td>
                      <td className="primary" style={{ maxWidth: 340 }}>
                        <div className="row" style={{ gap: 6 }}>
                          <span className="cellmono trunc" title={i.value}>{i.value_defanged || i.value}</span>
                          {fresh && <span className="new-dot" title="Added in the last 24 hours" />}
                          {i.malware_family && i.malware_family !== "unknown" && <Badge tone="violet">{i.malware_family}</Badge>}
                        </div>
                      </td>
                      <td><TypeBadge type={i.type} /></td>
                      <td><Conf value={i.confidence} /></td>
                      <td className="muted opt-lg">{i.source}</td>
                      <td className="opt-xl" style={{ maxWidth: 180 }}>
                        <div className="row" style={{ gap: 3, overflow: "hidden" }}>
                          {tags.slice(0, 2).map(t => <span key={t} className="tag link" onClick={e => { e.stopPropagation(); set({ tag: t }); }}>{t}</span>)}
                          {tags.length > 2 && <span className="faint xs">+{tags.length - 2}</span>}
                        </div>
                      </td>
                      <td className="opt-lg" style={{ maxWidth: 180 }}>
                        {i.campaign_name ? (
                          <span className="trunc hover-link" style={{ display: "block" }} onClick={e => { e.stopPropagation(); navigate(entityRoute("campaign", i.campaign_id)); }}>
                            {i.campaign_name}{i.threat_actor && <span className="faint"> · {i.threat_actor}</span>}
                          </span>
                        ) : <span className="faint">—</span>}
                      </td>
                      <td className="muted num" title={i.created_at}>{fmtDate(i.created_at)}</td>
                      <td className="muted num opt-lg">{timeAgo(i.last_seen)}</td>
                      <td className="muted num opt-xl" title={i.valid_until || "No expiry"}>{i.valid_until ? fmtDate(i.valid_until) : "Never"}</td>
                      <td className="muted opt-xl"><span style={{ color: i.enrichment_state === "error" ? "var(--high)" : undefined }}>{ENRICH_LABEL[i.enrichment_state] || "—"}</span></td>
                      <td><TLPBadge tlp={i.tlp} /></td>
                      <td><StatusBadge status={i.status} /></td>
                      <td className="muted opt-xl">{i.author || <span className="faint">connector</span>}</td>
                      <td onClick={e => e.stopPropagation()}>
                        <Menu trigger={t => <IconButton icon="more" size="sm" title="Actions" onClick={t} />} items={[
                          { label: "Open indicator", icon: "arrowRight", onClick: () => navigate(entityRoute("ioc", i.id)) },
                          { label: "Copy value", icon: "copy", onClick: () => { navigator.clipboard?.writeText(i.value); toast("Copied", "ok"); } },
                          { label: "Search globally", icon: "search", onClick: () => navigate("/search", { q: i.value }) },
                          { label: "Add to Workspace", icon: "briefcase", onClick: () => setPicker(i) },
                          { label: "Open in graph", icon: "graph", onClick: () => navigate("/explorer", { kind: "indicator", id: i.id }) },
                          "sep",
                          ...["suspicious", "confirmed", "unknown", "active"].filter(st => st !== i.status).map(st => ({ label: `Set ${st}`, icon: "flag", onClick: () => setStatus(i, st) })),
                          { label: i.status === "false_positive" ? "Remove FP flag" : "Mark false positive", icon: "alert", onClick: () => toggleFp(i) },
                          can("ioc.delete") && (me?.role === "admin" || i.created_by === me?.id) && { label: "Delete", icon: "trash", danger: true, onClick: () => del(i) },
                        ]} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {picker && (
        <InvestigationPicker withReason={picker !== "bulk"} onClose={() => setPicker(null)} onPick={(inv, reason) => picker === "bulk"
          ? apiJSON("/v2/iocs/bulk-action", { method: "POST", body: { ids: [...sel], action: "add_to_investigation", investigation_id: inv.id } })
          : apiJSON(`/v2/investigations/${enc(inv.id)}/entities`, { method: "POST", body: { kind: "indicator", ref: picker.id, reason } })} />
      )}
      {tagModal && <TagModal onClose={() => setTagModal(false)} onSave={tag => { setTagModal(false); bulk("add_tag", { tag }); }} />}
    </div>
  );
}

function TagModal({ onClose, onSave }) {
  const [t, setT] = useState("");
  return (
    <Modal title="Add tag to selected indicators" onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!t.trim()} onClick={() => onSave(t.trim())}>Add tag</Button></>}>
      <input className="input" autoFocus style={{ width: "100%" }} placeholder="e.g. phishing, c2, apt29" value={t} onChange={e => setT(e.target.value)} onKeyDown={e => e.key === "Enter" && t.trim() && onSave(t.trim())} />
    </Modal>
  );
}

// ── Add IOC ─────────────────────────────────────────────────────────────────
const MITRE_TECHNIQUES = [
  "T1566 - Phishing", "T1566.001 - Spearphishing Attachment", "T1566.002 - Spearphishing Link",
  "T1071 - Application Layer Protocol", "T1071.001 - Web Protocols", "T1071.004 - DNS",
  "T1190 - Exploit Public-Facing Application", "T1059 - Command and Scripting Interpreter",
  "T1078 - Valid Accounts", "T1133 - External Remote Services", "T1486 - Data Encrypted for Impact",
  "T1041 - Exfiltration Over C2 Channel", "T1055 - Process Injection", "T1003 - OS Credential Dumping",
  "T1110 - Brute Force", "T1562 - Impair Defenses", "T1027 - Obfuscated Files or Information",
  "T1105 - Ingress Tool Transfer", "T1021 - Remote Services", "T1140 - Deobfuscate/Decode Files",
];

export function AddIoc() {
  const initialValue = new URLSearchParams(window.location.hash.split("?")[1] || "").get("value") || "";
  const blank = { type: detectType(initialValue) || "IPv4", value: initialValue, industry: "General", tlp: "AMBER", confidence: 75, description: "", tags: "", valid_days: 90, mitre_techniques: [], campaign_id: "" };
  const [form, setForm] = useState(blank);
  const [dup, setDup] = useState(null);
  const [busy, setBusy] = useState(false);
  const [prefill, setPrefill] = useState(false);
  const [err, setErr] = useState("");
  const [result, setResult] = useState(null);
  const campaigns = useApi("/campaigns");
  const set = patch => setForm(f => ({ ...f, ...patch }));

  useEffect(() => {
    const v = form.value.trim();
    if (!v) { setDup(null); return; }
    const t = detectType(v);
    if (t && t !== "CVE" && t !== form.type) set({ type: t });
    const h = setTimeout(async () => {
      try { const d = await apiJSON("/iocs/check", { method: "POST", body: { value: refang(v) } }); setDup(d.exists ? d.existing : null); } catch { /* ignore */ }
    }, 450);
    return () => clearTimeout(h);
  }, [form.value]); // eslint-disable-line react-hooks/exhaustive-deps

  async function aiPrefill() {
    setPrefill(true);
    try {
      const d = await apiJSON("/ai/pre-fill", { method: "POST", body: { ioc_type: form.type, value: form.value, industry: form.industry } });
      set({ description: d.description ?? form.description, tags: Array.isArray(d.tags) ? d.tags.join(", ") : form.tags,
        confidence: d.confidence ?? form.confidence, tlp: TLP_LEVELS.includes(d.tlp) ? d.tlp : form.tlp,
        mitre_techniques: Array.isArray(d.mitre_techniques) ? d.mitre_techniques : form.mitre_techniques });
    } catch (e) { setErr(e.message); }
    setPrefill(false);
  }
  async function submit() {
    setBusy(true); setErr("");
    try {
      const d = await apiJSON("/iocs", { method: "POST", body: {
        ...form, tags: form.tags.split(",").map(t => t.trim()).filter(Boolean),
        confidence: parseInt(form.confidence) || 75, valid_days: parseInt(form.valid_days) || 90, campaign_id: form.campaign_id || null } });
      setResult(d);
    } catch (e) { setErr(e.message); }
    setBusy(false);
  }

  if (result) return (
    <div className="page narrow">
      <PageHeader title="Indicator added" />
      <Panel>
        <Callout tone="ok">Stored as <span className="mono">{result.value_defanged || result.value_canonical}</span> with enriched confidence <strong>{result.confidence}</strong>.</Callout>
        <div style={{ marginTop: 12 }}>
          {(result.enrichment?.confidence_reasons || []).map((r, k) => <div key={k} className="small muted" style={{ padding: "2px 0" }}>› {r}</div>)}
        </div>
        <div className="row" style={{ gap: 8, marginTop: 16 }}>
          <Button variant="primary" icon="arrowRight" onClick={() => navigate(entityRoute("ioc", result.id))}>Open entity</Button>
          <Button onClick={() => { setResult(null); setForm({ ...blank, value: "" }); }}>Add another</Button>
          <Button variant="ghost" onClick={() => navigate("/iocs")}>Back to feed</Button>
        </div>
      </Panel>
    </div>
  );

  return (
    <div className="page narrow">
      <PageHeader title="Add IOC" sub="Fanged or defanged values are normalised. Confidence is validated against VirusTotal, AbuseIPDB and URLhaus (cached 24h)." />
      <div className="grid g-main-side">
        <Panel>
          <Field label="Indicator value">
            <input className="input mono" style={{ height: 36, fontSize: 13 }} autoFocus value={form.value} onChange={e => set({ value: e.target.value })}
              placeholder="hxxp://evil[.]com/payload or 185[.]220[.]101[.]45 or a hash" />
          </Field>
          {dup && (
            <Callout tone="warn" style={{ marginBottom: 14 }}>
              Already tracked — added by <strong>{dup.author || "a connector"}</strong>, confidence {dup.confidence}.{" "}
              <a className="link" href={`#${entityRoute("ioc", dup.id)}`}>Open existing entity →</a>
            </Callout>
          )}
          <div className="grid g3" style={{ gap: 12 }}>
            <Field label="Type"><Select value={form.type} onChange={v => set({ type: v })} options={IOC_TYPES} /></Field>
            <Field label="TLP"><Select value={form.tlp} onChange={v => set({ tlp: v })} options={TLP_LEVELS} /></Field>
            <Field label="Industry"><Select value={form.industry} onChange={v => set({ industry: v })} options={INDUSTRIES} /></Field>
            <Field label="Base confidence"><input className="input" type="number" min={0} max={100} value={form.confidence} onChange={e => set({ confidence: e.target.value })} /></Field>
            <Field label="Expiry (days)"><input className="input" type="number" value={form.valid_days} onChange={e => set({ valid_days: e.target.value })} /></Field>
            <Field label="Campaign"><Select value={form.campaign_id} onChange={v => set({ campaign_id: v })} options={[["", "None"], ...((campaigns.data || []).map(c => [c.id, c.name]))]} /></Field>
          </div>
          <Field label="Description"><textarea className="textarea" rows={3} value={form.description} onChange={e => set({ description: e.target.value })} placeholder="Threat context, where it was observed…" /></Field>
          <Field label="Tags" hint="Comma-separated"><input className="input" value={form.tags} onChange={e => set({ tags: e.target.value })} placeholder="c2, phishing, apt" /></Field>
          <Field label="MITRE ATT&CK techniques">
            <Select value="" onChange={v => v && !form.mitre_techniques.includes(v) && set({ mitre_techniques: [...form.mitre_techniques, v] })}
              options={[["", "Add technique…"], ...MITRE_TECHNIQUES.map(t => [t, t])]} />
            <div className="row wrap" style={{ gap: 4, marginTop: 6 }}>
              {form.mitre_techniques.map(t => <span key={t} className="badge violet" style={{ cursor: "pointer" }} onClick={() => set({ mitre_techniques: form.mitre_techniques.filter(x => x !== t) })}>{t.split(" - ")[0]} ×</span>)}
            </div>
          </Field>
          {err && <Callout tone="error" style={{ marginBottom: 12 }}>{err}</Callout>}
          <div className="row" style={{ gap: 8 }}>
            <Button variant="primary" onClick={submit} loading={busy} disabled={!form.value.trim()}>Validate & save</Button>
            <Button icon="sparkle" onClick={aiPrefill} loading={prefill} disabled={!form.value.trim()}>Pre-fill context</Button>
            <Button variant="ghost" onClick={() => navigate("/iocs")}>Cancel</Button>
          </div>
        </Panel>
        <Panel title="How this is scored">
          <div className="small muted" style={{ lineHeight: 1.65 }}>
            The base confidence you set is adjusted by enrichment: VirusTotal engine detections, AbuseIPDB abuse score and URLhaus listings raise or lower it. Every change is kept in the indicator's score history.
          </div>
          <div className="divider" />
          <div className="small muted" style={{ lineHeight: 1.65 }}>
            Indicators expire after the configured number of days and drop out of STIX/TAXII exports; false positives are kept but excluded.
          </div>
        </Panel>
      </div>
    </div>
  );
}

// ── Import ──────────────────────────────────────────────────────────────────
export function ImportIocs() {
  const [tab, setTab] = useState("stix");
  const [stix, setStix] = useState("");
  const [taxii, setTaxii] = useState({ server_url: "", collection_id: "", token: "" });
  const [misp, setMisp] = useState({ misp_url: "", misp_key: "" });
  const [csv, setCsv] = useState(null);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  async function run() {
    setBusy(true); setRes(null);
    try {
      let d;
      if (tab === "stix") d = await apiJSON("/iocs/import/stix", { method: "POST", body: { bundle: JSON.parse(stix) } });
      if (tab === "taxii") d = await apiJSON("/iocs/import/taxii", { method: "POST", body: { ...taxii, token: taxii.token || null } });
      if (tab === "misp") d = await apiJSON("/iocs/import/misp", { method: "POST", body: misp });
      if (tab === "csv") { const fd = new FormData(); fd.append("file", csv); d = await apiJSON("/iocs/import/csv", { method: "POST", body: fd }); }
      setRes(d);
    } catch (e) { setRes({ error: e.message }); }
    setBusy(false);
  }
  const ready = tab === "stix" ? stix.trim() : tab === "taxii" ? taxii.server_url && taxii.collection_id : tab === "misp" ? misp.misp_url && misp.misp_key : csv;
  return (
    <div className="page narrow">
      <PageHeader title="Import indicators" sub="Every imported indicator is normalised, enriched and de-duplicated by value." />
      <Tabs value={tab} onChange={t => { setTab(t); setRes(null); }} tabs={[{ id: "stix", label: "STIX 2.1 bundle" }, { id: "taxii", label: "TAXII 2.1 poll" }, { id: "misp", label: "MISP pull" }, { id: "csv", label: "CSV upload" }]} />
      <Panel>
        {tab === "stix" && <Field label="STIX bundle JSON"><textarea className="textarea mono" rows={12} value={stix} onChange={e => setStix(e.target.value)} placeholder='{"type":"bundle","spec_version":"2.1","objects":[…]}' /></Field>}
        {tab === "taxii" && <>
          <Field label="TAXII server URL"><input className="input" value={taxii.server_url} onChange={e => setTaxii({ ...taxii, server_url: e.target.value })} placeholder="https://taxii.example.com" /></Field>
          <Field label="Collection ID"><input className="input mono" value={taxii.collection_id} onChange={e => setTaxii({ ...taxii, collection_id: e.target.value })} /></Field>
          <Field label="Bearer token (optional)"><input className="input" type="password" value={taxii.token} onChange={e => setTaxii({ ...taxii, token: e.target.value })} /></Field>
        </>}
        {tab === "misp" && <>
          <Field label="MISP URL"><input className="input" value={misp.misp_url} onChange={e => setMisp({ ...misp, misp_url: e.target.value })} placeholder="https://misp.example.com" /></Field>
          <Field label="API key"><input className="input" type="password" value={misp.misp_key} onChange={e => setMisp({ ...misp, misp_key: e.target.value })} /></Field>
        </>}
        {tab === "csv" && <Field label="CSV file" hint="Columns: type, value, industry, tlp, confidence, description, tags, valid_days"><input type="file" accept=".csv" onChange={e => setCsv(e.target.files[0])} /></Field>}
        <Button variant="primary" onClick={run} loading={busy} disabled={!ready}>Import</Button>
        {res && (res.error
          ? <Callout tone="error" style={{ marginTop: 14 }}>{res.error}</Callout>
          : <Callout tone="ok" style={{ marginTop: 14 }}>Imported <strong>{res.imported}</strong> · skipped {res.skipped}{res.errors?.length ? ` · ${res.errors.length} errors` : ""}. <a className="link" href="#/iocs?sort=created">View in feed →</a></Callout>)}
      </Panel>
    </div>
  );
}

// ── Export ──────────────────────────────────────────────────────────────────
export function ExportIocs() {
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const { data } = useApi("/v2/iocs?limit=1&status=live");
  const rows = [
    ["TAXII discovery", `${API_BASE}/taxii/`],
    ["Collection ID", "a45ef559-3f21-4b78-9cde-ef0123456789"],
    ["Objects endpoint", `${API_BASE}/collections/a45ef559-3f21-4b78-9cde-ef0123456789/objects/`],
    ["Authentication", "Authorization: Bearer <jwt-token>"],
    ["Suggested poll interval", "3600 seconds"],
  ];
  return (
    <div className="page narrow">
      <PageHeader title="Export indicators" sub="Active, non-false-positive indicators are published as STIX 2.1 and over TAXII 2.1 (OpenCTI compatible)." />
      <div className="grid g2">
        <Panel title="STIX 2.1 bundle">
          <div className="small muted" style={{ marginBottom: 12 }}>{data ? `${fmtNum(data.total)} active indicators` : "…"} will be included.</div>
          <Button variant="primary" icon="download" loading={busy} onClick={async () => {
            setBusy(true);
            try { await downloadJSON("/stix/bundle", `tfii-stix-bundle-${Date.now()}.json`); } catch (e) { toast(e.message, "error"); }
            setBusy(false);
          }}>Download bundle</Button>
        </Panel>
        <Panel title="TAXII 2.1 server" tight>
          {rows.map(([k, v]) => (
            <div key={k} className="list-row"><span className="faint" style={{ width: 150 }}>{k}</span><span className="mono trunc" style={{ flex: 1 }}>{v}</span><CopyButton value={v} /></div>
          ))}
        </Panel>
      </div>
    </div>
  );
}
