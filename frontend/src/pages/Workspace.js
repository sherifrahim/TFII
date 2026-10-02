import React, { useEffect, useMemo, useState } from "react";
import { useApi, apiJSON, api, getToken } from "../lib/api";
import { navigate, setQuery, entityRoute, enc } from "../lib/router";
import { useSession, pushRecentEntity } from "../lib/session";
import { fmtDate, fmtDateTime, timeAgo, detectType, refang, typeGroup } from "../lib/format";
import {
  PageHeader, Panel, Button, IconButton, Badge, TypeBadge, Conf, StatusBadge, SevBadge, Tabs, Modal, Field, Select, SearchInput,
  EmptyState, ErrorState, Loading, Skeleton, CopyButton, Menu, useToast, actionable, rowAction,
} from "../components/ui";
import { ReasonModal } from "./entity/parts";
import Graph from "../components/Graph";
import Icon from "../components/Icon";
import { SEV_COLOR, LEGACY_C } from "../design/tokens";
import { LegacyNotes } from "../legacy/lazy";
import AiPanel from "../components/AiPanel";

const STATUSES = [["open", "Open"], ["active", "Active"], ["monitoring", "Monitoring"], ["closed", "Closed"]];
const SEVS = [["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]];

export function WorkspacePage({ query }) {
  const { can } = useSession();
  const tab = query.tab || "investigations";
  const [status, setStatus] = useState("open,active,monitoring");
  const [q, setQ] = useState("");
  const { data, error, loading, reload } = useApi(`/v2/investigations?status=${enc(status)}`);
  const [creating, setCreating] = useState(query.new === "1");
  const rows = (data?.investigations || []).filter(i => !q || `${i.name} ${i.key} ${(i.tags || []).join(" ")}`.toLowerCase().includes(q.toLowerCase()));

  return (
    <div className="page">
      <PageHeader title="Workspace" sub="Investigations collect indicators, infrastructure, detections, notes and a timeline in one place."
        actions={<Button size="sm" variant="primary" icon="plus" onClick={() => setCreating(true)}>New investigation</Button>} />
      <Tabs value={tab} onChange={t => setQuery({ tab: t === "investigations" ? "" : t, new: "" })} tabs={[
        { id: "investigations", label: "Investigations", icon: "briefcase" },
        can("admin.panel") && { id: "notes", label: "Notes & checklists", icon: "note" },
      ]} />
      {tab === "notes" && can("admin.panel") && <div className="legacy-host"><LegacyNotes token={getToken()} C={LEGACY_C} /></div>}
      {tab === "investigations" && <>
        <div className="row wrap" style={{ gap: 8, marginBottom: 10 }}>
          <SearchInput value={q} onChange={setQ} placeholder="Filter investigations" style={{ width: 280 }} />
          <div className="seg">
            {[["open,active,monitoring", "In progress"], ["closed", "Closed"], ["", "All"]].map(([v, l]) => <button key={l} className={status === v ? "on" : ""} onClick={() => setStatus(v)}>{l}</button>)}
          </div>
        </div>
        <Panel tight bodyStyle={{ padding: 0 }}>
          {error ? <ErrorState error={error} onRetry={reload} /> : loading && !data ? <div style={{ padding: 16 }}><Skeleton h={120} /></div> :
            rows.length === 0 ? <EmptyState icon="briefcase" title="No investigations" desc="Open an investigation to track a campaign, an incident or a hunt — then add IOCs to it from any entity page or the IOC table."
              action={<Button size="sm" variant="primary" onClick={() => setCreating(true)}>New investigation</Button>} /> : (
              <table className="tbl">
                <thead><tr><th>Investigation</th><th>Severity</th><th>Status</th><th className="r">IOCs</th><th className="r">CVEs</th><th className="r">Notes</th><th>Owner</th><th>Last activity</th></tr></thead>
                <tbody>{rows.map(i => (
                  <tr key={i.id} className="clickable" onClick={() => navigate(`/investigations/${enc(i.id)}`)}>
                    <td className="primary"><div className="row" style={{ gap: 8 }}><span className="mono faint xs">{i.key}</span><span className="strong" style={{ fontWeight: 500 }}>{i.name}</span></div>
                      {(i.tags || []).length > 0 && <div className="row" style={{ gap: 3, marginTop: 2 }}>{i.tags.slice(0, 4).map(t => <span key={t} className="tag">{t}</span>)}</div>}</td>
                    <td><Badge tone={i.severity} dot>{i.severity}</Badge></td>
                    <td><Badge outline>{i.status}</Badge></td>
                    <td className="r num">{i.iocs}</td><td className="r num">{i.cves}</td><td className="r num">{i.notes}</td>
                    <td className="muted">{i.owner_name}</td>
                    <td className="muted">{timeAgo(i.last_event || i.updated_at)}</td>
                  </tr>))}</tbody>
              </table>
            )}
        </Panel>
      </>}
      {creating && <NewInvestigation onClose={() => { setCreating(false); if (query.new) setQuery({ new: "" }); }} />}
    </div>
  );
}

function NewInvestigation({ onClose }) {
  const [f, setF] = useState({ name: "", description: "", severity: "medium", tags: "" });
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  async function create() {
    setBusy(true);
    try {
      const inv = await apiJSON("/v2/investigations", { method: "POST", body: { ...f, tags: f.tags.split(",").map(t => t.trim()).filter(Boolean) } });
      navigate(`/investigations/${enc(inv.id)}`);
    } catch (e) { toast(e.message, "error"); setBusy(false); }
  }
  return (
    <Modal title="New investigation" onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" onClick={create} loading={busy} disabled={!f.name.trim()}>Create investigation</Button></>}>
      <Field label="Name"><input className="input" autoFocus value={f.name} onChange={e => setF({ ...f, name: e.target.value })} placeholder="e.g. SHAI-HULUD npm worm infrastructure" /></Field>
      <div className="grid g2" style={{ gap: 12 }}>
        <Field label="Severity"><Select value={f.severity} onChange={v => setF({ ...f, severity: v })} options={SEVS} /></Field>
        <Field label="Tags" hint="Comma-separated"><input className="input" value={f.tags} onChange={e => setF({ ...f, tags: e.target.value })} /></Field>
      </div>
      <Field label="Scope / hypothesis"><textarea className="textarea" rows={4} value={f.description} onChange={e => setF({ ...f, description: e.target.value })} /></Field>
    </Modal>
  );
}

// ── Investigation ───────────────────────────────────────────────────────────
export function InvestigationPage({ id, tab = "overview" }) {
  const { data, error, loading, reload } = useApi(`/v2/investigations/${enc(id)}`);
  const { can } = useSession();
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [reasonFor, setReasonFor] = useState(null);
  useEffect(() => { if (data?.investigation) pushRecentEntity({ kind: "investigation", ref: id, label: data.investigation.name }); }, [data, id]);
  if (error) return <div className="page"><ErrorState error={error} onRetry={reload} /></div>;
  if (loading && !data) return <div className="page"><Loading /></div>;
  const inv = data.investigation, st = data.stats;
  const setTab = t => setQuery({ tab: t === "overview" ? "" : t });
  const patch = async body => { try { await apiJSON(`/v2/investigations/${enc(id)}`, { method: "PATCH", body }); reload(true); } catch (e) { toast(e.message, "error"); } };
  const removeItem = async it => {
    const r = await api(`/v2/investigations/${enc(id)}/items/${it.id}`, { method: "DELETE" });
    if (r.ok) reload(true); else toast("Could not remove", "error");
  };
  async function del() {
    if (!window.confirm(`Delete ${inv.key}? Items and timeline are removed; notes are kept in the workspace.`)) return;
    const r = await api(`/v2/investigations/${enc(id)}`, { method: "DELETE" });
    if (r.ok) navigate("/workspace"); else toast("Delete failed (admin only)", "error");
  }
  const byType = t => data.items.filter(i => (Array.isArray(t) ? t.includes(i.item_type) : i.item_type === t));
  const indicators = byType(["ioc", "observable"]);
  const detections = byType(["query", "detection"]);
  const artifacts = byType(["artifact", "screenshot"]);
  const linked = byType(["cve", "campaign", "actor", "malware", "asset"]);

  return (
    <div className="page">
      <div className="entity-head">
        <div style={{ minWidth: 0 }}>
          <div className="row wrap" style={{ gap: 6, marginBottom: 6 }}>
            <span className="mono faint">{inv.key}</span>
            <select className="select" style={{ height: 24, fontSize: 11.5 }} value={inv.severity} onChange={e => patch({ severity: e.target.value })} aria-label="Severity">{SEVS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
            <select className="select" style={{ height: 24, fontSize: 11.5 }} value={inv.status} onChange={e => patch({ status: e.target.value })} aria-label="Status">{STATUSES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
            {(inv.tags || []).map(t => <span key={t} className="tag">{t}</span>)}
          </div>
          <h1 className="page-title" style={{ fontSize: 24 }}><span className="sev-dot" style={{ background: SEV_COLOR[inv.severity], width: 10, height: 10, marginRight: 10, verticalAlign: 3 }} />{inv.name}</h1>
          <div className="page-sub">Opened by {inv.owner_name || "—"} {timeAgo(inv.created_at)} · updated {timeAgo(inv.updated_at)}</div>
        </div>
        <div className="page-actions">
          <Button size="sm" icon="edit" onClick={() => setEditing(true)}>Edit</Button>
          <Button size="sm" icon="graph" onClick={() => navigate("/explorer", { kind: "investigation", id })}>Explorer</Button>
          <Button size="sm" icon="download" onClick={() => exportReport(data)}>Export report</Button>
          {can("admin.panel") && <IconButton icon="trash" title="Delete investigation" onClick={del} />}
        </div>
      </div>
      <div className="facts">
        {[["IOCs", st.iocs, "iocs"], ["Domains", st.domains, "infra"], ["IPs", st.ips, "infra"], ["URLs", st.urls, "infra"], ["Hashes", st.hashes, "iocs"],
          ["CVEs", st.cves, "overview"], ["Queries & detections", st.queries + st.detections, "detection"], ["Notes", st.notes, "notes"]].map(([l, v, t]) => (
          <div key={l} className="fact" style={{ cursor: "pointer" }} onClick={() => setTab(t)}><div className="fact-l">{l}</div><div className="fact-v num" style={{ fontSize: 18 }}>{v}</div></div>
        ))}
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "overview", label: "Overview" }, { id: "iocs", label: "IOCs", count: indicators.length },
        { id: "infra", label: "Infrastructure" }, { id: "detection", label: "Detection", count: detections.length },
        { id: "timeline", label: "Timeline", count: data.events.length }, { id: "notes", label: "Notes", count: data.notes.length },
        { id: "artifacts", label: "Artifacts", count: artifacts.length },
      ]} />

      {tab === "overview" && (
        <div className="grid g-main-side">
          <div className="stack">
            <AiPanel title="AI write-up" cta="Draft write-up" hint="An executive summary, findings and next steps drawn from this investigation's items, timeline and notes."
              path="/v2/ai/investigation" body={{ id }} />
            <Panel title="Scope">
              <div className="small" style={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: inv.description ? "var(--text-2)" : "var(--text-4)" }}>{inv.description || "No scope written yet — use Edit to describe the hypothesis and what's in and out of scope."}</div>
            </Panel>
            <Panel title="Linked intelligence" tight actions={<AddLinked invId={id} onDone={() => reload(true)} />}>
              {linked.length === 0 ? <div className="faint small" style={{ padding: 16 }}>Link CVEs, campaigns, threat actors or malware families this investigation covers.</div> :
                linked.map(it => (
                  <div key={it.id} className="list-row clickable" style={{ alignItems: "flex-start", padding: "8px 16px" }}
                    {...actionable(() => navigate(entityRoute(it.item_type, it.ref_id || it.value, id)))}>
                    <Badge outline>{it.item_type === "asset" ? "software" : it.item_type}</Badge>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className={it.item_type === "cve" ? "mono" : ""} style={{ overflowWrap: "anywhere" }}>{it.item_type === "cve" ? it.ref_id : (it.label || it.value)}</div>
                      <div className="xs" style={{ color: it.reason ? "var(--text-3)" : "var(--text-4)", overflowWrap: "anywhere" }}>{it.reason ? `Relevant because: ${it.reason}` : "No reason recorded"}</div>
                    </div>
                    {it.cve && <>{it.cve.kev_listed && <Badge tone="critical">KEV</Badge>}<SevBadge severity={it.cve.severity} score={it.cve.cvss_score} /><span className="faint xs">{it.cve.asset_name}</span></>}
                    <IconButton icon="edit" size="sm" title="Edit reason" onClick={e => { e.stopPropagation(); setReasonFor(it); }} />
                    <IconButton icon="x" size="sm" title="Remove" onClick={e => { e.stopPropagation(); removeItem(it); }} />
                  </div>
                ))}
            </Panel>
          </div>
          <Panel title="Recent activity" actions={<Button size="xs" variant="ghost" onClick={() => setTab("timeline")}>Full timeline</Button>}>
            <Timeline events={data.events.slice(0, 8)} />
          </Panel>
        </div>
      )}
      {tab === "iocs" && <IocsTab id={id} items={indicators} reload={reload} remove={removeItem} editReason={setReasonFor} />}
      {tab === "infra" && <InfraTab id={id} items={indicators} />}
      {tab === "detection" && <DetectionTab id={id} items={detections} reload={reload} remove={removeItem} />}
      {tab === "timeline" && <TimelineTab id={id} events={data.events} reload={reload} />}
      {tab === "notes" && <NotesTab id={id} notes={data.notes} reload={reload} />}
      {tab === "artifacts" && <ArtifactsTab id={id} items={artifacts} reload={reload} remove={removeItem} />}
      {reasonFor && <ReasonModal title="Why is this relevant?" initial={reasonFor.reason} onClose={() => setReasonFor(null)}
        onSave={async r => { try { await apiJSON(`/v2/investigations/${enc(id)}/items/${reasonFor.id}`, { method: "PATCH", body: { reason: r } }); setReasonFor(null); reload(true); } catch (e) { toast(e.message, "error"); } }} />}
      {editing && <EditInvestigation inv={inv} onClose={() => setEditing(false)} onSave={async b => { await patch(b); setEditing(false); }} />}
    </div>
  );
}

function EditInvestigation({ inv, onClose, onSave }) {
  const [f, setF] = useState({ name: inv.name, description: inv.description || "", tags: (inv.tags || []).join(", ") });
  return (
    <Modal title={`Edit ${inv.key}`} onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" onClick={() => onSave({ ...f, tags: f.tags.split(",").map(t => t.trim()).filter(Boolean) })}>Save</Button></>}>
      <Field label="Name"><input className="input" value={f.name} onChange={e => setF({ ...f, name: e.target.value })} /></Field>
      <Field label="Tags" hint="Comma-separated"><input className="input" value={f.tags} onChange={e => setF({ ...f, tags: e.target.value })} /></Field>
      <Field label="Scope / hypothesis"><textarea className="textarea" rows={6} value={f.description} onChange={e => setF({ ...f, description: e.target.value })} /></Field>
    </Modal>
  );
}

function AddLinked({ invId, onDone }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState("cve");
  const [val, setVal] = useState("");
  const [reason, setReason] = useState("");
  const campaigns = useApi(open && kind === "campaign" ? "/campaigns" : null);
  const assets = useApi(open && kind === "software" ? "/assets" : null);
  const toast = useToast();
  async function add() {
    try {
      await apiJSON(`/v2/investigations/${enc(invId)}/entities`, { method: "POST", body: { kind, ref: val.trim(), reason: reason.trim() || null } });
      setOpen(false); setVal(""); setReason(""); onDone();
    } catch (e) { toast(e.message, "error"); }
  }
  const pick = kind === "campaign" ? campaigns.data : kind === "software" ? assets.data : null;
  return (<>
    <Button size="xs" icon="plus" onClick={() => setOpen(true)}>Link</Button>
    {open && (
      <Modal title="Link intelligence" onClose={() => setOpen(false)}
        footer={<><Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" disabled={!val.trim()} onClick={add}>Link</Button></>}>
        <Field label="Type"><Select value={kind} onChange={v => { setKind(v); setVal(""); }} options={[["cve", "CVE"], ["campaign", "Campaign"], ["actor", "Threat actor"], ["malware", "Malware family"], ["software", "Software"]]} /></Field>
        <Field label={kind === "cve" ? "CVE ID" : kind === "campaign" ? "Campaign" : kind === "software" ? "Software" : "Name"}>
          {pick !== null && ["campaign", "software"].includes(kind)
            ? <Select value={val} onChange={setVal} options={[["", `Select ${kind === "campaign" ? "a campaign" : "software"}…`], ...(pick || []).map(c => [c.id, c.name])]} />
            : <input className={`input ${kind === "cve" ? "mono" : ""}`} autoFocus value={val} onChange={e => setVal(e.target.value)} placeholder={kind === "cve" ? "CVE-2025-12345" : ""} />}
        </Field>
        <Field label="Why is it relevant? (optional)"><input className="input" value={reason} maxLength={500} onChange={e => setReason(e.target.value)} /></Field>
      </Modal>
    )}
  </>);
}

function IocsTab({ id, items, reload, remove, editReason }) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");
  const toast = useToast();
  async function add() {
    const values = [...new Set(text.split(/[\n,;\s]+/).map(v => refang(v.trim())).filter(Boolean))].slice(0, 200);
    if (!values.length) return;
    setBusy(true);
    let added = 0, dup = 0;
    for (const v of values) {
      try { await apiJSON(`/v2/investigations/${enc(id)}/items`, { method: "POST", body: { item_type: "ioc", value: v } }); added++; }
      catch (e) { if (e.status === 409) dup++; else toast(`${v}: ${e.message}`, "error"); }
    }
    setBusy(false); setText(""); reload(true);
    toast(`${added} added${dup ? ` · ${dup} already present` : ""}`, "ok");
  }
  const rows = items.filter(i => !filter || (i.ioc_value || i.value || "").toLowerCase().includes(filter.toLowerCase()));
  return (
    <div className="grid g-main-side">
      <Panel tight bodyStyle={{ padding: 0 }} title="Indicators" actions={<SearchInput value={filter} onChange={setFilter} placeholder="Filter" style={{ width: 200 }} />}>
        {rows.length === 0 ? <EmptyState icon="crosshair" title="No indicators yet" desc="Paste values on the right, or use “Add to investigation” from the IOC table and entity pages." /> : (
          <div className="tbl-wrap" tabIndex={0}><table className="tbl"><thead><tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Status</th><th>Relevant because</th><th>Added</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{rows.map(it => {
              const tracked = it.item_type === "ioc";
              const type = it.ioc_type || it.data?.type || it.label;
              return (
                <tr key={it.id} className="clickable" {...rowAction(() => navigate(tracked ? entityRoute("ioc", it.ref_id, id) : entityRoute("indicator", it.value, id)))}>
                  <td className="cellmono trunc" style={{ maxWidth: 420 }}>{it.ioc_value || it.value}{it.malware_family && it.malware_family !== "unknown" && <Badge tone="violet" style={{ marginLeft: 6 }}>{it.malware_family}</Badge>}</td>
                  <td><TypeBadge type={type} /></td>
                  <td>{tracked ? <Conf value={it.ioc_confidence} /> : <span className="faint xs">untracked</span>}</td>
                  <td>{tracked ? <StatusBadge status={it.ioc_status} /> : <Badge outline>Observable</Badge>}</td>
                  <td className="wrapcell" style={{ maxWidth: 260, overflowWrap: "anywhere", color: it.reason ? "var(--text-2)" : "var(--text-4)" }}>{it.reason || "—"}</td>
                  <td className="muted">{timeAgo(it.created_at)} <span className="faint">· {it.created_by}</span></td>
                  <td onClick={e => e.stopPropagation()}><Menu trigger={t => <IconButton icon="more" size="sm" title="Actions" onClick={t} />} items={[
                    !tracked && { label: "Track as IOC", icon: "plus", onClick: () => navigate("/iocs/new", { value: it.value }) },
                    { label: "Edit reason", icon: "edit", onClick: () => editReason(it) },
                    { label: "Copy value", icon: "copy", onClick: () => navigator.clipboard?.writeText(it.ioc_value || it.value) },
                    { label: "Remove from investigation", icon: "x", danger: true, onClick: () => remove(it) },
                  ]} /></td>
                </tr>
              );
            })}</tbody></table></div>
        )}
      </Panel>
      <Panel title="Add indicators">
        <textarea className="textarea mono" rows={8} style={{ width: "100%" }} value={text} onChange={e => setText(e.target.value)}
          placeholder={"One per line — fanged or defanged\nevil[.]example\n185.220.101.45\nhxxps://…"} />
        <div className="faint xs" style={{ margin: "6px 0 10px" }}>Values already in the IOC database are linked; unknown ones are kept as untracked observables until you choose to track them.</div>
        <Button variant="primary" onClick={add} loading={busy} disabled={!text.trim()} style={{ width: "100%" }}>Add to investigation</Button>
      </Panel>
    </div>
  );
}

function InfraTab({ id, items }) {
  const graph = useApi(`/v2/entity/graph?kind=investigation&ref=${enc(id)}&depth=1`);
  const groups = useMemo(() => {
    const g = { domain: [], ip: [], url: [], hash: [], email: [] };
    items.forEach(it => { const t = typeGroup(it.ioc_type || it.data?.type || detectType(it.value || "")); if (g[t]) g[t].push(it); });
    return g;
  }, [items]);
  return (
    <div className="stack">
      <Panel title="Infrastructure graph">{!graph.data ? <Skeleton h={400} /> : <Graph data={graph.data} centerId={graph.data.center} height={500} emptyText="Add indicators to map infrastructure." />}</Panel>
      <div className="grid g4">
        {[["domain", "Domains"], ["ip", "IP addresses"], ["url", "URLs"], ["hash", "File hashes"]].map(([k, l]) => (
          <Panel key={k} title={l} sub={String(groups[k].length)} tight>
            {groups[k].length === 0 ? <div className="faint small" style={{ padding: "4px 16px 12px" }}>None</div> :
              groups[k].map(it => <div key={it.id} className="list-row clickable" {...actionable(() => navigate(it.item_type === "ioc" ? entityRoute("ioc", it.ref_id, id) : entityRoute("indicator", it.value, id)))}><span className="mono trunc">{it.ioc_value || it.value}</span></div>)}
          </Panel>
        ))}
      </div>
    </div>
  );
}

function DetectionTab({ id, items, reload, remove }) {
  const [f, setF] = useState({ kind: "query", name: "", language: "kql", body: "" });
  const toast = useToast();
  async function add() {
    try {
      await apiJSON(`/v2/investigations/${enc(id)}/items`, { method: "POST", body: { item_type: f.kind, label: f.name || `${f.language.toUpperCase()} ${f.kind}`, value: f.name || f.body.slice(0, 80), data: { language: f.language, [f.kind === "query" ? "query" : "rule"]: f.body } } });
      setF({ ...f, name: "", body: "" }); reload(true);
    } catch (e) { toast(e.message, "error"); }
  }
  return (
    <div className="grid g-main-side">
      <div className="stack">
        {items.length === 0 && <Panel><EmptyState icon="code" title="No queries or detections yet" desc="Save hunting queries and detection rules here — from an IOC's Detection tab, the Query Builder, or by pasting them on the right." /></Panel>}
        {items.map(it => {
          const body = it.data?.query || it.data?.rule || it.value;
          return (
            <Panel key={it.id} title={<><Badge outline>{it.item_type}</Badge> {it.label || it.value}</>} sub={`${(it.data?.language || "").toUpperCase()} · ${it.created_by || ""} · ${timeAgo(it.created_at)}`}
              actions={<><CopyButton value={body} /><IconButton icon="trash" size="sm" title="Remove" onClick={() => remove(it)} /></>}>
              <pre className="code">{body}</pre>
            </Panel>
          );
        })}
      </div>
      <Panel title="Save a query or rule">
        <div className="grid g2" style={{ gap: 10 }}>
          <Field label="Kind"><Select value={f.kind} onChange={v => setF({ ...f, kind: v })} options={[["query", "Hunting query"], ["detection", "Detection rule"]]} /></Field>
          <Field label="Language"><Select value={f.language} onChange={v => setF({ ...f, language: v })} options={[["kql", "KQL"], ["spl", "SPL"], ["sigma", "Sigma"], ["yara", "YARA"], ["suricata", "Suricata"], ["other", "Other"]]} /></Field>
        </div>
        <Field label="Name"><input className="input" value={f.name} onChange={e => setF({ ...f, name: e.target.value })} placeholder="C2 beaconing to campaign IPs" /></Field>
        <Field label="Body"><textarea className="textarea mono" rows={8} value={f.body} onChange={e => setF({ ...f, body: e.target.value })} /></Field>
        <div className="row" style={{ gap: 8 }}><Button variant="primary" onClick={add} disabled={!f.body.trim()}>Save</Button><Button variant="ghost" onClick={() => navigate("/query")}>Open Query Builder</Button></div>
      </Panel>
    </div>
  );
}

function Timeline({ events, onDelete }) {
  if (!events.length) return <div className="faint small">No activity yet.</div>;
  return (
    <div className="tl">
      {events.map(e => (
        <div key={e.id} className={`tl-item ${e.event_type === "manual" ? "accent" : e.event_type === "created" ? "accent" : ""}`}>
          <div className="tl-date row" style={{ gap: 6 }}>{fmtDateTime(e.occurred_at)}{e.created_by && <span>· {e.created_by}</span>}
            {onDelete && e.event_type === "manual" && <button className="btn ghost xs" onClick={() => onDelete(e)}>remove</button>}</div>
          <div className="tl-title">
            {e.ref_type === "ioc" && e.ref_id ? <a className="hover-link" href={`#${entityRoute("ioc", e.ref_id)}`}>{e.title}</a>
              : e.ref_type === "cve" && e.ref_id ? <a className="hover-link" href={`#${entityRoute("cve", e.ref_id)}`}>{e.title}</a> : e.title}
          </div>
          {e.body && <div className="tl-body">{e.body}</div>}
        </div>
      ))}
    </div>
  );
}

function TimelineTab({ id, events, reload }) {
  const [f, setF] = useState({ title: "", body: "", at: "" });
  const toast = useToast();
  async function add() {
    try { await apiJSON(`/v2/investigations/${enc(id)}/events`, { method: "POST", body: { title: f.title, body: f.body, occurred_at: f.at ? new Date(f.at).toISOString().slice(0, 19) : undefined } }); setF({ title: "", body: "", at: "" }); reload(true); }
    catch (e) { toast(e.message, "error"); }
  }
  async function del(e) {
    const r = await api(`/v2/investigations/${enc(id)}/events/${e.id}`, { method: "DELETE" });
    if (r.ok) reload(true);
  }
  // Group by day for readability.
  const days = useMemo(() => {
    const m = [];
    events.forEach(e => { const d = fmtDate(e.occurred_at); const last = m[m.length - 1]; if (last && last.d === d) last.e.push(e); else m.push({ d, e: [e] }); });
    return m;
  }, [events]);
  return (
    <div className="grid g-main-side">
      <Panel title="Timeline">
        {days.length === 0 ? <div className="faint small">No events.</div> : days.map(g => (
          <div key={g.d} style={{ marginBottom: 8 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>{g.d}</div>
            <Timeline events={g.e} onDelete={del} />
          </div>
        ))}
      </Panel>
      <Panel title="Record an event">
        <Field label="When" hint="Leave empty for now"><input className="input" type="datetime-local" value={f.at} onChange={e => setF({ ...f, at: e.target.value })} /></Field>
        <Field label="What happened"><input className="input" value={f.title} onChange={e => setF({ ...f, title: e.target.value })} placeholder="New infrastructure discovered" /></Field>
        <Field label="Details"><textarea className="textarea" rows={4} value={f.body} onChange={e => setF({ ...f, body: e.target.value })} /></Field>
        <Button variant="primary" onClick={add} disabled={!f.title.trim()}>Add to timeline</Button>
      </Panel>
    </div>
  );
}

function NotesTab({ id, notes, reload }) {
  const [edit, setEdit] = useState(null);
  const toast = useToast();
  async function save() {
    try {
      if (edit.id) await apiJSON(`/v2/investigations/${enc(id)}/notes/${enc(edit.id)}`, { method: "PATCH", body: edit });
      else await apiJSON(`/v2/investigations/${enc(id)}/notes`, { method: "POST", body: edit });
      setEdit(null); reload(true);
    } catch (e) { toast(e.message, "error"); }
  }
  async function del(n) {
    if (!window.confirm("Delete this note?")) return;
    const r = await api(`/v2/investigations/${enc(id)}/notes/${enc(n.id)}`, { method: "DELETE" });
    if (r.ok) reload(true);
  }
  return (
    <div className="stack">
      <div className="row"><span className="spacer" /><Button size="sm" variant="primary" icon="plus" onClick={() => setEdit({ title: "", content: "", pinned: false, tags: [] })}>New note</Button></div>
      {notes.length === 0 && <Panel><EmptyState icon="note" title="No notes yet" desc="Capture findings, analyst reasoning and hand-off context." /></Panel>}
      <div className="grid g2">
        {notes.map(n => (
          <Panel key={n.id} title={<>{n.pinned && <Icon name="pin" size={13} />} {n.title || "Untitled"}</>} sub={timeAgo(n.updated_at)}
            actions={<><IconButton icon="edit" size="sm" title="Edit" onClick={() => setEdit(n)} /><IconButton icon="trash" size="sm" title="Delete" onClick={() => del(n)} /></>}>
            <div className="small" style={{ whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{n.content}</div>
          </Panel>
        ))}
      </div>
      {edit && (
        <Modal title={edit.id ? "Edit note" : "New note"} onClose={() => setEdit(null)} wide
          footer={<><label className="check" style={{ marginRight: "auto" }}><input type="checkbox" checked={!!edit.pinned} onChange={e => setEdit({ ...edit, pinned: e.target.checked })} />Pinned</label>
            <Button variant="ghost" onClick={() => setEdit(null)}>Cancel</Button><Button variant="primary" onClick={save}>Save</Button></>}>
          <Field label="Title"><input className="input" autoFocus value={edit.title || ""} onChange={e => setEdit({ ...edit, title: e.target.value })} /></Field>
          <Field label="Note"><textarea className="textarea" rows={12} value={edit.content || ""} onChange={e => setEdit({ ...edit, content: e.target.value })} /></Field>
        </Modal>
      )}
    </div>
  );
}

function ArtifactsTab({ id, items, reload, remove }) {
  const [f, setF] = useState({ kind: "artifact", label: "", url: "", description: "" });
  const toast = useToast();
  async function add() {
    try {
      await apiJSON(`/v2/investigations/${enc(id)}/items`, { method: "POST", body: { item_type: f.kind, value: f.url || f.label, label: f.label, data: { url: f.url, description: f.description } } });
      setF({ kind: f.kind, label: "", url: "", description: "" }); reload(true);
    } catch (e) { toast(e.message, "error"); }
  }
  return (
    <div className="grid g-main-side">
      <Panel tight title="Artifacts & screenshots">
        {items.length === 0 ? <EmptyState icon="folder" title="No artifacts" desc="Reference evidence here — report links, screenshots in your evidence store, exported logs, ticket URLs." /> :
          items.map(it => (
            <div key={it.id} className="list-row" style={{ alignItems: "flex-start", padding: "10px 16px" }}>
              <Icon name={it.item_type === "screenshot" ? "eye" : "fileText"} size={15} style={{ marginTop: 2, color: "var(--text-3)" }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="strong" style={{ fontWeight: 500 }}>{it.label || it.value}</div>
                {it.data?.url && /^https?:\/\//i.test(it.data.url) && <a className="link xs trunc" style={{ display: "block" }} href={it.data.url} target="_blank" rel="noreferrer noopener">{it.data.url}</a>}
                {it.data?.description && <div className="small muted" style={{ marginTop: 2 }}>{it.data.description}</div>}
                <div className="faint xs">{it.created_by} · {timeAgo(it.created_at)}</div>
              </div>
              <IconButton icon="trash" size="sm" title="Remove" onClick={() => remove(it)} />
            </div>
          ))}
      </Panel>
      <Panel title="Add an artifact">
        <Field label="Kind"><Select value={f.kind} onChange={v => setF({ ...f, kind: v })} options={[["artifact", "Artifact / evidence"], ["screenshot", "Screenshot"]]} /></Field>
        <Field label="Title"><input className="input" value={f.label} onChange={e => setF({ ...f, label: e.target.value })} /></Field>
        <Field label="Link" hint="Where the evidence lives (evidence store, ticket, report)"><input className="input" value={f.url} onChange={e => setF({ ...f, url: e.target.value })} placeholder="https://" /></Field>
        <Field label="Description"><textarea className="textarea" rows={3} value={f.description} onChange={e => setF({ ...f, description: e.target.value })} /></Field>
        <Button variant="primary" onClick={add} disabled={!f.label.trim() && !f.url.trim()}>Add artifact</Button>
      </Panel>
    </div>
  );
}

// Markdown export of the whole investigation (client-side, from loaded data).
function exportReport(data) {
  const inv = data.investigation;
  const L = [];
  L.push(`# ${inv.key} — ${inv.name}`, "", `**Severity:** ${inv.severity} · **Status:** ${inv.status} · **Owner:** ${inv.owner_name || "—"} · **Opened:** ${fmtDate(inv.created_at)}`, "");
  if (inv.description) L.push("## Scope", "", inv.description, "");
  const ind = data.items.filter(i => i.item_type === "ioc" || i.item_type === "observable");
  if (ind.length) { L.push("## Indicators", "", "| Type | Value | Confidence | Status |", "|---|---|---|---|"); ind.forEach(i => L.push(`| ${i.ioc_type || i.data?.type || ""} | \`${(i.ioc_defanged || i.ioc_value || i.value || "").replace(/\|/g, "\\|")}\` | ${i.ioc_confidence ?? "—"} | ${i.ioc_status || "untracked"} |`)); L.push(""); }
  const linked = data.items.filter(i => ["cve", "campaign", "actor", "malware"].includes(i.item_type));
  if (linked.length) { L.push("## Linked intelligence", ""); linked.forEach(i => L.push(`- **${i.item_type}**: ${i.item_type === "cve" ? i.ref_id : i.label || i.value}${i.cve ? ` (CVSS ${i.cve.cvss_score ?? "?"}${i.cve.kev_listed ? ", CISA KEV" : ""})` : ""}`)); L.push(""); }
  const det = data.items.filter(i => i.item_type === "query" || i.item_type === "detection");
  if (det.length) { L.push("## Detection", ""); det.forEach(i => L.push(`### ${i.label || i.value}`, "", "```" + (i.data?.language || ""), i.data?.query || i.data?.rule || i.value, "```", "")); }
  if (data.events.length) { L.push("## Timeline", ""); [...data.events].reverse().forEach(e => L.push(`- ${fmtDateTime(e.occurred_at)} — ${e.title}${e.body ? `: ${e.body}` : ""}`)); L.push(""); }
  if (data.notes.length) { L.push("## Notes", ""); data.notes.forEach(n => L.push(`### ${n.title || "Note"}`, "", n.content || "", "")); }
  const blob = new Blob([L.join("\n")], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `${inv.key}-${inv.name.replace(/[^\w-]+/g, "_").slice(0, 40)}.md`; a.click();
  URL.revokeObjectURL(url);
}
