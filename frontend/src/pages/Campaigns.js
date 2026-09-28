import React, { useEffect, useState } from "react";
import { useApi, apiJSON, api } from "../lib/api";
import { navigate, entityRoute, enc } from "../lib/router";
import { useSession, pushRecentEntity } from "../lib/session";
import { fmtNum, fmtDate, timeAgo } from "../lib/format";
import { PageHeader, Panel, Button, Badge, TypeBadge, Conf, StatusBadge, Modal, Field, SearchInput, EmptyState, ErrorState, Loading, Skeleton, useToast, Tabs } from "../components/ui";
import { BarList, Sparkline } from "../components/charts";
import Graph from "../components/Graph";
import InvestigationPicker from "../components/InvestigationPicker";
import { TYPE_COLOR, T } from "../design/tokens";

export function CampaignsPage() {
  const { data, error, loading, reload } = useApi("/campaigns");
  const [q, setQ] = useState("");
  const [edit, setEdit] = useState(null);
  const rows = (data || []).filter(c => !q || `${c.name} ${c.threat_actor || ""} ${c.description || ""}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="page">
      <PageHeader title="Campaigns" sub="Clusters of related indicators under one intrusion set, attributed to threat actors."
        actions={<><SearchInput value={q} onChange={setQ} placeholder="Filter campaigns" style={{ width: 240 }} />
          <Button size="sm" variant="primary" icon="plus" onClick={() => setEdit({})}>New campaign</Button></>} />
      <Panel tight bodyStyle={{ padding: 0 }}>
        {error ? <ErrorState error={error} onRetry={reload} /> : loading && !data ? <div style={{ padding: 16 }}><Skeleton h={120} /></div> :
          rows.length === 0 ? <EmptyState icon="flag" title={q ? "No campaigns match" : "No campaigns yet"} desc="A campaign groups related indicators so you can track an actor across infrastructure. Create one, then assign IOCs from the IOC table (bulk actions) or an entity page."
            action={<Button size="sm" variant="primary" onClick={() => setEdit({})}>Create campaign</Button>} /> : (
            <table className="tbl"><thead><tr><th>Campaign</th><th>Threat actor</th><th className="r">Indicators</th><th>Targets</th><th>Created</th></tr></thead>
              <tbody>{rows.map(c => (
                <tr key={c.id} className="clickable" onClick={() => navigate(entityRoute("campaign", c.id))}>
                  <td className="primary"><div className="strong" style={{ fontWeight: 500 }}>{c.name}</div>{c.description && <div className="faint xs trunc" style={{ maxWidth: 480 }}>{c.description}</div>}</td>
                  <td>{c.threat_actor ? <a className="hover-link" href={`#${entityRoute("actor", c.threat_actor)}`} onClick={e => e.stopPropagation()}>{c.threat_actor}</a> : <span className="faint">Unattributed</span>}</td>
                  <td className="r num strong">{fmtNum(c.ioc_count)}</td>
                  <td className="muted">{(c.industry_targets || []).join(", ") || "—"}</td>
                  <td className="muted">{fmtDate(c.created_at)}</td>
                </tr>))}</tbody></table>
          )}
      </Panel>
      {edit && <CampaignModal campaign={edit} onClose={() => setEdit(null)} onSaved={id => { setEdit(null); reload(true); if (id) navigate(entityRoute("campaign", id)); }} />}
    </div>
  );
}

function CampaignModal({ campaign, onClose, onSaved }) {
  const isNew = !campaign.id;
  const [f, setF] = useState({ name: campaign.name || "", threat_actor: campaign.threat_actor || "", description: campaign.description || "", targets: (campaign.industry_targets || []).join(", ") });
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  async function save() {
    setBusy(true);
    const body = { name: f.name.trim(), threat_actor: f.threat_actor.trim(), description: f.description, industry_targets: f.targets.split(",").map(t => t.trim()).filter(Boolean) };
    try {
      if (isNew) { const d = await apiJSON("/campaigns", { method: "POST", body }); onSaved(d.id); }
      else { await apiJSON(`/v2/campaigns/${enc(campaign.id)}`, { method: "PATCH", body }); onSaved(); }
    } catch (e) { toast(e.message, "error"); }
    setBusy(false);
  }
  return (
    <Modal title={isNew ? "New campaign" : "Edit campaign"} onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" onClick={save} loading={busy} disabled={!f.name.trim()}>{isNew ? "Create" : "Save"}</Button></>}>
      <Field label="Name"><input className="input" autoFocus value={f.name} onChange={e => setF({ ...f, name: e.target.value })} placeholder="Operation Sandstorm" /></Field>
      <Field label="Threat actor"><input className="input" value={f.threat_actor} onChange={e => setF({ ...f, threat_actor: e.target.value })} placeholder="APT34, Lazarus Group…" /></Field>
      <Field label="Industry targets" hint="Comma-separated"><input className="input" value={f.targets} onChange={e => setF({ ...f, targets: e.target.value })} /></Field>
      <Field label="Description"><textarea className="textarea" rows={4} value={f.description} onChange={e => setF({ ...f, description: e.target.value })} /></Field>
    </Modal>
  );
}

export function CampaignPage({ id }) {
  const { data, error, loading, reload } = useApi(`/v2/campaigns/${enc(id)}`);
  const graph = useApi(`/v2/graph?kind=campaign&id=${enc(id)}`);
  const { can } = useSession();
  const [edit, setEdit] = useState(false);
  const [picker, setPicker] = useState(false);
  const [tab, setTab] = useState("overview");
  const toast = useToast();
  useEffect(() => { if (data?.campaign) pushRecentEntity({ kind: "campaign", ref: id, label: data.campaign.name }); }, [data, id]);
  if (error) return <div className="page"><ErrorState error={error} onRetry={reload} /></div>;
  if (loading && !data) return <div className="page"><Loading /></div>;
  const { campaign: c, stats } = data;

  async function del() {
    if (!window.confirm(`Delete campaign "${c.name}"? Indicators are kept but unassigned.`)) return;
    const r = await api(`/campaigns/${enc(c.id)}`, { method: "DELETE" });
    if (r.ok) { toast("Campaign deleted", "ok"); navigate("/campaigns"); } else toast("Delete failed (admin only)", "error");
  }

  return (
    <div className="page">
      <div className="entity-head">
        <div>
          <div className="row" style={{ gap: 6, marginBottom: 6 }}><Badge tone="high" dot>Campaign</Badge>{(c.industry_targets || []).map(t => <Badge key={t} outline>{t}</Badge>)}</div>
          <h1 className="page-title" style={{ fontSize: 24 }}>{c.name}</h1>
          <div className="page-sub">
            {c.threat_actor ? <>Attributed to <a className="link" href={`#${entityRoute("actor", c.threat_actor)}`}>{c.threat_actor}</a></> : "Unattributed"}
            {c.created_by_name && <> · created by {c.created_by_name} {timeAgo(c.created_at)}</>}
          </div>
        </div>
        <div className="page-actions">
          <Button size="sm" icon="edit" onClick={() => setEdit(true)}>Edit</Button>
          <Button size="sm" icon="list" onClick={() => navigate("/iocs", { campaign_id: c.id, status: "all" })}>IOC table</Button>
          <Button size="sm" variant="primary" icon="briefcase" onClick={() => setPicker(true)}>Add to investigation</Button>
          {can("admin.panel") && <Button size="sm" variant="danger" icon="trash" onClick={del}>Delete</Button>}
        </div>
      </div>
      <div className="facts">
        <div className="fact"><div className="fact-l">Indicators</div><div className="fact-v num">{fmtNum(stats.total)}</div></div>
        <div className="fact"><div className="fact-l">Active</div><div className="fact-v num">{fmtNum(stats.active)}</div></div>
        <div className="fact"><div className="fact-l">Avg confidence</div><div className="fact-v num">{stats.avg_conf ?? "—"}</div></div>
        <div className="fact"><div className="fact-l">First seen</div><div className="fact-v">{fmtDate(stats.first_seen)}</div></div>
        <div className="fact"><div className="fact-l">Last seen</div><div className="fact-v">{timeAgo(stats.last_seen)}</div></div>
        <div className="fact"><div className="fact-l">30-day activity</div><div className="fact-v"><Sparkline data={data.activity} color={T.high} w={110} h={20} /></div></div>
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "iocs", label: "Indicators", count: stats.total }, { id: "graph", label: "Infrastructure graph" }]} />
      {tab === "overview" && (
        <div className="grid g-main-side">
          <div className="stack">
            <Panel title="Description"><div className="small" style={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: c.description ? "var(--text-2)" : "var(--text-4)" }}>{c.description || "No description."}</div></Panel>
            <Panel title="Infrastructure" actions={<Button size="xs" variant="ghost" onClick={() => setTab("graph")}>Full graph</Button>}>
              {!graph.data ? <Skeleton h={280} /> : <Graph data={graph.data} centerId={`campaign:${c.id}`} height={360} emptyText="No indicators assigned to this campaign yet." />}
            </Panel>
          </div>
          <div className="stack">
            <Panel title="Indicator types"><BarList items={data.types.map(t => ({ label: t.type, value: Number(t.n), color: TYPE_COLOR[t.type], dot: true }))} onClick={it => navigate("/iocs", { campaign_id: c.id, type: it.label, status: "all" })} /></Panel>
            <Panel title="Investigations" tight>
              {data.investigations.length === 0 ? <div className="faint small" style={{ padding: 16 }}>Not part of an investigation.</div> :
                data.investigations.map(i => <div key={i.id} className="list-row clickable" onClick={() => navigate(`/investigations/${enc(i.id)}`)}><span className="mono faint xs">{i.key}</span><span style={{ flex: 1 }}>{i.name}</span><Badge outline>{i.status}</Badge></div>)}
            </Panel>
          </div>
        </div>
      )}
      {tab === "iocs" && (
        <Panel tight bodyStyle={{ padding: 0 }} footer={stats.total > data.iocs.length && <span>Showing latest {data.iocs.length} — <a className="link" href={`#/iocs?campaign_id=${enc(c.id)}&status=all`}>open all in IOC table</a></span>}>
          {data.iocs.length === 0 ? <EmptyState icon="crosshair" title="No indicators" desc="Assign indicators from the IOC table using bulk actions." /> : (
            <table className="tbl"><thead><tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Source</th><th>Status</th><th>First seen</th></tr></thead>
              <tbody>{data.iocs.map(i => (
                <tr key={i.id} className="clickable" onClick={() => navigate(entityRoute("ioc", i.id))}>
                  <td className="cellmono trunc" style={{ maxWidth: 440 }}>{i.value}</td><td><TypeBadge type={i.type} /></td><td><Conf value={i.confidence} /></td>
                  <td className="muted">{i.source}</td><td><StatusBadge status={i.status} /></td><td className="muted">{fmtDate(i.created_at)}</td>
                </tr>))}</tbody></table>
          )}
        </Panel>
      )}
      {tab === "graph" && <Panel>{!graph.data ? <Skeleton h={500} /> : <Graph data={graph.data} centerId={`campaign:${c.id}`} height={620} />}</Panel>}
      {edit && <CampaignModal campaign={c} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); reload(true); }} />}
      {picker && <InvestigationPicker onClose={() => setPicker(false)} onPick={inv => apiJSON(`/v2/investigations/${enc(inv.id)}/items`, { method: "POST", body: { item_type: "campaign", ref_id: c.id } })} />}
    </div>
  );
}
