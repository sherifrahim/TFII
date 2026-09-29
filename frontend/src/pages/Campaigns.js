import React, { useState } from "react";
import { useApi, apiJSON, api } from "../lib/api";
import { navigate, entityRoute, enc } from "../lib/router";
import { useSession } from "../lib/session";
import { fmtNum, fmtDate } from "../lib/format";
import { PageHeader, Panel, Button, Badge, TypeBadge, Conf, StatusBadge, Modal, Field, SearchInput, EmptyState, ErrorState, Loading, Skeleton, useToast, rowAction } from "../components/ui";
import { BarList, Sparkline } from "../components/charts";
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
                <tr key={c.id} className="clickable" {...rowAction(() => navigate(entityRoute("campaign", c.id)))}>
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

// Header actions for the shared entity page.
export function CampaignActions({ campaign: c, onChanged }) {
  const { can } = useSession();
  const [edit, setEdit] = useState(false);
  const toast = useToast();
  async function del() {
    if (!window.confirm(`Delete campaign "${c.name}"? Indicators are kept but unassigned.`)) return;
    const r = await api(`/campaigns/${enc(c.id)}`, { method: "DELETE" });
    if (r.ok) { toast("Campaign deleted", "ok"); navigate("/campaigns"); } else toast("Delete failed (admin only)", "error");
  }
  return (
    <>
      <Button size="sm" icon="edit" onClick={() => setEdit(true)}>Edit</Button>
      <Button size="sm" icon="list" onClick={() => navigate("/iocs", { campaign_id: c.id, status: "all" })}>IOC table</Button>
      {can("admin.panel") && <Button size="sm" variant="danger" icon="trash" onClick={del}>Delete</Button>}
      {edit && <CampaignModal campaign={c} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); onChanged(); }} />}
    </>
  );
}

export function CampaignOverview({ kd }) {
  const { data, error, loading, reload } = kd;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading || !data) return <Loading />;
  const { campaign: c, stats } = data;
  return (
    <div className="grid g-main-side">
      <div className="stack">
        {(c.description || (c.industry_targets || []).length > 0) && (
          <Panel title="Description">
            <div className="small" style={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "var(--text-2)", overflowWrap: "anywhere" }}>{c.description || "No description."}</div>
            {(c.industry_targets || []).length > 0 && <div className="row wrap" style={{ gap: 4, marginTop: 10 }}>{c.industry_targets.map(t => <Badge key={t} outline>{t}</Badge>)}</div>}
          </Panel>
        )}
        <Panel tight bodyStyle={{ padding: 0 }} title="Indicators" sub={`${fmtNum(stats.total)} assigned`}
          footer={stats.total > data.iocs.length && <span>Showing latest {data.iocs.length} — <a className="link" href={`#/iocs?campaign_id=${enc(c.id)}&status=all`}>open all in IOC table</a></span>}>
          {data.iocs.length === 0 ? <EmptyState icon="crosshair" title="No indicators" desc="Assign indicators from the IOC table using bulk actions." /> : (
            <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Source</th><th>Status</th><th>First seen</th></tr></thead>
              <tbody>{data.iocs.map(i => (
                <tr key={i.id} className="clickable" {...rowAction(() => navigate(entityRoute("ioc", i.id)))}>
                  <td className="cellmono trunc" style={{ maxWidth: 440 }}>{i.value}</td><td><TypeBadge type={i.type} /></td><td><Conf value={i.confidence} /></td>
                  <td className="muted">{i.source}</td><td><StatusBadge status={i.status} /></td><td className="muted">{fmtDate(i.created_at)}</td>
                </tr>))}</tbody></table></div>
          )}
        </Panel>
      </div>
      <div className="stack">
        <Panel title="30-day activity"><Sparkline data={data.activity} color={T.high} w={240} h={40} /></Panel>
        <Panel title="Indicator types"><BarList items={data.types.map(t => ({ label: t.type, value: Number(t.n), color: TYPE_COLOR[t.type], dot: true }))} onClick={it => navigate("/iocs", { campaign_id: c.id, type: it.label, status: "all" })} /></Panel>
      </div>
    </div>
  );
}
