import React, { useEffect, useMemo, useState } from "react";
import { useApi, apiJSON, api } from "../lib/api";
import { navigate, entityRoute, enc, setQuery } from "../lib/router";
import { useSession, pushRecentEntity } from "../lib/session";
import { fmtDate, fmtDateTime, timeAgo, confBand, detectionTemplates, detectType, refang, REL_TYPES, typeGroup } from "../lib/format";
import {
  Panel, Button, IconButton, Badge, TypeBadge, TLPBadge, StatusBadge, Tabs, Loading, ErrorState, EmptyState, Callout,
  Menu, Modal, Field, Select, SearchInput, CopyButton, useToast, useDebounced, SevBadge,
} from "../components/ui";
import Graph from "../components/Graph";
import Icon from "../components/Icon";
import InvestigationPicker from "../components/InvestigationPicker";
import { SEV_COLOR } from "../design/tokens";

const VERDICT = { critical: "Malicious", high: "Malicious", medium: "Suspicious", low: "Low risk" };

export function IocEntity({ id, tab = "overview" }) {
  const { data, error, loading, reload } = useApi(`/v2/entities/ioc/${enc(id)}`);
  const { me, can } = useSession();
  const toast = useToast();
  const [picker, setPicker] = useState(false);
  const [busy, setBusy] = useState(null);

  useEffect(() => {
    if (data?.ioc) pushRecentEntity({ kind: "ioc", ref: data.ioc.id, label: data.ioc.value });
  }, [data]);

  if (error) return <div className="page"><ErrorState error={error} onRetry={reload} title="Indicator not found" /></div>;
  if (loading && !data) return <div className="page"><Loading label="Loading entity" /></div>;
  const { ioc } = data;
  const band = confBand(ioc.confidence);
  const canEdit = me?.role === "admin" || ioc.created_by === me?.id;
  const setTab = t => setQuery({ tab: t === "overview" ? "" : t });

  async function reEnrich() {
    setBusy("enrich");
    try { const d = await apiJSON(`/iocs/${enc(ioc.id)}/re-enrich`, { method: "POST" }); toast(`Re-enriched · confidence ${d.confidence}`, "ok"); reload(true); }
    catch (e) { toast(e.message, "error"); }
    setBusy(null);
  }
  async function toggleFp() {
    const fp = ioc.status !== "false_positive";
    const reason = fp ? window.prompt("Why is this a false positive?", "") : "";
    if (fp && reason === null) return;
    try { await apiJSON(`/iocs/${enc(ioc.id)}/false-positive`, { method: "PATCH", body: { false_positive: fp, reason } }); reload(true); toast(fp ? "Marked as false positive" : "False-positive flag removed", "ok"); }
    catch (e) { toast(e.message, "error"); }
  }
  async function del() {
    if (!window.confirm(`Delete ${ioc.value}? Notes, score history and relationships are removed too.`)) return;
    const r = await api(`/iocs/${enc(ioc.id)}`, { method: "DELETE" });
    if (r.ok) { toast("Indicator deleted", "ok"); navigate("/iocs"); } else toast("Delete failed", "error");
  }

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "relations", label: "Relations", count: data.relationships.length },
    { id: "observations", label: "Observations", count: data.notes.length + data.score_history.length + data.provenance.length },
    { id: "detection", label: "Detection" },
    { id: "workspace", label: "Workspace", count: data.investigations.length },
    { id: "raw", label: "Raw Data" },
  ];

  return (
    <div className="page">
      <div className="entity-head">
        <div style={{ minWidth: 0, flex: 1 }}>
          <div className="row wrap" style={{ gap: 6, marginBottom: 8 }}>
            <TypeBadge type={ioc.type} />
            <Badge tone={band} dot>{VERDICT[band]}</Badge>
            <TLPBadge tlp={ioc.tlp} />
            <StatusBadge status={ioc.status} />
            {data.malware_family && data.malware_family !== "unknown" && <Badge tone="violet">{data.malware_family}</Badge>}
          </div>
          <div className="row" style={{ gap: 6, alignItems: "flex-start" }}>
            <div className="entity-value">{ioc.value}</div>
            <CopyButton value={ioc.value} />
          </div>
          {ioc.value_defanged && ioc.value_defanged !== ioc.value && <div className="mono faint" style={{ marginTop: 4 }}>{ioc.value_defanged} <CopyButton value={ioc.value_defanged} /></div>}
        </div>
        <div className="page-actions">
          <Button size="sm" icon="refresh" onClick={reEnrich} loading={busy === "enrich"}>Re-enrich</Button>
          <Button size="sm" icon="graph" onClick={() => setTab("relations")}>Graph</Button>
          <Button size="sm" variant="primary" icon="briefcase" onClick={() => setPicker(true)}>Add to investigation</Button>
          <Menu trigger={t => <IconButton icon="more" title="More actions" onClick={t} />} items={[
            { label: "Search related across TFII", icon: "search", onClick: () => navigate("/search", { q: ioc.value }) },
            ioc.type === "IPv4" && { label: "Pivot on /24 subnet", icon: "globe", onClick: () => navigate("/iocs", { q: ioc.value.split(".").slice(0, 3).join(".") + ".", status: "all" }) },
            { label: "OSINT lookup", icon: "radar", onClick: () => navigate("/osint/lookup", { target: ioc.value }) },
            "sep",
            canEdit && { label: ioc.status === "false_positive" ? "Remove false-positive flag" : "Mark false positive", icon: "alert", onClick: toggleFp },
            can("ioc.delete") && canEdit && { label: "Delete indicator", icon: "trash", danger: true, onClick: del },
          ]} />
        </div>
      </div>

      <div className="facts">
        <Fact label="Reputation" value={<span style={{ color: SEV_COLOR[band] }}>{VERDICT[band]}</span>} />
        <Fact label="Confidence" value={`${ioc.confidence} / 100`} />
        <Fact label="First seen" value={fmtDate(ioc.created_at)} title={fmtDateTime(ioc.created_at)} />
        <Fact label="Last seen" value={timeAgo(ioc.last_seen_at)} title={fmtDateTime(ioc.last_seen_at)} />
        <Fact label="Source" value={ioc.source} />
        <Fact label="Campaign" value={ioc.campaign_name ? <a className="hover-link" href={`#${entityRoute("campaign", ioc.campaign_id)}`}>{ioc.campaign_name}</a> : "—"} />
        <Fact label="Threat actor" value={ioc.threat_actor ? <a className="hover-link" href={`#${entityRoute("actor", ioc.threat_actor)}`}>{ioc.threat_actor}</a> : "—"} />
        <Fact label="Expires" value={ioc.valid_until ? fmtDate(ioc.valid_until) : "Never"} />
      </div>

      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {tab === "overview" && <Overview data={data} canEdit={canEdit} reload={reload} />}
      {tab === "relations" && <Relations data={data} reload={reload} />}
      {tab === "observations" && <Observations data={data} reload={reload} />}
      {tab === "detection" && <Detection ioc={ioc} />}
      {tab === "workspace" && <WorkspaceTab data={data} onAdd={() => setPicker(true)} />}
      {tab === "raw" && <Panel title="Raw record" actions={<CopyButton value={JSON.stringify(ioc, null, 2)} />}><pre className="code" style={{ maxHeight: 600 }}>{JSON.stringify(ioc, null, 2)}</pre></Panel>}

      {picker && <InvestigationPicker onClose={() => setPicker(false)}
        onPick={inv => apiJSON(`/v2/investigations/${enc(inv.id)}/items`, { method: "POST", body: { item_type: "ioc", ref_id: ioc.id } }).then(() => reload(true))} />}
    </div>
  );
}

function Fact({ label, value, title }) {
  return <div className="fact" title={title}><div className="fact-l">{label}</div><div className="fact-v">{value}</div></div>;
}

// ── Overview ────────────────────────────────────────────────────────────────
function Overview({ data, canEdit, reload }) {
  const { ioc, geo, related, cves } = data;
  const enr = ioc.enrichment || {};
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [desc, setDesc] = useState(ioc.description || "");
  const [tags, setTags] = useState((ioc.tags || []).join(", "));

  async function save() {
    try {
      await apiJSON(`/v2/iocs/${enc(ioc.id)}`, { method: "PATCH", body: { description: desc, tags: tags.split(",").map(t => t.trim()).filter(Boolean) } });
      setEditing(false); reload(true); toast("Saved", "ok");
    } catch (e) { toast(e.message, "error"); }
  }

  const vt = enr.virustotal || {}, ab = enr.abuseipdb || {}, uh = enr.urlhaus || {};
  const sources = [
    { name: "VirusTotal", d: vt, rows: [["Detections", vt.total !== undefined ? `${vt.malicious ?? 0} / ${vt.total}` : null], ["Score", vt.vt_score !== undefined ? `${vt.vt_score}%` : null], ["AS owner", vt.as_owner], ["Reputation", vt.reputation]] },
    { name: "AbuseIPDB", d: ab, rows: [["Abuse score", ab.abuse_score !== undefined ? `${ab.abuse_score} / 100` : null], ["Reports", ab.total_reports], ["ISP", ab.isp], ["Usage", ab.usage_type]] },
    { name: "URLhaus", d: uh, rows: [["Listed", uh.found === undefined ? null : uh.found ? "Yes" : "No"], ["Threat", uh.threat], ["Status", uh.url_status]] },
  ].filter(s => s.d && !s.d.skipped && Object.keys(s.d).length);
  const relGroups = [
    ["Same campaign", related.campaign, ioc.campaign_name],
    ["Same malware family", related.malware, data.malware_family],
    ["Same /24 subnet", related.subnet],
    ["Shared tags", related.tags],
  ].filter(([, rows]) => rows && rows.length);

  return (
    <div className="grid g-main-side">
      <div className="stack">
        <Panel title="Context" actions={canEdit && !editing && <Button size="xs" variant="ghost" icon="edit" onClick={() => setEditing(true)}>Edit</Button>}>
          {editing ? (
            <>
              <Field label="Description"><textarea className="textarea" rows={4} value={desc} onChange={e => setDesc(e.target.value)} /></Field>
              <Field label="Tags" hint="Comma-separated"><input className="input" value={tags} onChange={e => setTags(e.target.value)} /></Field>
              <div className="row" style={{ gap: 8 }}><Button size="sm" variant="primary" onClick={save}>Save</Button><Button size="sm" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button></div>
            </>
          ) : (
            <>
              <div className="small" style={{ color: ioc.description ? "var(--text-2)" : "var(--text-4)", lineHeight: 1.6, whiteSpace: "pre-wrap" }}>{ioc.description || "No description."}</div>
              {(ioc.tags || []).length > 0 && (
                <div className="row wrap" style={{ gap: 4, marginTop: 12 }}>
                  {ioc.tags.map(t => <a key={t} className="tag link" href={`#/iocs?tag=${enc(t)}&status=all`}>{t}</a>)}
                </div>
              )}
              {(ioc.mitre_techniques || []).length > 0 && (
                <div className="row wrap" style={{ gap: 4, marginTop: 10 }}>
                  {ioc.mitre_techniques.map(t => <a key={t} className="badge violet" href={`https://attack.mitre.org/techniques/${t.split(" ")[0].replace(".", "/")}/`} target="_blank" rel="noreferrer">{t}</a>)}
                </div>
              )}
              {ioc.status === "false_positive" && <Callout tone="warn" style={{ marginTop: 12 }}>Marked as false positive{ioc.fp_reason ? `: ${ioc.fp_reason}` : ""}. Excluded from STIX/TAXII exports.</Callout>}
            </>
          )}
        </Panel>

        <Panel title="Enrichment" sub={enr.enriched_at ? `updated ${timeAgo(enr.enriched_at)}` : undefined}>
          {sources.length === 0 ? (
            <div className="small faint">No enrichment sources returned data for this indicator{enr.source ? ` (ingested from ${enr.source})` : ""}. Use Re-enrich to query VirusTotal, AbuseIPDB and URLhaus.</div>
          ) : (
            <div className="grid g3">
              {sources.map(s => (
                <div key={s.name} style={{ background: "var(--elevated)", borderRadius: 6, padding: "10px 12px" }}>
                  <div className="row between" style={{ marginBottom: 6 }}>
                    <span className="strong small">{s.name}</span>
                    {s.d.link && <a className="link xs" href={s.d.link} target="_blank" rel="noreferrer">Open ↗</a>}
                  </div>
                  {s.d.error ? <div className="xs" style={{ color: "var(--critical)" }}>{s.d.error}</div> : (
                    <dl className="kv" style={{ gridTemplateColumns: "90px 1fr", gap: "4px 8px", margin: 0 }}>
                      {s.rows.filter(([, v]) => v !== null && v !== undefined && v !== "").map(([k, v]) => <React.Fragment key={k}><dt className="xs">{k}</dt><dd className="xs">{String(v)}</dd></React.Fragment>)}
                    </dl>
                  )}
                </div>
              ))}
            </div>
          )}
          {(enr.confidence_reasons || []).length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>Confidence reasoning</div>
              {enr.confidence_reasons.map((r, k) => <div key={k} className="small muted" style={{ padding: "2px 0" }}>› {r}</div>)}
            </div>
          )}
          {Object.keys(geo || {}).length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>Network & geo</div>
              <dl className="kv">{Object.entries(geo).map(([k, v]) => <React.Fragment key={k}><dt style={{ textTransform: "capitalize" }}>{k.replace(/_/g, " ")}</dt><dd>{String(v)}</dd></React.Fragment>)}</dl>
            </div>
          )}
        </Panel>

        {relGroups.length > 0 && (
          <Panel title="Related indicators" tight>
            {relGroups.map(([label, rows, meta]) => (
              <div key={label}>
                <div className="eyebrow" style={{ padding: "10px 16px 4px" }}>{label}{meta ? ` · ${meta}` : ""} <span className="faint">({rows.length}{rows.length >= 25 ? "+" : ""})</span></div>
                {rows.slice(0, 6).map(r => (
                  <div key={r.id} className="list-row clickable" onClick={() => navigate(entityRoute("ioc", r.id))}>
                    <TypeBadge type={r.type} /><span className="mono trunc" style={{ flex: 1 }}>{r.value}</span>
                    <span className="faint xs">conf {r.confidence}</span><span className="faint xs">{timeAgo(r.created_at)}</span>
                  </div>
                ))}
              </div>
            ))}
          </Panel>
        )}
      </div>

      <div className="stack">
        <Panel title="Intelligence links" tight>
          <LinkRow icon="flag" label="Campaign" value={ioc.campaign_name} to={ioc.campaign_id && entityRoute("campaign", ioc.campaign_id)} />
          <LinkRow icon="skull" label="Threat actor" value={ioc.threat_actor} to={ioc.threat_actor && entityRoute("actor", ioc.threat_actor)} />
          <LinkRow icon="bug" label="Malware" value={data.malware_family && data.malware_family !== "unknown" ? data.malware_family : null} to={data.malware_family && entityRoute("malware", data.malware_family)} />
          <LinkRow icon="link" label="Relationships" value={data.relationships.length ? `${data.relationships.length} linked indicator${data.relationships.length === 1 ? "" : "s"}` : null} to={`/ioc/${enc(ioc.id)}?tab=relations`} />
          <LinkRow icon="briefcase" label="Investigations" value={data.investigations.length ? `${data.investigations.length} investigation(s)` : null} to={`/ioc/${enc(ioc.id)}?tab=workspace`} />
        </Panel>
        <Panel title="Linked vulnerabilities" tight>
          {cves.length === 0 ? <div className="faint small" style={{ padding: "8px 16px 12px" }}>No CVEs reference this indicator.</div>
            : cves.map(c => (
              <div key={c.cve_id} className="list-row clickable" onClick={() => navigate(entityRoute("cve", c.cve_id))}>
                <span className="mono">{c.cve_id}</span>{c.kev_listed && <Badge tone="critical">KEV</Badge>}
                <span className="spacer" /><SevBadge severity={c.severity} score={c.cvss_score} />
              </div>
            ))}
        </Panel>
        <Panel title="Provenance" tight>
          <div className="list-row"><span className="faint" style={{ width: 90 }}>Added by</span><span>{ioc.author || "connector"}</span></div>
          <div className="list-row"><span className="faint" style={{ width: 90 }}>Source</span><span>{ioc.source}</span></div>
          <div className="list-row"><span className="faint" style={{ width: 90 }}>Industry</span><span>{ioc.industry || "—"}</span></div>
          {data.provenance.map(p => (
            <div key={p.id} className="list-row"><span className="faint" style={{ width: 90 }}>{p.source_type}</span><span className="trunc">{p.source_ref}</span><span className="faint xs">{fmtDate(p.observed_at)}</span></div>
          ))}
        </Panel>
      </div>
    </div>
  );
}

function LinkRow({ icon, label, value, to }) {
  return (
    <div className={`list-row ${to && value ? "clickable" : ""}`} onClick={to && value ? () => navigate(to) : undefined}>
      <span className="row faint" style={{ gap: 8, width: 130 }}><Icon name={icon} size={13} />{label}</span>
      <span className="trunc" style={{ flex: 1, color: value ? "var(--text)" : "var(--text-4)" }}>{value || "—"}</span>
    </div>
  );
}

// ── Relations ──────────────────────────────────────────────────────────────
function Relations({ data, reload }) {
  const { ioc } = data;
  const [depth, setDepth] = useState(1);
  const graph = useApi(`/v2/graph?kind=ioc&id=${enc(ioc.id)}&depth=${depth}`);
  const [adding, setAdding] = useState(false);
  const toast = useToast();

  async function remove(relId) {
    if (!window.confirm("Remove this relationship?")) return;
    const r = await api(`/iocs/relationships/${relId}`, { method: "DELETE" });
    if (r.ok) { reload(true); graph.reload(true); } else toast("Could not remove", "error");
  }
  return (
    <div className="stack">
      <Panel title="Relationship graph" sub="indicators, campaigns, actors, malware, CVEs and investigations"
        actions={<>
          <div className="seg">{[1, 2].map(d => <button key={d} className={depth === d ? "on" : ""} onClick={() => setDepth(d)}>{d === 1 ? "Direct" : "2 hops"}</button>)}</div>
          <Button size="sm" icon="maximize" onClick={() => navigate("/explorer", { kind: "ioc", id: ioc.id })}>Explorer</Button>
          <Button size="sm" variant="primary" icon="plus" onClick={() => setAdding(true)}>Link indicator</Button>
        </>}>
        {graph.error ? <ErrorState error={graph.error} onRetry={graph.reload} /> : !graph.data ? <Loading /> :
          <Graph data={graph.data} centerId={`ioc:${ioc.id}`} height={480} emptyText="No relationships yet — link an indicator, assign a campaign, or add it to an investigation." />}
      </Panel>
      <Panel title="Direct relationships" tight>
        {data.relationships.length === 0 ? <EmptyState icon="link" title="No direct relationships" desc="Link this indicator to infrastructure it resolves to, drops, or communicates with." action={<Button size="sm" onClick={() => setAdding(true)}>Link indicator</Button>} /> : (
          <table className="tbl compact"><thead><tr><th>Direction</th><th>Relationship</th><th>Indicator</th><th>Type</th><th>Added</th><th /></tr></thead>
            <tbody>
              {data.relationships.map(r => {
                const out = r.source_id === ioc.id;
                const oid = out ? r.target_id : r.source_id;
                return (
                  <tr key={r.id} className="clickable" onClick={() => navigate(entityRoute("ioc", oid))}>
                    <td className="muted">{out ? "outgoing →" : "← incoming"}</td>
                    <td><Badge outline>{r.relationship_type.replace(/_/g, " ")}</Badge></td>
                    <td className="cellmono trunc" style={{ maxWidth: 380 }}>{out ? r.target_value : r.source_value}</td>
                    <td><TypeBadge type={out ? r.target_type : r.source_type} /></td>
                    <td className="muted">{timeAgo(r.created_at)}</td>
                    <td onClick={e => e.stopPropagation()}><IconButton icon="x" size="sm" title="Remove" onClick={() => remove(r.id)} /></td>
                  </tr>
                );
              })}
            </tbody></table>
        )}
      </Panel>
      {adding && <LinkModal ioc={ioc} onClose={() => setAdding(false)} onDone={() => { setAdding(false); reload(true); graph.reload(true); }} />}
    </div>
  );
}

function LinkModal({ ioc, onClose, onDone }) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q, 250);
  const [type, setType] = useState("related_to");
  const [target, setTarget] = useState(null);
  const [note, setNote] = useState("");
  const res = useApi(dq.trim().length >= 2 ? `/v2/iocs?q=${enc(dq.trim())}&limit=8&facets=false&status=all` : null);
  const toast = useToast();
  async function save() {
    try { await apiJSON(`/iocs/${enc(ioc.id)}/relationships`, { method: "POST", body: { target_id: target.id, relationship_type: type, note } }); toast("Relationship added", "ok"); onDone(); }
    catch (e) { toast(e.message, "error"); }
  }
  return (
    <Modal title="Link to another indicator" onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!target} onClick={save}>Add relationship</Button></>}>
      <Field label="Relationship"><Select value={type} onChange={setType} options={REL_TYPES.map(t => [t, t.replace(/_/g, " ")])} /></Field>
      <Field label="Target indicator">
        {target ? (
          <div className="row" style={{ gap: 8 }}><TypeBadge type={target.type} /><span className="mono trunc" style={{ flex: 1 }}>{target.value}</span><Button size="xs" variant="ghost" onClick={() => setTarget(null)}>Change</Button></div>
        ) : (
          <>
            <SearchInput value={q} onChange={setQ} placeholder="Search tracked indicators by value" autoFocus />
            <div style={{ maxHeight: 240, overflow: "auto", marginTop: 6 }}>
              {(res.data?.items || []).filter(i => i.id !== ioc.id).map(i => (
                <div key={i.id} className="list-row clickable" style={{ padding: "0 6px" }} onClick={() => setTarget(i)}>
                  <TypeBadge type={i.type} /><span className="mono trunc" style={{ flex: 1 }}>{i.value}</span><span className="faint xs">conf {i.confidence}</span>
                </div>
              ))}
              {res.data && res.data.items.length === 0 && <div className="faint small" style={{ padding: 8 }}>No tracked indicator matches. <a className="link" href={`#/iocs/new?value=${enc(q)}`}>Add it first →</a></div>}
            </div>
          </>
        )}
      </Field>
      <Field label="Note (optional)"><input className="input" value={note} onChange={e => setNote(e.target.value)} /></Field>
    </Modal>
  );
}

// ── Observations ───────────────────────────────────────────────────────────
function Observations({ data, reload }) {
  const { ioc } = data;
  const { me } = useSession();
  const [note, setNote] = useState("");
  const toast = useToast();
  const events = useMemo(() => {
    const ev = [{ at: ioc.created_at, title: "First observed", body: `Added to TFII from ${ioc.source}${ioc.author ? ` by ${ioc.author}` : ""}`, tone: "gold" }];
    data.score_history.forEach(h => ev.push({ at: h.created_at, title: `Confidence ${h.old_score} → ${h.new_score} (${h.delta > 0 ? "+" : ""}${h.delta})`, body: (h.reason || "").split(" | ").join("\n"), who: h.triggered_by }));
    data.provenance.forEach(p => ev.push({ at: p.observed_at, title: `Observed · ${p.source_type}`, body: [p.source_ref, p.context].filter(Boolean).join("\n") }));
    data.notes.forEach(n => ev.push({ at: n.created_at, title: `Note by ${n.username}`, body: n.note }));
    data.investigations.forEach(i => ev.push({ at: i.linked_at, title: `Added to ${i.key} ${i.name}`, tone: "gold" }));
    return ev.filter(e => e.at).sort((a, b) => String(b.at).localeCompare(String(a.at)));
  }, [data, ioc]);

  async function addNote() {
    if (!note.trim()) return;
    try { await apiJSON(`/iocs/${enc(ioc.id)}/notes`, { method: "POST", body: { note } }); setNote(""); reload(true); }
    catch (e) { toast(e.message, "error"); }
  }
  async function delNote(id) {
    const r = await api(`/iocs/${enc(ioc.id)}/notes/${id}`, { method: "DELETE" });
    if (r.ok) reload(true); else toast("Could not delete note", "error");
  }

  return (
    <div className="grid g-main-side">
      <Panel title="Activity timeline">
        <div className="tl">
          {events.map((e, k) => (
            <div key={k} className={`tl-item ${e.tone || ""}`}>
              <div className="tl-date">{fmtDateTime(e.at)}{e.who ? ` · ${e.who}` : ""}</div>
              <div className="tl-title">{e.title}</div>
              {e.body && <div className="tl-body">{e.body}</div>}
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Analyst notes" tight>
        <div style={{ padding: "8px 16px 12px" }}>
          <textarea className="textarea" rows={3} style={{ width: "100%" }} placeholder="Add an observation… (Ctrl+Enter to save)" value={note}
            onChange={e => setNote(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) addNote(); }} />
          <div className="row" style={{ justifyContent: "flex-end", marginTop: 6 }}><Button size="sm" variant="primary" disabled={!note.trim()} onClick={addNote}>Add note</Button></div>
        </div>
        {data.notes.map(n => (
          <div key={n.id} style={{ padding: "10px 16px", borderTop: "1px solid var(--border)" }}>
            <div className="row between"><span className="small strong">{n.username}</span>
              <span className="row" style={{ gap: 4 }}><span className="faint xs">{timeAgo(n.created_at)}</span>
                {(me?.role === "admin" || n.user_id === me?.id) && <IconButton icon="trash" size="sm" title="Delete note" onClick={() => delNote(n.id)} />}</span></div>
            <div className="small" style={{ whiteSpace: "pre-wrap", marginTop: 4 }}>{n.note}</div>
          </div>
        ))}
      </Panel>
    </div>
  );
}

// ── Detection ──────────────────────────────────────────────────────────────
export function Detection({ ioc }) {
  const templates = detectionTemplates(ioc.type, ioc.value);
  const [picker, setPicker] = useState(null);
  return (
    <div className="stack">
      <Callout>Hunting queries generated from this indicator. They are starting points to run in your SIEM/EDR — not a statement of existing coverage. Save the ones you deploy to an investigation to track them.</Callout>
      {(ioc.mitre_techniques || []).length > 0 && (
        <Panel title="Mapped ATT&CK techniques" sub="set by analysts on this indicator">
          <div className="row wrap" style={{ gap: 6 }}>
            {ioc.mitre_techniques.map(t => <a key={t} className="badge violet" href={`https://attack.mitre.org/techniques/${t.split(" ")[0].replace(".", "/")}/`} target="_blank" rel="noreferrer">{t}</a>)}
          </div>
        </Panel>
      )}
      {templates.length === 0 && <EmptyState icon="code" title="No templates for this indicator type" desc="Use the Query Builder to generate a detection for this context." action={<Button size="sm" onClick={() => navigate("/query")}>Open Query Builder</Button>} />}
      {templates.map(t => (
        <Panel key={t.name} title={t.name} actions={<>
          <CopyButton value={t.body} />
          <Button size="xs" icon="briefcase" onClick={() => setPicker(t)}>Save to investigation</Button>
        </>}>
          <pre className="code">{t.body}</pre>
        </Panel>
      ))}
      {picker && <InvestigationPicker title="Save detection to investigation" onClose={() => setPicker(null)}
        onPick={inv => apiJSON(`/v2/investigations/${enc(inv.id)}/items`, { method: "POST", body: { item_type: "detection", value: `${picker.name}: ${ioc.value}`, label: picker.name, data: { language: picker.lang, rule: picker.body, indicator: ioc.value } } })} />}
    </div>
  );
}

function WorkspaceTab({ data, onAdd }) {
  return (
    <Panel title="Investigations containing this indicator" actions={<Button size="sm" variant="primary" icon="plus" onClick={onAdd}>Add to investigation</Button>} tight>
      {data.investigations.length === 0 ? <EmptyState icon="briefcase" title="Not part of any investigation" desc="Add it to an investigation to collect it with related infrastructure, notes and detections." /> :
        data.investigations.map(i => (
          <div key={i.id} className="list-row clickable" onClick={() => navigate(`/investigations/${enc(i.id)}`)}>
            <span className="sev-dot" style={{ background: SEV_COLOR[i.severity] }} />
            <span className="mono faint xs">{i.key}</span>
            <span style={{ flex: 1, color: "var(--text)" }}>{i.name}</span>
            <Badge outline>{i.status}</Badge>
            <span className="faint xs">added {timeAgo(i.linked_at)}</span>
          </div>
        ))}
    </Panel>
  );
}

// ── Untracked observable ───────────────────────────────────────────────────
export function ObservablePage({ value }) {
  const val = refang(value || "");
  const res = useApi(`/v2/entities/resolve?value=${enc(val)}`);
  const [lookup, setLookup] = useState(null);
  const [busy, setBusy] = useState(false);
  const [picker, setPicker] = useState(false);
  const toast = useToast();

  const type = res.data?.type || detectType(val) || "Unknown";
  useEffect(() => {
    if (type === "CVE") navigate(`/cve/${enc(val.toUpperCase())}`, undefined, { replace: true });
    else if (res.data?.found) navigate(entityRoute("ioc", res.data.id), undefined, { replace: true });
  }, [res.data, type, val]);

  if (type === "CVE") return null;
  if (res.error) return <div className="page"><ErrorState error={res.error} onRetry={res.reload} /></div>;
  if (!res.data || res.data.found) return <div className="page"><Loading label="Resolving" /></div>;

  async function runLookup() {
    setBusy(true);
    try { const d = await apiJSON("/iocs/bulk-lookup", { method: "POST", body: { input: val } }); setLookup(d.results?.[0] || null); }
    catch (e) { toast(e.message, "error"); }
    setBusy(false);
  }
  const verdictTone = { malicious: "critical", suspicious: "high", clean: "success" };
  return (
    <div className="page">
      <div className="entity-head">
        <div style={{ minWidth: 0 }}>
          <div className="row" style={{ gap: 6, marginBottom: 8 }}><TypeBadge type={type} /><Badge outline>Not tracked</Badge></div>
          <div className="row" style={{ gap: 6 }}><div className="entity-value">{val}</div><CopyButton value={val} /></div>
        </div>
        <div className="page-actions">
          <Button size="sm" icon="search" onClick={runLookup} loading={busy}>Reputation lookup</Button>
          <Button size="sm" icon="briefcase" onClick={() => setPicker(true)}>Add to investigation</Button>
          <Button size="sm" variant="primary" icon="plus" onClick={() => navigate("/iocs/new", { value: val })}>Track as IOC</Button>
        </div>
      </div>
      <Callout style={{ marginBottom: 12 }}>This value isn't in the TFII indicator database. Look up its reputation, then track it as an IOC to enrich it, relate it and share it via STIX/TAXII.</Callout>
      {lookup && (
        <Panel title="Reputation" style={{ marginBottom: 12 }}>
          <div className="row" style={{ gap: 8, marginBottom: 8 }}>
            <Badge tone={verdictTone[lookup.verdict] || "low"} dot>{lookup.verdict}</Badge>
            {lookup.geo?.country && <span className="muted small">{lookup.geo.country} · {lookup.geo.org}</span>}
          </div>
          <div className="small muted">{lookup.reason}</div>
        </Panel>
      )}
      {typeGroup(type) !== "other" && <Detection ioc={{ type, value: val, mitre_techniques: [] }} />}
      {picker && <InvestigationPicker onClose={() => setPicker(false)}
        onPick={inv => apiJSON(`/v2/investigations/${enc(inv.id)}/items`, { method: "POST", body: { item_type: "observable", value: val } })} />}
    </div>
  );
}
