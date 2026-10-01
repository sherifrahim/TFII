import React, { useMemo, useState } from "react";
import { useApi, apiJSON, api } from "../../lib/api";
import { navigate, enc } from "../../lib/router";
import { entityPath, KINDS, canonicalKind } from "../../lib/entity";
import { fmtDateTime, timeAgo } from "../../lib/format";
import { safeUrl } from "../../lib/safe";
import { useSession } from "../../lib/session";
import {
  Panel, Button, IconButton, Badge, TypeBadge, Modal, Field, Select, SearchInput, EmptyState, ErrorState, Loading,
  Callout, CopyButton, useToast, useDebounced, actionable, STATUS_OPTIONS,
} from "../../components/ui";
import Icon from "../../components/Icon";
import Graph from "../../components/Graph";

// ── An entity, wherever it appears ──────────────────────────────────────────
export function EntityChip({ item, inv }) {
  const kind = canonicalKind(item.kind);
  const meta = KINDS[kind] || KINDS.note;
  const path = item.tracked === false && kind !== "indicator" ? null : entityPath(kind, item.ref, inv);
  const label = item.label || item.ref;
  const mono = kind === "indicator" || kind === "cve";
  const body = (
    <span className="row" style={{ gap: 8, minWidth: 0 }}>
      <Icon name={meta.icon} size={13} />
      <span className={`${mono ? "mono " : ""}trunc`} title={label}>{label}</span>
    </span>
  );
  return path ? <a className="hover-link" style={{ minWidth: 0, display: "block" }} href={`#${path}`} onClick={e => e.stopPropagation()}>{body}</a>
    : <span style={{ minWidth: 0, display: "block" }}>{body}</span>;
}

const ORIGIN = {
  derived: ["Derived", "computed on read from a stored column or row — nothing is inferred"],
  stored: ["Recorded", "an edge somebody asserted, stored with its own source"],
  legacy: ["Analyst link", "link created between two IOCs before typed relationships existed"],
};

// ── Relationships ───────────────────────────────────────────────────────────
export function RelationshipsTab({ env, kind, refv, inv, reload }) {
  const { me } = useSession();
  const toast = useToast();
  const [view, setView] = useState("list");
  const [full, setFull] = useState(null);
  const [adding, setAdding] = useState(false);
  const [busyMore, setBusyMore] = useState(false);
  const rel = full || env.relationships;
  const admin = me?.role === "admin";

  async function loadAll() {
    setBusyMore(true);
    try { setFull(await apiJSON(`/v2/entity/relationships?kind=${enc(kind)}&ref=${enc(refv)}&per_group=500${inv ? `&inv=${enc(inv)}` : ""}`)); }
    catch (e) { toast(e.message, "error"); }
    setBusyMore(false);
  }
  async function remove(it) {
    if (!window.confirm("Remove this relationship?")) return;
    try {
      if (it.edge_id) await apiJSON(`/v2/relationships/${it.edge_id}`, { method: "DELETE" });
      else { const r = await api(`/iocs/relationships/${it.legacy_id}`, { method: "DELETE" }); if (!r.ok) throw new Error("Could not remove"); }
      setFull(null); reload(true);
    } catch (e) { toast(e.message, "error"); }
  }
  const removable = it => (it.edge_id && (admin || it.created_by === me?.username)) || (it.legacy_id && env.entity.tracked);

  return (
    <div className="stack">
      <Panel title="Relationships" sub={`${rel.total} across ${rel.groups.length} type${rel.groups.length === 1 ? "" : "s"}`}
        actions={<>
          <div className="seg">{[["list", "List"], ["graph", "Graph"]].map(([id, l]) => <button key={id} className={view === id ? "on" : ""} onClick={() => setView(id)}>{l}</button>)}</div>
          <Button size="sm" variant="primary" icon="plus" onClick={() => setAdding(true)}>Add relationship</Button>
        </>}>
        {view === "graph"
          ? <EntityGraph kind={kind} refv={refv} />
          : rel.groups.length === 0
            ? <EmptyState icon="link" title="No relationships recorded" desc="TFII only shows links the data supports: campaign or malware assignments, hostnames of URLs, CVE references, and edges analysts add here." />
            : <div className="stack" style={{ gap: 14 }}>
              {rel.groups.map(g => (
                <div key={`${g.rel}-${g.direction}`}>
                  <div className="eyebrow" style={{ marginBottom: 4 }}>{g.label} <span className="faint">({g.total})</span></div>
                  <div className="panel" style={{ background: "transparent" }}>
                    {g.items.map(it => (
                      <div key={`${it.kind}:${it.ref}:${it.edge_id || it.legacy_id || ""}`} className="list-row" style={{ alignItems: "flex-start", padding: "8px 14px" }}>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div className="row" style={{ gap: 8 }}>
                            <EntityChip item={it} inv={inv} />
                            {it.type && it.kind === "indicator" && <TypeBadge type={it.type} />}
                            {it.in_investigation && <Badge tone="accent" outline title="Already part of the investigation you came from">In investigation</Badge>}
                          </div>
                          <div className="faint xs" style={{ marginTop: 2, overflowWrap: "anywhere" }}>
                            <span title={(ORIGIN[it.origin] || [])[1]}>{(ORIGIN[it.origin] || [it.origin])[0]}</span>
                            {it.source && <> · {it.source}</>}
                            {it.observed_at && <> · {timeAgo(it.observed_at)}</>}
                            {it.evidence && <> · {it.evidence}</>}
                            {it.reason && <> · why: {it.reason}</>}
                            {safeUrl(it.source_ref) && <> · <a className="link" href={safeUrl(it.source_ref)} target="_blank" rel="noreferrer">reference ↗</a></>}
                          </div>
                        </div>
                        {removable(it) && <IconButton icon="x" size="sm" title="Remove relationship" onClick={() => remove(it)} />}
                      </div>
                    ))}
                    {g.total > g.items.length && (
                      <div className="list-row" style={{ justifyContent: "space-between" }}>
                        <span className="faint xs">Showing {g.items.length} of {g.total}</span>
                        {!full && <Button size="xs" variant="ghost" loading={busyMore} onClick={loadAll}>Show more</Button>}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>}
      </Panel>
      {adding && <AddRelationshipModal kind={kind} refv={env.entity.ref} title={env.entity.title} onClose={() => setAdding(false)}
        onDone={() => { setAdding(false); setFull(null); reload(true); }} />}
    </div>
  );
}

export function EntityGraph({ kind, refv, height = 480 }) {
  const [depth, setDepth] = useState(1);
  const g = useApi(`/v2/entity/graph?kind=${enc(kind)}&ref=${enc(refv)}&depth=${depth}`);
  return (
    <div>
      <div className="row" style={{ marginBottom: 8, gap: 8 }}>
        <div className="seg">{[1, 2].map(d => <button key={d} className={depth === d ? "on" : ""} onClick={() => setDepth(d)}>{d === 1 ? "Direct" : "2 hops"}</button>)}</div>
        <span className="faint xs">Drawn from the relationships above — the same data, nothing extra.</span>
      </div>
      {g.error ? <ErrorState error={g.error} onRetry={g.reload} /> : !g.data ? <Loading label="Building graph" /> :
        <Graph data={g.data} centerId={g.data.center} height={height} emptyText="No relationships to draw." />}
    </div>
  );
}

function AddRelationshipModal({ kind, refv, title, onClose, onDone }) {
  const types = useApi("/v2/relationship-types");
  const [type, setType] = useState("related_to");
  const [dir, setDir] = useState("out");
  const [q, setQ] = useState("");
  const dq = useDebounced(q.trim(), 250);
  const res = useApi(dq.length >= 2 ? `/v2/search?q=${enc(dq)}&limit=5` : null);
  const [target, setTarget] = useState(null);
  const [note, setNote] = useState("");
  const [src, setSrc] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const hits = useMemo(() => Object.values(res.data?.groups || {}).flatMap(g => g.hits).filter(h => h.kind !== "note" && !(h.kind === kind && String(h.ref).toLowerCase() === String(refv).toLowerCase())), [res.data, kind, refv]);
  // A value that looks like an indicator can be related even if TFII has never seen it.
  const raw = dq && res.data && res.data.detected_type && res.data.detected_type !== "Unknown" && res.data.detected_type !== "CVE"
    ? { kind: "indicator", ref: res.data.normalized, title: res.data.normalized, type: res.data.detected_type, untracked: true } : null;

  async function save() {
    setBusy(true);
    const me = { kind, ref: refv }, other = { kind: target.kind, ref: target.ref };
    const [a, b] = dir === "out" ? [me, other] : [other, me];
    try {
      await apiJSON("/v2/relationships", { method: "POST", body: { src_kind: a.kind, src_ref: a.ref, rel_type: type, dst_kind: b.kind, dst_ref: b.ref, note: note || null, source_ref: src.trim() || null } });
      toast("Relationship recorded", "ok"); onDone();
    } catch (e) { toast(e.message, "error"); }
    setBusy(false);
  }
  const t = (types.data?.types || []).find(x => x.id === type);
  return (
    <Modal title="Add relationship" onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!target} loading={busy} onClick={save}>Record relationship</Button></>}>
      <Callout style={{ marginBottom: 12 }}>Relationships you add are stored with your name as the source, so anyone can see who asserted the link. Add a reference URL if there is one.</Callout>
      <Field label="Direction">
        <Select value={dir} onChange={setDir} options={[["out", `${title} → target`], ["in", `target → ${title}`]]} />
      </Field>
      <Field label="Relationship"><Select value={type} onChange={setType} options={(types.data?.types || [{ id: "related_to", out: "Related to" }]).map(x => [x.id, dir === "out" ? x.out : x.in || x.out])} /></Field>
      {t && <div className="faint xs" style={{ marginTop: -6, marginBottom: 10 }}>{dir === "out" ? `${title} ${t.out.toLowerCase()} target` : `target ${t.out.toLowerCase()} ${title}`}</div>}
      <Field label="Target">
        {target ? (
          <div className="row" style={{ gap: 8 }}><EntityChip item={{ ...target, label: target.title, tracked: true }} /><span className="spacer" /><Button size="xs" variant="ghost" onClick={() => setTarget(null)}>Change</Button></div>
        ) : (
          <>
            <SearchInput value={q} onChange={setQ} placeholder="Search an indicator, CVE, actor, malware, campaign…" autoFocus />
            <div style={{ maxHeight: 220, overflow: "auto", marginTop: 6 }}>
              {[...hits, ...(raw && !hits.some(h => h.kind === "indicator" && h.ref === raw.ref) ? [raw] : [])].map(h => (
                <div key={`${h.kind}:${h.ref}`} className="list-row clickable" style={{ padding: "0 6px" }} {...actionable(() => setTarget(h))}>
                  <Icon name={(KINDS[h.kind] || KINDS.note).icon} size={13} />
                  <span className="trunc" style={{ flex: 1 }}>{h.title}</span>
                  <span className="faint xs">{h.untracked ? "not tracked · will be created as an observable" : (KINDS[h.kind] || {}).label}</span>
                </div>
              ))}
              {res.data && hits.length === 0 && !raw && <div className="faint small" style={{ padding: 8 }}>Nothing matches.</div>}
            </div>
          </>
        )}
      </Field>
      <Field label="Note (optional)"><input className="input" value={note} maxLength={300} onChange={e => setNote(e.target.value)} /></Field>
      <Field label="Reference URL (optional)"><input className="input" value={src} onChange={e => setSrc(e.target.value)} placeholder="https://…" /></Field>
    </Modal>
  );
}

// ── Activity (timeline) ─────────────────────────────────────────────────────
const TL_TONE = { first_seen: "accent", kev: "red", expiry: "red", investigation: "accent", status: "accent", resolution: "accent" };
export function TimelineTab({ events }) {
  return (
    <Panel title="Activity" sub="Only events with a recorded timestamp — nothing is estimated">
      <div className="tl">
        {events.map((e, k) => (
          <div key={k} className={`tl-item ${TL_TONE[e.type] || ""}`}>
            <div className="tl-date">{fmtDateTime(e.ts)}{e.source ? ` · ${e.source}` : ""}</div>
            <div className="tl-title" style={{ overflowWrap: "anywhere" }}>
              {e.ref_kind && entityPath(e.ref_kind, e.ref) ? <a className="hover-link" href={`#${entityPath(e.ref_kind, e.ref)}`}>{e.title}</a> : e.title}
            </div>
            {e.detail && <div className="tl-body">{e.detail}</div>}
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── Provenance: "why does TFII believe this?" ───────────────────────────────
export function SourceHistoryTab({ env }) {
  const { sources, rationale } = env;
  return (
    <div className="stack">
      {rationale.length > 0 && (
        <Panel title="Why does TFII believe this?" sub="each line traces to stored data">
          {rationale.map((r, i) => <div key={i} className="small" style={{ padding: "3px 0", color: "var(--text-2)", overflowWrap: "anywhere" }}>› {r}</div>)}
        </Panel>
      )}
      <Panel title="Sources" sub={`${sources.length} source${sources.length === 1 ? "" : "s"}`} tight>
        <div className="tbl-wrap">
          <table className="tbl compact">
            <thead><tr><th>Source</th><th>Type</th><th className="r">Reports</th><th>First</th><th>Last</th><th>Confidence</th><th>Latest</th></tr></thead>
            <tbody>
              {sources.map(s => (
                <tr key={`${s.source}-${s.source_type}`}>
                  <td className="primary" style={{ maxWidth: 200 }}>
                    <span className="trunc" style={{ display: "block" }}>{safeUrl(s.source_ref) ? <a className="link" href={safeUrl(s.source_ref)} target="_blank" rel="noreferrer">{s.source} ↗</a> : s.source}</span>
                  </td>
                  <td className="muted">{s.source_type}{s.derived && <span className="faint" title="Reconstructed from stored columns; no observation was recorded at the time"> *</span>}</td>
                  <td className="r num">{s.count}</td>
                  <td className="muted num">{timeAgo(s.first)}</td><td className="muted num">{timeAgo(s.last)}</td>
                  <td className="num">{s.confidence ?? <span className="faint">—</span>}</td>
                  <td className="wrapcell muted" style={{ maxWidth: 320, overflowWrap: "anywhere" }}>{s.latest_summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {sources.some(s => s.derived) && <div className="faint xs" style={{ padding: "8px 14px" }}>* reconstructed from stored columns (added before per-source observations were recorded).</div>}
      </Panel>
    </div>
  );
}

export function ObservationsTab({ env, children }) {
  return (
    <div className="stack">
      {children}
      {env.observations.length > 0 && (
        <Panel title="Observation ledger" sub="what each source told TFII, when it was observed and when TFII ingested it" tight>
          <div className="tbl-wrap">
            <table className="tbl compact">
              <thead><tr><th>Observed</th><th>Ingested</th><th>Source</th><th>Type</th><th>Confidence</th><th>By</th><th>Detail</th></tr></thead>
              <tbody>
                {env.observations.map((o, k) => (
                  <tr key={o.id || `d${k}`}>
                    <td className="muted num" title={fmtDateTime(o.observed_at)}>{o.observed_at ? timeAgo(o.observed_at) : "—"}</td>
                    <td className="muted num" title={fmtDateTime(o.ingested_at)}>{o.ingested_at ? timeAgo(o.ingested_at) : "—"}</td>
                    <td className="primary" style={{ maxWidth: 180 }}><span className="trunc" style={{ display: "block" }}>{safeUrl(o.source_ref) ? <a className="link" href={safeUrl(o.source_ref)} target="_blank" rel="noreferrer">{o.source} ↗</a> : o.source}</span></td>
                    <td><Badge outline>{o.type.replace(/_/g, " ")}</Badge></td>
                    <td className="num">{o.confidence ?? <span className="faint">—</span>}</td>
                    <td className="muted">{o.actor || "—"}</td>
                    <td className="wrapcell muted" style={{ maxWidth: 360, overflowWrap: "anywhere" }}>{o.summary}{o.derived && <span className="faint" title="Reconstructed from stored columns"> *</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}

// ── Investigations ──────────────────────────────────────────────────────────
export function InvestigationsTab({ env, onAdd, onEditReason }) {
  return (
    <Panel title="Investigations" sub="where this entity has been collected, and why" tight
      actions={<Button size="sm" variant="primary" icon="plus" onClick={onAdd}>Add to Workspace</Button>}>
      {env.investigations.map(i => (
        <div key={i.id} className="list-row clickable" style={{ alignItems: "flex-start", padding: "10px 16px" }}
          {...actionable(() => navigate(`/investigations/${enc(i.id)}`))}>
          <span className="mono faint xs" style={{ marginTop: 2 }}>{i.key}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ color: "var(--text)", overflowWrap: "anywhere" }}>{i.name}</div>
            <div className="small" style={{ color: i.reason ? "var(--text-2)" : "var(--text-4)", overflowWrap: "anywhere" }}>
              {i.reason ? `Relevant because: ${i.reason}` : "No reason recorded"}
              <IconButton icon="edit" size="sm" title="Edit reason" onClick={e => { e.stopPropagation(); onEditReason(i); }} />
            </div>
          </div>
          <Badge outline>{i.status}</Badge>
          <span className="faint xs">added {timeAgo(i.added_at)}{i.added_by ? ` by ${i.added_by}` : ""}</span>
        </div>
      ))}
    </Panel>
  );
}

export function RawTab({ kind, refv }) {
  const raw = useApi(`/v2/entity/raw?kind=${enc(kind)}&ref=${enc(refv)}`);
  if (raw.error) return <ErrorState error={raw.error} onRetry={raw.reload} />;
  if (!raw.data) return <Loading label="Loading record" />;
  const text = JSON.stringify(raw.data.data, null, 2);
  return (
    <Panel title="Raw record" sub="as stored; secrets are never stored here" actions={<CopyButton value={text} />}>
      <pre className="code" style={{ maxHeight: 620, overflowWrap: "anywhere", whiteSpace: "pre-wrap" }}>{text}</pre>
    </Panel>
  );
}

// ── Small dialogs ───────────────────────────────────────────────────────────
export function StatusModal({ entity, initial, onClose, onDone }) {
  const [status, setStatus] = useState(initial || entity.status);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const options = STATUS_OPTIONS.filter(([k]) => k !== "expired");
  async function save() {
    setBusy(true);
    try { await apiJSON("/v2/entity/status", { method: "POST", body: { ref: entity.ref, status, reason } }); toast("Status updated", "ok"); onDone(); }
    catch (e) { toast(e.message, "error"); }
    setBusy(false);
  }
  return (
    <Modal title="Change status" onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} onClick={save}>Save</Button></>}>
      <Field label="Status" hint="Expired is automatic: it follows the indicator's expiry date. Setting Active clears any analyst verdict.">
        <Select value={options.some(([k]) => k === status) ? status : "active"} onChange={setStatus} options={options} />
      </Field>
      <Field label="Reason (recorded in the timeline)"><input className="input" value={reason} maxLength={300} onChange={e => setReason(e.target.value)} placeholder="e.g. confirmed by sandbox detonation" /></Field>
    </Modal>
  );
}

export function TagModal({ ioc, onClose, onDone }) {
  const [t, setT] = useState("");
  const toast = useToast();
  async function save() {
    const tag = t.trim().toLowerCase();
    if (!tag) return;
    const tags = [...new Set([...(ioc.tags || []), tag])];
    try { await apiJSON(`/v2/iocs/${enc(ioc.id)}`, { method: "PATCH", body: { tags } }); toast("Tag added", "ok"); onDone(); }
    catch (e) { toast(e.message, "error"); }
  }
  return (
    <Modal title="Add tag" onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!t.trim()} onClick={save}>Add tag</Button></>}>
      <input className="input" style={{ width: "100%" }} placeholder="e.g. phishing, c2, apt29" value={t} maxLength={60}
        onChange={e => setT(e.target.value)} onKeyDown={e => e.key === "Enter" && save()} />
    </Modal>
  );
}

export function ReasonModal({ initial, title, onClose, onSave }) {
  const [r, setR] = useState(initial || "");
  return (
    <Modal title={title} onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" onClick={() => onSave(r)}>Save</Button></>}>
      <Field label="Why is this relevant to the investigation?">
        <textarea className="textarea" rows={3} value={r} maxLength={500} onChange={e => setR(e.target.value)} />
      </Field>
    </Modal>
  );
}
