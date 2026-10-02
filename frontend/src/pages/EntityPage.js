import React, { useEffect, useState } from "react";
import { useApi, apiJSON, api, downloadJSON } from "../lib/api";
import { openReport } from "../lib/report";
import { navigate, enc, setQuery } from "../lib/router";
import { useSession, pushRecentEntity } from "../lib/session";
import { KINDS, canonicalKind } from "../lib/entity";
import { fmtDate, fmtDateTime, fmtNum, timeAgo, confBand } from "../lib/format";
import { safeUrl } from "../lib/safe";
import {
  Button, IconButton, Badge, TypeBadge, TLPBadge, StatusBadge, Tabs, Loading, ErrorState, Callout, Menu, Skeleton, useToast, CopyButton,
} from "../components/ui";
import InvestigationPicker from "../components/InvestigationPicker";
import {
  RelationshipsTab, TimelineTab, SourceHistoryTab, ObservationsTab, InvestigationsTab, RawTab,
  StatusModal, TagModal, ReasonModal,
} from "./entity/parts";
import { IndicatorOverview, ObservableOverview, CveOverview, NotesPanel, Detection, hasDetections } from "./entity/Overviews";
import { SoftwareOverview, softwareTabs, SoftwareActions } from "./Cve";
import { ActorOverview, MalwareOverview } from "./Actors";
import { CampaignOverview, CampaignActions } from "./Campaigns";

const VERDICT = { critical: "Malicious", high: "Malicious", medium: "Suspicious", low: "Low risk" };

// Endpoint that feeds a kind's own overview (beyond the shared envelope).
function kindDataPath(kind, hd, hasData) {
  if (!hd || !hasData) return null;
  switch (kind) {
    case "software": return `/v2/software/${enc(hd.ref)}`;
    case "actor": return hd.tracked ? `/v2/actors/${enc(hd.ref)}` : null;
    case "malware": return `/v2/malware/${enc(hd.ref)}`;
    case "campaign": return `/v2/campaigns/${enc(hd.ref)}`;
    default: return null;
  }
}

function facts(hd, kd) {
  const f = [];
  const add = (label, value, title) => { if (value !== null && value !== undefined && value !== "" && value !== "—") f.push({ label, value, title }); };
  switch (hd.kind) {
    case "indicator":
      if (!hd.tracked) break;
      add("Confidence", hd.confidence != null ? `${hd.confidence} / 100` : null);
      add("First seen", fmtDate(hd.first_seen), fmtDateTime(hd.first_seen));
      add("Last seen", timeAgo(hd.last_seen), fmtDateTime(hd.last_seen));
      add("Source", hd.source);
      add("Campaign", hd.campaign_name && <a className="hover-link" href={`#/campaigns/${enc(hd.campaign_id)}`}>{hd.campaign_name}</a>);
      add("Threat actor", hd.threat_actor && <a className="hover-link" href={`#/actors/${enc(hd.threat_actor)}`}>{hd.threat_actor}</a>);
      add("Expires", hd.valid_until ? fmtDate(hd.valid_until) : "Never");
      break;
    case "cve":
      if (!hd.tracked) break;
      add("CVSS", hd.cvss != null ? Number(hd.cvss).toFixed(1) : null);
      add("EPSS", hd.epss != null ? `${(hd.epss * 100).toFixed(hd.epss * 100 < 1 ? 2 : 1)}%` : null);
      add("CISA KEV", hd.kev ? `Yes${hd.kev_date ? ` · ${hd.kev_date}` : ""}` : "No");
      add("Published", hd.published);
      add("Modified", hd.modified);
      add("Monitored software", hd.software_count);
      break;
    case "malware":
      add("Indicators", fmtNum(hd.indicator_count));
      add("First seen", fmtDate(hd.first_seen), fmtDateTime(hd.first_seen));
      add("Last seen", timeAgo(hd.last_seen), fmtDateTime(hd.last_seen));
      break;
    case "actor":
      add("Campaigns in TFII", hd.campaign_count);
      add("First attributed", fmtDate(hd.first_seen));
      break;
    case "campaign":
      add("Indicators", fmtNum(hd.indicator_count));
      add("Threat actor", hd.threat_actor && <a className="hover-link" href={`#/actors/${enc(hd.threat_actor)}`}>{hd.threat_actor}</a>);
      add("First seen", fmtDate(hd.first_seen));
      add("Last seen", timeAgo(hd.last_seen));
      break;
    case "software":
      add("Vendor", hd.vendor);
      add("Version", hd.version);
      add("CVEs", fmtNum(hd.cve_count));
      add("CISA KEV", fmtNum(hd.kev_count));
      add("Unpatched", fmtNum(hd.unpatched));
      add("Criticality", hd.criticality);
      break;
    default: break;
  }
  void kd;
  return f;
}

export default function EntityPage({ kind: rawKind, refv, tab = "overview", inv }) {
  const kind = canonicalKind(rawKind);
  const { me, can } = useSession();
  const hasData = can("data.workspace");
  const toast = useToast();
  const env = useApi(`/v2/entity?kind=${enc(kind)}&ref=${enc(refv)}${inv ? `&inv=${enc(inv)}` : ""}`);
  const { data, error, loading, reload } = env;
  const hd = data?.entity;
  const kd = useApi(kindDataPath(kind, hd, hasData));
  const [modal, setModal] = useState(null);

  useEffect(() => { if (hd) pushRecentEntity({ kind: hd.kind, ref: hd.kind === "indicator" ? hd.ref : hd.ref, label: hd.title }); }, [hd?.kind, hd?.ref]); // eslint-disable-line react-hooks/exhaustive-deps

  const ioc = data?.overview?.ioc;
  const canEdit = !!ioc && (me?.role === "admin" || ioc.created_by === me?.id);
  const setTab = t => setQuery({ tab: t === "overview" ? "" : t });

  if (error) {
    return (
      <div className="page">
        <ErrorState error={error} onRetry={reload} title={error.status === 404 ? `${(KINDS[kind] || {}).label || "Entity"} not found` : "Couldn't load this entity"} />
        {error.status === 404 && <div style={{ textAlign: "center", marginTop: 8 }}><Button size="sm" icon="search" onClick={() => navigate("/search", { q: refv })}>Search TFII for “{String(refv).slice(0, 60)}”</Button></div>}
      </div>
    );
  }
  if (!data) {
    return (
      <div className="page">
        <Skeleton h={22} w={220} style={{ marginBottom: 12 }} /><Skeleton h={34} w="60%" style={{ marginBottom: 20 }} /><Skeleton h={64} style={{ marginBottom: 16 }} />
        {loading ? <Loading label="Loading entity" /> : null}
      </div>
    );
  }

  const meta = KINDS[kind] || KINDS.note;
  const tracked = hd.tracked;
  const band = hd.severity || (hd.confidence != null ? confBand(hd.confidence) : null);
  const membership = data.membership;
  const srcLink = (data.sources || []).map(s => safeUrl(s.source_ref)).find(Boolean);

  // ── actions ───────────────────────────────────────────────────────────────
  async function addToWorkspace(invRow, reason) {
    try {
      await apiJSON(`/v2/investigations/${enc(invRow.id)}/entities`, { method: "POST", body: { kind, ref: hd.ref, reason } });
      reload(true);
    } catch (e) {
      if (e.status === 409) throw new Error("Already part of that investigation — edit its reason from the Investigations tab.");
      throw e;
    }
  }
  async function saveReason(itemInv, itemId, reason) {
    try { await apiJSON(`/v2/investigations/${enc(itemInv)}/items/${itemId}`, { method: "PATCH", body: { reason } }); toast("Reason saved", "ok"); setModal(null); reload(true); }
    catch (e) { toast(e.message, "error"); }
  }
  async function act(fn, okMsg) {
    try { const r = await fn(); if (okMsg) toast(typeof okMsg === "function" ? okMsg(r) : okMsg, "ok"); reload(true); }
    catch (e) { toast(e.message, "error"); }
  }
  const reEnrich = () => act(() => apiJSON(`/iocs/${enc(ioc.id)}/re-enrich`, { method: "POST" }), d => `Re-enriched · confidence ${d.confidence}`);
  const resolveDns = () => act(() => apiJSON("/v2/entity/resolve-dns", { method: "POST", body: { ref: hd.ref } }),
    d => `Resolved · ${d.new_relationships} new relationship${d.new_relationships === 1 ? "" : "s"} recorded`);
  const syncMitre = () => act(() => apiJSON("/v2/entity/sync-mitre", { method: "POST", body: { ref: hd.ref } }),
    d => `${d.group}: ${d.new_relationships} malware association${d.new_relationships === 1 ? "" : "s"} imported`);
  async function del() {
    if (!window.confirm(`Delete ${hd.value}? Notes, score history and relationships are removed too.`)) return;
    const r = await api(`/iocs/${enc(ioc.id)}`, { method: "DELETE" });
    if (r.ok) { toast("Indicator deleted", "ok"); navigate("/iocs"); } else toast("Delete failed", "error");
  }

  const isDomain = kind === "indicator" && hd.type === "Domain";
  const menu = [
    { label: "Copy value", icon: "copy", onClick: () => { navigator.clipboard?.writeText(hd.value || hd.title); toast("Copied", "ok"); } },
    { label: "Search globally", icon: "search", onClick: () => navigate("/search", { q: hd.value || hd.title }) },
    { label: "View raw data", icon: "code", onClick: () => setTab("raw"), disabled: !tracked || !["indicator", "cve", "campaign", "software"].includes(kind) },
    srcLink && { label: "View source", icon: "external", onClick: () => window.open(srcLink, "_blank", "noopener,noreferrer") },
    { label: "Export JSON", icon: "download", onClick: () => downloadJSON(`/v2/entity?kind=${enc(kind)}&ref=${enc(hd.ref)}`, `tfii-${kind}-${String(hd.title).replace(/[^\w.-]+/g, "_").slice(0, 40)}.json`).catch(e => toast(e.message, "error")) },
    "sep",
    kind === "indicator" && tracked && canEdit && { label: "Add tag", icon: "hash", onClick: () => setModal("tag") },
    kind === "indicator" && tracked && { label: "Change status", icon: "flag", onClick: () => setModal("status") },
    kind === "indicator" && tracked && canEdit && hd.status !== "false_positive" && { label: "Mark false positive", icon: "alert", onClick: () => setModal("fp") },
    kind === "indicator" && tracked && { label: "Re-enrich", icon: "refresh", onClick: reEnrich },
    isDomain && { label: "Resolve DNS (record A/AAAA)", icon: "globe", onClick: resolveDns },
    kind === "actor" && { label: "Import malware from MITRE ATT&CK", icon: "download", onClick: syncMitre },
    kind === "indicator" && { label: "OSINT lookup", icon: "radar", onClick: () => navigate("/osint/lookup", { target: hd.value }) },
    kind === "indicator" && hd.type === "IPv4" && { label: "Pivot on /24 subnet", icon: "globe", onClick: () => navigate("/iocs", { q: hd.value.split(".").slice(0, 3).join(".") + ".", status: "all" }) },
    kind === "indicator" && tracked && can("ioc.delete") && canEdit && { label: "Delete indicator", icon: "trash", danger: true, onClick: del },
  ];

  // ── tabs: empty sections do not appear ───────────────────────────────────
  const extra = kind === "software" ? softwareTabs(kd.data, hd) : [];
  const tabs = [
    { id: "overview", label: "Overview" },
    data.counts.relationships > 0 && { id: "relations", label: "Relationships", count: data.counts.relationships },
    data.counts.timeline > 0 && { id: "activity", label: "Activity", count: data.counts.timeline },
    (data.counts.observations > 0 || (kind === "indicator" && tracked)) && { id: "observations", label: "Observations", count: data.counts.observations },
    (data.counts.sources > 0 || data.rationale.length > 0) && { id: "sources", label: "Source History", count: data.counts.sources },
    kind === "indicator" && hasDetections(hd.type) && { id: "detection", label: "Detections" },
    ...extra.map(t => ({ id: t.id, label: t.label, count: t.count })),
    data.counts.investigations > 0 && { id: "investigations", label: "Investigations", count: data.counts.investigations },
    tracked && ["indicator", "cve", "campaign", "software"].includes(kind) && { id: "raw", label: "Raw Data" },
  ].filter(Boolean);
  const active = tabs.some(t => t.id === tab) ? tab : "overview";

  const factList = facts(hd, kd.data);

  return (
    <div className="page">
      {inv && membership && <ContextBanner m={membership} kind={kind} onAdd={() => setModal("add-here")} onEdit={() => setModal("reason-here")} />}

      <div className="entity-head">
        <div style={{ minWidth: 0, flex: 1 }}>
          <div className="row wrap" style={{ gap: 6, marginBottom: 8 }}>
            <Badge tone={meta.tone} dot>{meta.label}</Badge>
            {kind === "indicator" && <TypeBadge type={hd.type} />}
            {kind === "indicator" && tracked && band && !["suspicious", "confirmed", "unknown"].includes(hd.status) && <Badge tone={band} dot>{VERDICT[band] || band}</Badge>}
            {kind === "cve" && tracked && hd.severity && hd.severity !== "none" && <Badge tone={hd.severity} dot>{hd.severity}</Badge>}
            {hd.tlp && <TLPBadge tlp={hd.tlp} />}
            {hd.status && <StatusBadge status={hd.status} />}
            {hd.malware_family && <a className="badge violet" title={hd.malware_family} style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", verticalAlign: "middle", }} href={`#/malware/${enc(hd.malware_family)}`}>{hd.malware_family}</a>}
          </div>
          <div className="row" style={{ gap: 6, alignItems: "flex-start" }}>
            {["indicator", "cve"].includes(kind) ? <LongValue value={hd.title} /> : <h1 className="page-title" style={{ fontSize: 24, overflowWrap: "anywhere" }}>{hd.title}</h1>}
            <CopyButton value={hd.value || hd.title} />
          </div>
          {kind === "indicator" && hd.defanged && hd.defanged !== hd.value && <div className="mono faint" style={{ marginTop: 4, overflowWrap: "anywhere" }}>{hd.defanged} <CopyButton value={hd.defanged} /></div>}
          {kind === "cve" && hd.summary && <div className="page-sub" style={{ maxWidth: 900 }}>{hd.summary}</div>}
          {kind === "software" && <div className="page-sub">{[hd.vendor, hd.version && `version ${hd.version}`].filter(Boolean).join(" · ")}{hd.cpe && <> · <span className="mono faint">{hd.cpe}</span></>}</div>}
          {kind === "campaign" && hd.threat_actor && <div className="page-sub">Attributed to <a className="link" href={`#/actors/${enc(hd.threat_actor)}`}>{hd.threat_actor}</a></div>}
          {(hd.tags || []).length > 0 && kind !== "indicator" && kind !== "cve" && <div className="row wrap" style={{ gap: 4, marginTop: 8 }}>{hd.tags.map(t => <span key={t} className="tag">{t}</span>)}</div>}
        </div>
        <div className="page-actions">
          {kind === "indicator" && !tracked && <Button size="sm" icon="plus" onClick={() => navigate("/iocs/new", { value: hd.value })}>Track as IOC</Button>}
          {kind === "indicator" && !["CVE", "Filename"].includes(hd.type) && <Button size="sm" icon="layers" onClick={() => openReport([hd.value])}>Detailed report</Button>}
          {kind === "software" && <SoftwareActions hd={hd} />}
          {kind === "campaign" && kd.data && <CampaignActions campaign={kd.data.campaign} onChanged={() => { kd.reload(true); reload(true); }} />}
          {hasData && <Button size="sm" variant="primary" icon="briefcase" onClick={() => setModal("add")}>Add to Workspace</Button>}
          <Menu trigger={t => <IconButton icon="more" title="More actions" onClick={t} />} items={menu} />
        </div>
      </div>

      {factList.length > 0 && (
        <div className="facts">
          {factList.map(f => <div className="fact" key={f.label} title={f.title}><div className="fact-l">{f.label}</div><div className="fact-v" style={{ overflowWrap: "anywhere" }}>{f.value}</div></div>)}
        </div>
      )}

      <Tabs tabs={tabs} value={active} onChange={setTab} />

      {active === "overview" && (
        kind === "indicator" ? (tracked ? <IndicatorOverview env={data} canEdit={canEdit} reload={reload} /> : <ObservableOverview env={data} />)
          : kind === "cve" ? <CveOverview env={data} />
            : kind === "software" ? <SoftwareOverview kd={kd} hd={hd} setTab={setTab} />
              : kind === "actor" ? <ActorOverview name={hd.ref} hd={hd} kd={kd} />
                : kind === "malware" ? <MalwareOverview name={hd.ref} kd={kd} />
                  : kind === "campaign" ? <CampaignOverview kd={kd} setTab={setTab} />
                    : null
      )}
      {active === "relations" && <RelationshipsTab env={data} kind={kind} refv={hd.ref} inv={inv} reload={reload} />}
      {active === "activity" && <TimelineTab events={data.timeline} />}
      {active === "observations" && <ObservationsTab env={data}>{kind === "indicator" && tracked && <NotesPanel env={data} reload={reload} />}</ObservationsTab>}
      {active === "sources" && <SourceHistoryTab env={data} />}
      {active === "detection" && kind === "indicator" && <Detection ioc={{ type: hd.type, value: hd.value, mitre_techniques: ioc?.mitre_techniques || [] }} />}
      {extra.map(t => active === t.id && <React.Fragment key={t.id}>{t.render()}</React.Fragment>)}
      {active === "investigations" && <InvestigationsTab env={data} onAdd={() => setModal("add")} onEditReason={i => setModal({ reason: i })} />}
      {active === "raw" && <RawTab kind={kind} refv={hd.ref} />}

      {modal === "add" && <InvestigationPicker withReason title="Add to Workspace" onClose={() => setModal(null)} onPick={addToWorkspace} />}
      {modal === "add-here" && <ReasonModal title="Add to this investigation" onClose={() => setModal(null)}
        onSave={async r => { try { await addToWorkspace({ id: inv }, r.trim()); toast("Added", "ok"); setModal(null); } catch (e) { toast(e.message, "error"); } }} />}
      {modal === "reason-here" && membership?.item_id && <ReasonModal title="Why is this relevant?" initial={membership.reason} onClose={() => setModal(null)} onSave={r => saveReason(inv, membership.item_id, r)} />}
      {modal?.reason && <ReasonModal title="Why is this relevant?" initial={modal.reason.reason} onClose={() => setModal(null)} onSave={r => saveReason(modal.reason.id, modal.reason.item_id, r)} />}
      {modal === "status" && <StatusModal entity={hd} onClose={() => setModal(null)} onDone={() => { setModal(null); reload(true); }} />}
      {modal === "fp" && <StatusModal entity={hd} initial="false_positive" onClose={() => setModal(null)} onDone={() => { setModal(null); reload(true); }} />}
      {modal === "tag" && ioc && <TagModal ioc={ioc} onClose={() => setModal(null)} onDone={() => { setModal(null); reload(true); }} />}
    </div>
  );
}

// Indicator values can be kilobytes long (tracking URLs). Long ones get a smaller
// type size and a collapsed view with an explicit "Show all".
function LongValue({ value }) {
  const [open, setOpen] = useState(false);
  const long = value.length > 140;
  return (
    <div style={{ minWidth: 0 }}>
      <div className="entity-value" style={long ? { fontSize: 14, maxHeight: open ? "none" : 88, overflow: "hidden" } : undefined}>{value}</div>
      {long && <Button size="xs" variant="ghost" onClick={() => setOpen(o => !o)}>{open ? "Show less" : `Show all ${value.length} characters`}</Button>}
    </div>
  );
}

// "Opened from investigation X": keeps the analyst's context when they follow an
// entity out of the workspace, and offers the way back.
function ContextBanner({ m, kind, onAdd, onEdit }) {
  const i = m.investigation;
  return (
    <Callout tone="accent" icon="briefcase" style={{ marginBottom: 14 }}>
      <div className="row wrap" style={{ gap: 10 }}>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div>Viewing from <a className="link" href={`#/investigations/${enc(i.id)}`}><span className="mono">{i.key}</span> {i.name}</a>
            {m.member ? <> · added {timeAgo(m.added_at)}{m.added_by ? ` by ${m.added_by}` : ""}</> : <> · this {(KINDS[kind] || {}).label?.toLowerCase() || "entity"} is not part of it yet</>}</div>
          {m.member && <div className="small" style={{ color: "var(--text-2)", overflowWrap: "anywhere" }}>{m.reason ? <>Relevant because: {m.reason}</> : <span className="faint">No reason recorded.</span>}</div>}
        </div>
        {m.member ? <Button size="xs" icon="edit" onClick={onEdit}>{m.reason ? "Edit reason" : "Add reason"}</Button> : <Button size="xs" variant="primary" icon="plus" onClick={onAdd}>Add to this investigation</Button>}
        <Button size="xs" icon="chevronLeft" onClick={() => navigate(`/investigations/${enc(i.id)}`)}>Back to investigation</Button>
      </div>
    </Callout>
  );
}
