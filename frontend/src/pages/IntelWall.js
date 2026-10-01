import React, { useMemo, useState } from "react";
import { useApi, apiJSON, qs } from "../lib/api";
import { navigate, setQuery, entityRoute, enc } from "../lib/router";
import { useSession } from "../lib/session";
import { timeAgo } from "../lib/format";
import { KINDS } from "../lib/entity";
import { PageHeader, Panel, Button, Badge, SearchInput, Select, EmptyState, ErrorState, SkeletonRows, useToast, Menu, IconButton, Callout } from "../components/ui";
import { safeUrl } from "../lib/safe";
import InvestigationPicker from "../components/InvestigationPicker";
import Icon from "../components/Icon";
import { SEV_COLOR } from "../design/tokens";

const CATS = ["All", "CVE", "APT", "Ransomware", "Malware", "Vulnerability", "IOC"];
const CAT_TONE = { CVE: "critical", APT: "violet", Ransomware: "high", Malware: "high", Vulnerability: "medium", IOC: "accent", General: "low" };
const ENTITY_FILTERS = ["cve", "actor", "malware", "software", "indicator"];

export default function IntelWall({ query }) {
  const [refresh, setRefresh] = useState(0);
  const eKind = query.entity_kind || "", eRef = query.entity_ref || "";
  const path = `/v2/intel-wall${qs({ refresh: refresh ? "true" : "", entity_kind: eKind, entity_ref: eRef })}`;
  const { data, error, loading, reload } = useApi(path);
  const { can } = useSession();
  const toast = useToast();
  const cat = query.cat || "All";
  const ent = query.ent || "";
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [source, setSource] = useState("");
  const [range, setRange] = useState("");
  const [mine, setMine] = useState(false);
  const [picker, setPicker] = useState(null);
  const hasData = can("data.workspace");

  const items = useMemo(() => {
    const now = Date.now();
    return (data?.items || []).filter(it => {
      if (cat !== "All" && it.category !== cat) return false;
      if (sev && it.severity !== sev) return false;
      if (source && it.source !== source) return false;
      if (ent && !it.entities.some(e => e.kind === ent)) return false;
      if (mine && !(it.affects || []).length) return false;
      if (range && it.date) {
        const age = (now - new Date(it.date).getTime()) / 864e5;
        if (age > Number(range)) return false;
      }
      if (q) {
        const s = `${it.title} ${it.summary} ${it.entities.map(e => e.label).join(" ")}`.toLowerCase();
        if (!s.includes(q.toLowerCase())) return false;
      }
      return true;
    });
  }, [data, cat, sev, source, range, mine, q, ent]);
  const sources = useMemo(() => [...new Set((data?.items || []).map(i => i.source))].sort(), [data]);
  const affectingCount = (data?.items || []).filter(i => (i.affects || []).length).length;
  const dead = (data?.feeds || []).filter(f => !f.ok);

  async function addToWorkspace(it, inv, reason) {
    await apiJSON(`/v2/investigations/${enc(inv.id)}/events`, { method: "POST", body: { title: `Intel: ${it.title}`, body: [it.source, safeUrl(it.url)].filter(Boolean).join(" — "), occurred_at: it.date ? `${it.date.slice(0, 10)}T00:00:00` : undefined } });
    // Every entity the article is actually about, each with the article as the reason.
    for (const e of it.entities.filter(e => e.kind !== "indicator" || e.id).slice(0, 8)) {
      try { await apiJSON(`/v2/investigations/${enc(inv.id)}/entities`, { method: "POST", body: { kind: e.kind, ref: e.ref, reason: reason || `Mentioned in “${it.title.slice(0, 120)}” (${it.source})` } }); }
      catch (err) { if (err.status !== 409 && err.status !== 404) toast(err.message, "error"); }
    }
  }

  return (
    <div className="page narrow" style={{ maxWidth: 1240 }}>
      <PageHeader title="Intel Wall" sub="Threat news, advisories and vulnerability research — classified by content and linked to the entities TFII holds."
        actions={<>
          {data && <span className="faint xs">Fetched {timeAgo(data.fetched_at)}</span>}
          <Button size="sm" icon="refresh" loading={loading && !!data} onClick={() => { if (refresh) reload(); else setRefresh(1); }}>Refresh</Button>
        </>} />
      {eKind && eRef && (
        <Callout tone="accent" icon="filter" style={{ marginBottom: 10 }}>
          <div className="row" style={{ gap: 8 }}>
            <span>Showing items that mention <strong style={{ overflowWrap: "anywhere" }}>{eRef}</strong> ({(KINDS[eKind] || {}).label || eKind}).</span>
            <span className="spacer" />
            <Button size="xs" onClick={() => setQuery({ entity_kind: "", entity_ref: "" })}>Show everything</Button>
          </div>
        </Callout>
      )}
      <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
        {CATS.map(c => (
          <button key={c} className={`chip ${cat === c ? "on" : ""}`} onClick={() => setQuery({ cat: c === "All" ? "" : c })}>
            {c}<span className="n">{c === "All" ? (data?.items.length ?? "") : (data?.counts?.[c] ?? 0)}</span>
          </button>
        ))}
        {hasData && affectingCount > 0 && (
          <button className={`chip ${mine ? "on" : ""}`} onClick={() => setMine(m => !m)} style={{ marginLeft: 6 }}>
            Affects my software<span className="n">{affectingCount}</span>
          </button>
        )}
      </div>
      <div className="row wrap" style={{ gap: 8, marginBottom: 12 }}>
        <SearchInput value={q} onChange={setQ} placeholder="Search titles, CVEs, entities" style={{ width: 260 }} />
        <Select value={sev} onChange={setSev} options={[["", "Any severity"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]} />
        <Select value={source} onChange={setSource} options={[["", "All sources"], ...sources.map(s => [s, s])]} />
        <Select value={range} onChange={setRange} options={[["", "Any time"], ["1", "Last 24h"], ["7", "Last 7 days"], ["30", "Last 30 days"]]} />
        {hasData && <Select value={ent} onChange={v => setQuery({ ent: v })}
          options={[["", "Any entity"], ...ENTITY_FILTERS.map(k => [k, `Mentions ${(KINDS[k] || {}).plural?.toLowerCase() || k}${data?.entity_counts?.[k] ? ` (${data.entity_counts[k]})` : ""}`])]} />}
        {data && <span className="faint xs" style={{ marginLeft: "auto" }}>
          {(data.feeds.length - dead.length)}/{data.feeds.length} sources live
          {dead.length > 0 && <span title={dead.map(f => `${f.source}: ${f.error}`).join("\n")} style={{ color: "var(--high)", cursor: "help" }}> · {dead.length} unavailable</span>}
        </span>}
      </div>
      <Panel tight bodyStyle={{ padding: 0 }} footer={data && <span>{items.length} of {data.items.length} items</span>}>
        {error ? <ErrorState error={error} onRetry={reload} /> : loading && !data ? <SkeletonRows rows={10} cols={3} /> :
          items.length === 0 ? <EmptyState icon="rss" title="Nothing matches" desc="Try another category or clear the filters." /> :
            items.map(it => (
              <article key={it.id} className="feed-item">
                <div className="feed-rail" style={{ background: SEV_COLOR[it.severity] }} />
                <div style={{ minWidth: 0 }}>
                  <div className="row" style={{ gap: 8, marginBottom: 4 }}>
                    <span className="xs strong" style={{ color: "var(--text-2)" }}>{it.source}</span>
                    <span className="faint xs">·</span>
                    <span className="faint xs">{it.date ? timeAgo(it.date) : "undated"}</span>
                  </div>
                  {safeUrl(it.url)
                    ? <a className="feed-title" href={safeUrl(it.url)} target="_blank" rel="noreferrer">{it.title}</a>
                    : <span className="feed-title">{it.title}</span>}
                  {it.summary && <div className="feed-sum">{it.summary}</div>}
                  <div className="feed-meta">
                    <Badge tone={CAT_TONE[it.category]}>{it.category}</Badge>
                    <Badge tone={it.severity} dot>{it.severity}</Badge>
                    {(it.tags || []).map(t => <span key={t} className="tag">{t}</span>)}
                    {(it.affects || []).map(a => (
                      <a key={a.cve_id} className="badge critical" href={`#${entityRoute("software", a.asset_id)}`} title={`${a.cve_id} is tracked against ${a.asset_name}`}>Affects {a.asset_name}</a>
                    ))}
                    {it.entities.map(e => (
                      <a key={`${e.kind}:${e.ref}`} className={`tag link ${e.kind === "cve" || e.kind === "indicator" ? "mono" : ""}`} href={`#${entityRoute(e.kind, e.ref)}`}
                        title={`${(KINDS[e.kind] || {}).label || e.kind} in TFII`} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                        <Icon name={(KINDS[e.kind] || KINDS.note).icon} size={11} />{e.label}
                      </a>
                    ))}
                  </div>
                </div>
                <div className="row" style={{ alignItems: "flex-start", gap: 4 }}>
                  {safeUrl(it.url) && <a className="btn sm" href={safeUrl(it.url)} target="_blank" rel="noreferrer">Read ↗</a>}
                  {hasData && (
                    <Menu trigger={t => <IconButton icon="more" size="sm" title="Actions" onClick={t} />} items={[
                      { label: "Add to Workspace", icon: "briefcase", onClick: () => setPicker(it) },
                      ...it.entities.slice(0, 4).map(e => ({ label: `Open ${e.label.slice(0, 40)}`, icon: (KINDS[e.kind] || KINDS.note).icon, onClick: () => navigate(entityRoute(e.kind, e.ref)) })),
                    ]} />
                  )}
                </div>
              </article>
            ))}
      </Panel>
      {picker && <InvestigationPicker withReason title="Add to Workspace" onClose={() => setPicker(null)} onPick={(inv, reason) => addToWorkspace(picker, inv, reason)} />}
    </div>
  );
}
