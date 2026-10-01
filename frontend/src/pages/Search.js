import React, { useEffect, useState } from "react";
import { useApi, apiJSON } from "../lib/api";
import { navigate, setQuery, entityRoute, enc } from "../lib/router";
import { useSession, pushRecentSearch, recentEntities, recentSearches } from "../lib/session";
import { KINDS, canonicalKind } from "../lib/entity";
import { HitBadges, HitTail, hitRoute } from "../components/SearchHit";
import { timeAgo } from "../lib/format";
import { PageHeader, Panel, Button, Badge, SearchInput, EmptyState, ErrorState, Loading, Callout, Segmented, useDebounced, useToast, actionable } from "../components/ui";
import Graph from "../components/Graph";
import Icon from "../components/Icon";

export function SearchPage({ q, kinds = "" }) {
  const [text, setText] = useState(q);
  const dq = useDebounced(text.trim(), 300);
  useEffect(() => { if (dq !== q) setQuery({ q: dq }); if (dq.length >= 2) pushRecentSearch(dq); }, [dq]); // eslint-disable-line react-hooks/exhaustive-deps
  const path = q.trim() ? `/v2/search?q=${enc(q.trim())}&limit=20${kinds ? `&kinds=${enc(kinds)}` : ""}` : null;
  const { data, error, loading, reload } = useApi(path);
  const groups = Object.entries(data?.groups || {});
  const t = data?.detected_type;
  const norm = data?.normalized;
  const searches = recentSearches();

  return (
    <div className="page narrow" style={{ maxWidth: 1200 }}>
      <PageHeader title="Global Search" sub="One search over indicators, CVEs, software, malware, actors, campaigns, investigations and notes." />
      <SearchInput value={text} onChange={setText} autoFocus placeholder="Search anything — IP, domain, URL, hash, CVE-2024-…, actor, campaign" style={{ marginBottom: 12 }} />
      {data && groups.length > 0 && (
        <div className="row wrap" style={{ gap: 6, marginBottom: 12 }} role="group" aria-label="Filter by type">
          <button className={`chip ${!kinds ? "on" : ""}`} onClick={() => setQuery({ kinds: "" })}>All<span className="n">{data.total}</span></button>
          {groups.map(([k, g]) => (
            <button key={k} className={`chip ${kinds === k ? "on" : ""}`} onClick={() => setQuery({ kinds: k })}>{g.label}<span className="n">{g.count}</span></button>
          ))}
        </div>
      )}
      {!q.trim() && (
        <div className="grid g2">
          <Panel title="Recently opened" tight>
            {recentEntities().length === 0 ? <div className="faint small" style={{ padding: 16 }}>Nothing yet. Tip: press <kbd>Ctrl K</kbd> anywhere to search.</div> :
              recentEntities().map(r => (
                <div key={`${r.kind}-${r.ref}`} className="list-row clickable" {...actionable(() => navigate(entityRoute(r.kind, r.ref)))}>
                  <Badge outline>{(KINDS[canonicalKind(r.kind)] || {}).label || r.kind}</Badge><span className={["ioc", "indicator", "cve"].includes(r.kind) ? "mono trunc" : "trunc"} style={{ flex: 1 }}>{r.label}</span><span className="faint xs">{timeAgo(new Date(r.at).toISOString())}</span>
                </div>
              ))}
          </Panel>
          {searches.length > 0 && (
            <Panel title="Recent searches" tight>
              {searches.map(s => <div key={s} className="list-row clickable" {...actionable(() => { setText(s); setQuery({ q: s }); })}><Icon name="search" size={13} /><span className="trunc">{s}</span></div>)}
            </Panel>
          )}
        </div>
      )}
      {error && <ErrorState error={error} onRetry={reload} />}
      {loading && !data && q && <Loading label="Searching" />}
      {data && (
        <div className="stack">
          {t && t !== "Unknown" && (
            <Callout tone="accent" icon="target">
              <div className="row wrap" style={{ gap: 8 }}>
                <span>Looks like {t === "CVE" ? "a CVE ID" : <>a <strong>{t}</strong> indicator</>}: <span className="mono" style={{ overflowWrap: "anywhere" }}>{norm}</span></span>
                <span className="spacer" />
                {t === "CVE" ? <Button size="xs" variant="primary" onClick={() => navigate(`/cve/${enc(norm.toUpperCase())}`)}>Open CVE</Button> : <>
                  <Button size="xs" variant="primary" onClick={() => navigate(`/observable/${enc(norm)}`)}>Open indicator</Button>
                  <Button size="xs" onClick={() => navigate("/osint/bulk")}>Bulk lookup</Button>
                </>}
              </div>
            </Callout>
          )}
          {data.limited && <Callout>Your account searches public sources only. Request full access to search the IOC database.</Callout>}
          {data.total === 0 && <EmptyState icon="search" title={`No results for “${q}”`} desc="Nothing in TFII matches. For an indicator you can still open it as an untracked value and look up its reputation." />}
          {groups.map(([k, g]) => (
            <Panel key={k} title={<><Icon name={(KINDS[k] || KINDS.note).icon} size={14} /> {g.label}</>} sub={`${g.count}${g.count >= 20 ? "+" : ""}`} tight
              actions={k === "indicator" && g.count >= 20 && <Button size="xs" variant="ghost" onClick={() => navigate("/iocs", { q, status: "all" })}>All in IOC table</Button>}>
              {g.hits.map(h => {
                const [to, query] = hitRoute(h);
                return (
                  <div key={`${h.kind}-${h.ref}`} className="list-row clickable" {...actionable(() => navigate(to, query))}>
                    <HitBadges h={h} />
                    <span className={`${h.kind === "indicator" || h.kind === "cve" ? "mono " : ""}trunc`} style={{ flex: 1, color: "var(--text)" }} title={h.title}>{h.title}</span>
                    {h.subtitle && <span className="faint xs trunc" style={{ maxWidth: 320 }}>{h.subtitle}</span>}
                    <HitTail h={h} />
                  </div>
                );
              })}
            </Panel>
          ))}
          {data.took_ms !== undefined && data.total > 0 && <div className="faint xs" style={{ textAlign: "right" }}>{data.total} result{data.total === 1 ? "" : "s"} in {data.took_ms} ms</div>}
        </div>
      )}
    </div>
  );
}

// ── Entity Explorer ─────────────────────────────────────────────────────────
function merge(a, b) {
  if (!a) return b;
  const nodes = new Map(a.nodes.map(n => [n.id, n]));
  b.nodes.forEach(n => { if (!nodes.has(n.id)) nodes.set(n.id, n); });
  const key = e => `${e.source}|${e.target}|${e.type}`;
  const edges = new Map(a.edges.map(e => [key(e), e]));
  b.edges.forEach(e => edges.set(key(e), e));
  return { nodes: [...nodes.values()], edges: [...edges.values()], truncated: a.truncated || b.truncated, center: a.center };
}

export function ExplorerPage({ query }) {
  const kind = canonicalKind(query.kind || ""), id = query.id;
  const [depth, setDepth] = useState(Number(query.depth || 1));
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");
  const dq = useDebounced(q.trim(), 250);
  const res = useApi(dq.length >= 2 ? `/v2/search?q=${enc(dq)}&limit=6` : null);
  const toast = useToast();
  const { can } = useSession();

  useEffect(() => {
    if (!kind || !id) { setData(null); return; }
    let alive = true;
    setBusy(true); setErr(null);
    apiJSON(`/v2/entity/graph?kind=${enc(kind)}&ref=${enc(id)}&depth=${depth}`)
      .then(d => alive && setData(d)).catch(e => alive && setErr(e)).finally(() => alive && setBusy(false));
    return () => { alive = false; };
  }, [kind, id, depth]);

  async function expand(node) {
    try {
      const g = await apiJSON(`/v2/entity/graph?kind=${enc(canonicalKind(node.kind))}&ref=${enc(node.ref)}&depth=1`);
      setData(d => merge(d, g));
    } catch (e) { toast(e.message, "error"); }
  }
  const start = (k, ref) => { setQ(""); navigate("/explorer", { kind: k, id: ref }); };
  const options = Object.values(res.data?.groups || {}).flatMap(grp => grp.hits)
    .filter(h => ["indicator", "cve", "campaign", "actor", "malware", "software", "investigation"].includes(h.kind) && h.kind !== "investigation")
    .map(h => ({ k: h.kind, ref: h.ref, label: h.title, meta: (KINDS[h.kind] || {}).label }));
  const recents = recentEntities().filter(r => canonicalKind(r.kind) !== "investigation");

  return (
    <div className="page">
      <PageHeader title="Entity Explorer" sub="Pivot across indicators, campaigns, actors, malware, CVEs and investigations. Select a node to inspect it; Expand pulls in its neighbours."
        actions={kind && <Segmented value={String(depth)} onChange={v => setDepth(Number(v))} options={[["1", "Direct"], ["2", "2 hops"]]} />} />
      <div className="grid g-side-main">
        <div className="stack">
          <Panel title="Start from" tight>
            <div style={{ padding: "4px 12px 8px" }}><SearchInput value={q} onChange={setQ} placeholder="IOC, campaign, actor, malware…" autoFocus={!kind} /></div>
            {options.map(o => (
              <div key={`${o.k}-${o.ref}`} className="list-row clickable" {...actionable(() => start(o.k, o.ref))}>
                <span className={o.k === "indicator" ? "mono trunc" : "trunc"} style={{ flex: 1 }}>{o.label}</span><span className="faint xs">{o.meta}</span>
              </div>
            ))}
            {dq.length >= 2 && res.data && options.length === 0 && <div className="faint small" style={{ padding: "8px 16px" }}>No graphable entities match.</div>}
            {!q && recents.length > 0 && <>
              <div className="eyebrow" style={{ padding: "8px 16px 4px" }}>Recent</div>
              {recents.map(r => <div key={`${r.kind}-${r.ref}`} className="list-row clickable" {...actionable(() => start(canonicalKind(r.kind), r.ref))}><span className={["ioc", "indicator", "cve"].includes(r.kind) ? "mono trunc" : "trunc"} style={{ flex: 1 }}>{r.label}</span><span className="faint xs">{r.kind}</span></div>)}
            </>}
          </Panel>
          {data && (
            <Panel title="In view">
              {Object.entries(data.nodes.reduce((m, n) => ({ ...m, [n.kind]: (m[n.kind] || 0) + 1 }), {})).map(([k, n]) => (
                <div key={k} className="row between small" style={{ height: 24 }}><span style={{ textTransform: "capitalize" }}>{k}</span><span className="num">{n}</span></div>
              ))}
              <div className="divider" />
              <div className="row between small"><span>Relationships</span><span className="num">{data.edges.length}</span></div>
              {data.truncated && <div className="faint xs" style={{ marginTop: 6 }}>Graph capped at 120 nodes.</div>}
            </Panel>
          )}
        </div>
        <div>
          {!can("data.workspace") ? <Callout>The explorer works over your indicator database, which needs full access.</Callout> :
            !kind ? <Panel><EmptyState icon="graph" title="Pick a starting entity" desc="Search on the left, or open any IOC, campaign or actor and choose Explorer." /></Panel> :
              err ? <ErrorState error={err} /> : busy && !data ? <Panel><Loading label="Building graph" /></Panel> :
                <Graph data={data} centerId={data?.center} height={Math.max(520, window.innerHeight - 200)} onExpand={expand} />}
        </div>
      </div>
    </div>
  );
}
