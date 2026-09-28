import React, { useEffect, useState } from "react";
import { useApi, apiJSON } from "../lib/api";
import { navigate, setQuery, entityRoute, enc } from "../lib/router";
import { useSession, pushRecentSearch, recentEntities } from "../lib/session";
import { fmtNum, timeAgo } from "../lib/format";
import { PageHeader, Panel, Button, Badge, TypeBadge, SevBadge, Conf, StatusBadge, SearchInput, EmptyState, ErrorState, Loading, Callout, Segmented, useDebounced, useToast } from "../components/ui";
import Graph from "../components/Graph";
import Icon from "../components/Icon";

export function SearchPage({ q }) {
  const [text, setText] = useState(q);
  const dq = useDebounced(text.trim(), 350);
  useEffect(() => { if (dq !== q) setQuery({ q: dq }); if (dq) pushRecentSearch(dq); }, [dq]); // eslint-disable-line react-hooks/exhaustive-deps
  const { data, error, loading, reload } = useApi(q.trim() ? `/v2/search?q=${enc(q.trim())}&limit=20` : null);
  const g = data?.groups || {};
  const total = Object.values(g).reduce((s, arr) => s + (arr?.length || 0), 0);
  const t = data?.detected_type;
  const norm = data?.normalized;

  const Section = ({ title, icon, rows, render, more }) => rows && rows.length > 0 && (
    <Panel title={<><Icon name={icon} size={14} /> {title}</>} sub={`${rows.length}${rows.length >= 20 ? "+" : ""}`} tight actions={more}>
      {rows.map(render)}
    </Panel>
  );

  return (
    <div className="page narrow" style={{ maxWidth: 1200 }}>
      <PageHeader title="Global Search" sub="Indicators, CVEs, software, campaigns, threat actors, malware families, investigations and notes." />
      <SearchInput value={text} onChange={setText} autoFocus placeholder="Search anything — IP, domain, URL, hash, CVE-2024-…, actor, campaign" style={{ marginBottom: 16 }} />
      {!q.trim() && (
        <Panel title="Recently opened" tight>
          {recentEntities().length === 0 ? <div className="faint small" style={{ padding: 16 }}>Nothing yet. Tip: press <kbd>Ctrl K</kbd> anywhere to search.</div> :
            recentEntities().map(r => (
              <div key={`${r.kind}-${r.ref}`} className="list-row clickable" onClick={() => navigate(entityRoute(r.kind, r.ref))}>
                <Badge outline>{r.kind}</Badge><span className={r.kind === "ioc" ? "mono trunc" : "trunc"} style={{ flex: 1 }}>{r.label}</span><span className="faint xs">{timeAgo(new Date(r.at).toISOString())}</span>
              </div>
            ))}
        </Panel>
      )}
      {error && <ErrorState error={error} onRetry={reload} />}
      {loading && !data && q && <Loading label="Searching" />}
      {data && (
        <div className="stack">
          {t && t !== "Unknown" && (
            <Callout tone="gold" icon="target">
              <div className="row wrap" style={{ gap: 8 }}>
                <span>Looks like {t === "CVE" ? "a CVE ID" : <>a <strong>{t}</strong> indicator</>}: <span className="mono">{norm}</span></span>
                <span className="spacer" />
                {t === "CVE" ? <Button size="xs" variant="primary" onClick={() => navigate(`/cve/${enc(norm.toUpperCase())}`)}>Open CVE intelligence</Button> : <>
                  <Button size="xs" variant="primary" onClick={() => navigate(`/observable/${enc(norm)}`)}>Open entity</Button>
                  <Button size="xs" onClick={() => navigate("/osint/bulk")}>Bulk lookup</Button>
                </>}
              </div>
            </Callout>
          )}
          {data.limited && <Callout>Your account searches public sources only. Request full access to search the IOC database.</Callout>}
          {total === 0 && <EmptyState icon="search" title={`No results for “${q}”`} desc="Nothing in TFII matches. For an indicator you can still open it as an untracked observable and look up its reputation." />}
          <Section title="Indicators" icon="crosshair" rows={g.iocs} more={g.iocs?.length >= 20 && <Button size="xs" variant="ghost" onClick={() => navigate("/iocs", { q, status: "all" })}>All in IOC table</Button>}
            render={r => (
              <div key={r.id} className="list-row clickable" onClick={() => navigate(entityRoute("ioc", r.id))}>
                <TypeBadge type={r.type} /><span className="mono trunc" style={{ flex: 1 }}>{r.value}</span>
                {r.malware_family && r.malware_family !== "unknown" && <Badge tone="violet">{r.malware_family}</Badge>}
                <Conf value={r.confidence} /><StatusBadge status={r.status} /><span className="faint xs" style={{ width: 64, textAlign: "right" }}>{timeAgo(r.created_at)}</span>
              </div>)} />
          <Section title="CVEs" icon="shieldAlert" rows={g.cves} render={r => (
            <div key={r.cve_id} className="list-row clickable" onClick={() => navigate(entityRoute("cve", r.cve_id))}>
              <span className="mono" style={{ width: 140 }}>{r.cve_id}</span><span className="trunc muted" style={{ flex: 1 }}>{r.title}</span>
              {r.kev_listed && <Badge tone="critical">KEV</Badge>}<SevBadge severity={r.severity} score={r.cvss_score} /><span className="faint xs">{r.asset_name}</span>
            </div>)} />
          <Section title="Software" icon="package" rows={g.software} render={r => (
            <div key={r.id} className="list-row clickable" onClick={() => navigate(entityRoute("software", r.id))}>
              <span style={{ flex: 1, color: "var(--text)" }}>{r.name}</span><span className="faint xs">{r.vendor}</span><span className="num">{fmtNum(r.cve_count)} CVEs</span>
            </div>)} />
          <Section title="Threat actors" icon="skull" rows={g.actors} render={r => (
            <div key={r.name} className="list-row clickable" onClick={() => navigate(entityRoute("actor", r.name))}><span style={{ flex: 1 }}>{r.name}</span><span className="faint xs">{r.campaigns} campaign(s)</span></div>)} />
          <Section title="Malware families" icon="bug" rows={g.malware} render={r => (
            <div key={r.name} className="list-row clickable" onClick={() => navigate(entityRoute("malware", r.name))}><span style={{ flex: 1 }}>{r.name}</span><span className="faint xs">{fmtNum(r.iocs)} IOCs</span></div>)} />
          <Section title="Campaigns" icon="flag" rows={g.campaigns} render={r => (
            <div key={r.id} className="list-row clickable" onClick={() => navigate(entityRoute("campaign", r.id))}><span style={{ flex: 1 }}>{r.name}</span><span className="faint xs">{r.threat_actor}</span><span className="num">{fmtNum(r.ioc_count)} IOCs</span></div>)} />
          <Section title="Investigations" icon="briefcase" rows={g.investigations} render={r => (
            <div key={r.id} className="list-row clickable" onClick={() => navigate(entityRoute("investigation", r.id))}><span className="mono faint xs">{r.key}</span><span style={{ flex: 1 }}>{r.name}</span><Badge outline>{r.status}</Badge></div>)} />
          <Section title="Notes" icon="note" rows={g.notes} render={r => (
            <div key={r.id} className="list-row clickable" onClick={() => navigate(r.investigation_id ? `/investigations/${enc(r.investigation_id)}` : "/workspace", { tab: "notes" })}>
              <span className="strong" style={{ fontWeight: 500 }}>{r.title || "Untitled"}</span><span className="trunc faint" style={{ flex: 1 }}>{r.snippet}</span><span className="faint xs">{timeAgo(r.updated_at)}</span>
            </div>)} />
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
  return { nodes: [...nodes.values()], edges: [...edges.values()], truncated: a.truncated || b.truncated };
}

export function ExplorerPage({ query }) {
  const kind = query.kind, id = query.id;
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
    setBusy(true); setErr(null);
    apiJSON(`/v2/graph?kind=${enc(kind)}&id=${enc(id)}&depth=${depth}`).then(setData).catch(setErr).finally(() => setBusy(false));
  }, [kind, id, depth]);

  async function expand(node) {
    try {
      const g = await apiJSON(`/v2/graph?kind=${enc(node.kind)}&id=${enc(node.ref)}&depth=1`);
      setData(d => merge(d, g));
    } catch (e) { toast(e.message, "error"); }
  }
  const start = (k, ref) => { setQ(""); navigate("/explorer", { kind: k, id: ref }); };
  const g = res.data?.groups || {};
  const options = [
    ...(g.iocs || []).map(r => ({ k: "ioc", ref: r.id, label: r.value, meta: r.type })),
    ...(g.campaigns || []).map(r => ({ k: "campaign", ref: r.id, label: r.name, meta: "campaign" })),
    ...(g.actors || []).map(r => ({ k: "actor", ref: r.name, label: r.name, meta: "actor" })),
    ...(g.malware || []).map(r => ({ k: "malware", ref: r.name, label: r.name, meta: "malware" })),
    ...(g.investigations || []).map(r => ({ k: "investigation", ref: r.id, label: r.name, meta: r.key })),
  ];
  const recents = recentEntities().filter(r => ["ioc", "campaign", "actor", "malware", "investigation"].includes(r.kind));

  return (
    <div className="page">
      <PageHeader title="Entity Explorer" sub="Pivot across indicators, campaigns, actors, malware, CVEs and investigations. Select a node to inspect it; Expand pulls in its neighbours."
        actions={kind && <Segmented value={String(depth)} onChange={v => setDepth(Number(v))} options={[["1", "Direct"], ["2", "2 hops"]]} />} />
      <div className="grid g-side-main">
        <div className="stack">
          <Panel title="Start from" tight>
            <div style={{ padding: "4px 12px 8px" }}><SearchInput value={q} onChange={setQ} placeholder="IOC, campaign, actor, malware…" autoFocus={!kind} /></div>
            {options.map(o => (
              <div key={`${o.k}-${o.ref}`} className="list-row clickable" onClick={() => start(o.k, o.ref)}>
                <span className={o.k === "ioc" ? "mono trunc" : "trunc"} style={{ flex: 1 }}>{o.label}</span><span className="faint xs">{o.meta}</span>
              </div>
            ))}
            {dq.length >= 2 && res.data && options.length === 0 && <div className="faint small" style={{ padding: "8px 16px" }}>No graphable entities match.</div>}
            {!q && recents.length > 0 && <>
              <div className="eyebrow" style={{ padding: "8px 16px 4px" }}>Recent</div>
              {recents.map(r => <div key={`${r.kind}-${r.ref}`} className="list-row clickable" onClick={() => start(r.kind, r.ref)}><span className={r.kind === "ioc" ? "mono trunc" : "trunc"} style={{ flex: 1 }}>{r.label}</span><span className="faint xs">{r.kind}</span></div>)}
            </>}
          </Panel>
          {data && (
            <Panel title="In view">
              {Object.entries(data.nodes.reduce((m, n) => ({ ...m, [n.kind]: (m[n.kind] || 0) + 1 }), {})).map(([k, n]) => (
                <div key={k} className="row between small" style={{ height: 24 }}><span style={{ textTransform: "capitalize" }}>{k}</span><span className="num">{n}</span></div>
              ))}
              <div className="divider" />
              <div className="row between small"><span>Relationships</span><span className="num">{data.edges.length}</span></div>
              {data.truncated && <div className="faint xs" style={{ marginTop: 6 }}>Graph truncated at 260 nodes.</div>}
            </Panel>
          )}
        </div>
        <div>
          {!can("data.workspace") ? <Callout>The explorer works over your indicator database, which needs full access.</Callout> :
            !kind ? <Panel><EmptyState icon="graph" title="Pick a starting entity" desc="Search on the left, or open any IOC, campaign or actor and choose Explorer." /></Panel> :
              err ? <ErrorState error={err} /> : busy && !data ? <Panel><Loading label="Building graph" /></Panel> :
                <Graph data={data} centerId={`${kind}:${id}`} height={Math.max(520, window.innerHeight - 200)} onExpand={expand} />}
        </div>
      </div>
    </div>
  );
}
