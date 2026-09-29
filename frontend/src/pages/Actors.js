import React, { useState } from "react";
import { useApi } from "../lib/api";
import { navigate, setQuery, entityRoute, enc } from "../lib/router";
import { useSession } from "../lib/session";
import { fmtNum, fmtDate, timeAgo } from "../lib/format";
import { PageHeader, Panel, Button, Badge, TypeBadge, Tabs, SearchInput, EmptyState, ErrorState, Loading, Skeleton, Callout, Conf, StatusBadge, actionable, rowAction } from "../components/ui";
import { BarList } from "../components/charts";
import { safeUrl } from "../lib/safe";
import { T, TYPE_COLOR } from "../design/tokens";

// Well-known groups offered as a starting point for MITRE ATT&CK lookups.
const DIRECTORY = [
  { name: "Lazarus Group", origin: "North Korea", focus: "Financial, espionage" },
  { name: "APT28", origin: "Russia", focus: "Government, military" },
  { name: "APT29", origin: "Russia", focus: "Government, think tanks" },
  { name: "Sandworm Team", origin: "Russia", focus: "Critical infrastructure" },
  { name: "Scattered Spider", origin: "—", focus: "Telecom, finance" },
  { name: "Volt Typhoon", origin: "China", focus: "Critical infrastructure" },
  { name: "APT41", origin: "China", focus: "Espionage, cybercrime" },
  { name: "Kimsuky", origin: "North Korea", focus: "Government, research" },
  { name: "Turla", origin: "Russia", focus: "Government, diplomacy" },
  { name: "FIN7", origin: "—", focus: "Retail, hospitality" },
  { name: "OilRig", origin: "Iran", focus: "Middle East, energy" },
  { name: "MuddyWater", origin: "Iran", focus: "Government, telecom" },
];

export function ActorsPage({ query }) {
  const { can } = useSession();
  const hasData = can("data.workspace");
  const tab = query.tab || (hasData ? "tracked" : "directory");
  const { data, error, loading, reload } = useApi(hasData ? "/v2/actors" : null);
  const [q, setQ] = useState("");
  const filt = rows => rows.filter(r => !q || r.name.toLowerCase().includes(q.toLowerCase()));

  return (
    <div className="page">
      <PageHeader title="Threat Actors" sub="Actors attributed in your campaigns, malware families observed in your feed, and MITRE ATT&CK group profiles."
        actions={<SearchInput value={q} onChange={setQ} placeholder="Filter or look up an actor…" style={{ width: 280 }}
          onKeyDown={e => { if (e.key === "Enter" && q.trim()) navigate(entityRoute("actor", q.trim())); }} />} />
      <Tabs value={tab} onChange={t => setQuery({ tab: t })} tabs={[
        hasData && { id: "tracked", label: "Tracked actors", count: data?.actors.length },
        hasData && { id: "malware", label: "Malware families", count: data?.malware.length },
        { id: "directory", label: "ATT&CK directory" },
      ]} />
      {error && <ErrorState error={error} onRetry={reload} />}
      {tab === "tracked" && hasData && (
        <Panel tight bodyStyle={{ padding: 0 }}>
          {loading && !data ? <div style={{ padding: 16 }}><Skeleton h={120} /></div> : filt(data?.actors || []).length === 0 ? (
            <EmptyState icon="skull" title="No attributed actors yet" desc="Set a threat actor on a campaign to see it here with its infrastructure. You can also look up any group in the ATT&CK directory."
              action={<Button size="sm" onClick={() => navigate("/campaigns")}>Go to campaigns</Button>} />
          ) : (
            <table className="tbl"><thead><tr><th>Actor</th><th className="r">Campaigns</th><th className="r">Indicators</th><th>Campaigns</th><th>Last activity</th></tr></thead>
              <tbody>{filt(data.actors).map(a => (
                <tr key={a.name} className="clickable" {...rowAction(() => navigate(entityRoute("actor", a.name)))}>
                  <td className="primary strong">{a.name}</td>
                  <td className="r num">{a.campaigns}</td><td className="r num">{fmtNum(a.iocs)}</td>
                  <td className="muted trunc" style={{ maxWidth: 320 }}>{(a.campaign_names || []).join(", ")}</td>
                  <td className="muted">{a.last_activity ? timeAgo(a.last_activity) : "—"}</td>
                </tr>))}</tbody></table>
          )}
        </Panel>
      )}
      {tab === "malware" && hasData && (
        <Panel tight bodyStyle={{ padding: 0 }}>
          {loading && !data ? <div style={{ padding: 16 }}><Skeleton h={120} /></div> : filt(data?.malware || []).length === 0 ? (
            <EmptyState icon="bug" title="No malware families yet" desc="Enable the ThreatFox or MalwareBazaar connectors — they tag indicators with malware families." />
          ) : (
            <table className="tbl"><thead><tr><th>Family</th><th className="r">Indicators</th><th className="r">Last 7 days</th><th>Types</th><th>First seen</th><th>Last seen</th></tr></thead>
              <tbody>{filt(data.malware).map(m => (
                <tr key={m.name} className="clickable" {...rowAction(() => navigate(entityRoute("malware", m.name)))}>
                  <td className="primary strong">{m.name}</td>
                  <td className="r num">{fmtNum(m.iocs)}</td>
                  <td className="r num" style={{ color: m.recent ? "var(--high)" : "var(--text-4)" }}>{m.recent ? `+${m.recent}` : "0"}</td>
                  <td><div className="row" style={{ gap: 3 }}>{(m.types || []).map(t => <TypeBadge key={t} type={t} />)}</div></td>
                  <td className="muted">{fmtDate(m.first_seen)}</td><td className="muted">{timeAgo(m.last_seen)}</td>
                </tr>))}</tbody></table>
          )}
        </Panel>
      )}
      {tab === "directory" && (
        <div className="grid g4">
          {DIRECTORY.filter(a => !q || a.name.toLowerCase().includes(q.toLowerCase())).map(a => (
            <div key={a.name} className="tool-card" style={{ minHeight: 0 }} onClick={() => navigate(entityRoute("actor", a.name))}>
              <div className="row between"><span className="tool-name">{a.name}</span><Badge outline>{a.origin}</Badge></div>
              <div className="tool-desc">{a.focus}</div>
              <div className="tool-open">MITRE ATT&CK profile →</div>
            </div>
          ))}
          {q && !DIRECTORY.some(a => a.name.toLowerCase().includes(q.toLowerCase())) && (
            <div className="tool-card" style={{ minHeight: 0 }} onClick={() => navigate(entityRoute("actor", q.trim()))}>
              <div className="tool-name">Look up “{q}”</div><div className="tool-desc">Search MITRE ATT&CK by name or alias.</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Bodies for the shared entity page (header, facts and tabs live in EntityPage).
export function ActorOverview({ name, hd, kd }) {
  const { can } = useSession();
  const hasData = can("data.workspace");
  const mitre = useApi(`/mitre/actor?name=${enc(name)}`);
  const m = mitre.data;
  const t = kd.data;

  return (
    <div className="grid g-main-side">
      <div className="stack">
        <Panel title="Profile" sub="MITRE ATT&CK" actions={safeUrl(m?.mitre_url) && <a className="btn sm" href={safeUrl(m.mitre_url)} target="_blank" rel="noreferrer">ATT&CK ↗</a>}>
          {mitre.loading && !m ? <Loading label="Querying MITRE ATT&CK (large dataset, may take a few seconds)" /> :
            mitre.error ? <ErrorState error={mitre.error} onRetry={mitre.reload} /> :
              !m?.found ? <Callout tone="warn">No ATT&CK group matches “{name}”.{m?.error ? ` (${m.error})` : " Try an alias — e.g. Fancy Bear for APT28."}</Callout> : (
                <>
                  {m.also_known_as?.length > 1 && <div className="small faint" style={{ marginBottom: 8 }}>Also known as {m.also_known_as.filter(a => a !== m.name).join(", ")}</div>}
                  <div className="small" style={{ lineHeight: 1.65, color: "var(--text-2)", overflowWrap: "anywhere" }}>{(m.description || "").replace(/\(Citation:[^)]*\)/g, "")}</div>
                  {m.ttps?.length > 0 && <>
                    <div className="eyebrow" style={{ margin: "14px 0 6px" }}>Techniques ({m.ttps.length})</div>
                    <div className="row wrap" style={{ gap: 4 }}>
                      {m.ttps.map(x => <a key={x} className="badge violet" href={`https://attack.mitre.org/techniques/${x.split(" ")[0].replace(".", "/")}/`} target="_blank" rel="noreferrer">{x}</a>)}
                    </div>
                  </>}
                  <div className="grid g2" style={{ marginTop: 14 }}>
                    {m.malware_used?.length > 0 && <div><div className="eyebrow" style={{ marginBottom: 6 }}>Malware</div><div className="row wrap" style={{ gap: 4 }}>{m.malware_used.map(x => <a key={x} className="tag link" href={`#${entityRoute("malware", x)}`}>{x}</a>)}</div></div>}
                    {m.tools_used?.length > 0 && <div><div className="eyebrow" style={{ marginBottom: 6 }}>Tools</div><div className="row wrap" style={{ gap: 4 }}>{m.tools_used.map(x => <span key={x} className="tag">{x}</span>)}</div></div>}
                  </div>
                </>
              )}
        </Panel>
        {hasData && !hd.tracked && <Callout>No TFII campaign attributes this actor yet. Set the threat actor on a campaign to link infrastructure to it.</Callout>}
      </div>
      <div className="stack">
        {hasData && t && t.campaigns.length > 0 && (
          <Panel title="Campaigns" tight>
            {t.campaigns.map(c => (
              <div key={c.id} className="list-row clickable" {...actionable(() => navigate(entityRoute("campaign", c.id)))}>
                <span style={{ flex: 1, color: "var(--text)" }} className="trunc">{c.name}</span><span className="faint xs">{c.ioc_count} IOCs</span>
              </div>
            ))}
          </Panel>
        )}
        {hasData && t && t.types.length > 0 && <Panel title="Indicator mix"><BarList items={t.types.map(x => ({ label: x.type, value: Number(x.n), color: TYPE_COLOR[x.type], dot: true }))} /></Panel>}
        {hasData && t && t.malware.length > 0 && <Panel title="Malware observed"><BarList items={t.malware.map(x => ({ label: x.name, value: Number(x.n), color: "#F472B6" }))} onClick={it => navigate(entityRoute("malware", it.label))} /></Panel>}
        {m?.references?.length > 0 && <Panel title="References" tight>{m.references.filter(safeUrl).map(r => <a key={r} className="list-row clickable" href={safeUrl(r)} target="_blank" rel="noreferrer"><span className="trunc link small">{r}</span></a>)}</Panel>}
      </div>
    </div>
  );
}

// Accounts without indicator-database access still get the public ATT&CK profile.
export function ActorPublicPage({ name }) {
  const kd = { data: null, error: null, loading: false, reload: () => {} };
  return (
    <div className="page">
      <div className="entity-head"><div>
        <div className="row" style={{ gap: 6, marginBottom: 6 }}><Badge tone="critical" dot>Threat actor</Badge></div>
        <h1 className="page-title" style={{ fontSize: 24, overflowWrap: "anywhere" }}>{name}</h1>
      </div></div>
      <ActorOverview name={name} hd={{ tracked: false }} kd={kd} />
    </div>
  );
}

export function MalwareOverview({ name, kd }) {
  const { data, error, loading, reload } = kd;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading || !data) return <Loading />;
  return (
    <div className="grid g-main-side">
      <div className="stack">
        <Panel title="Latest indicators" tight actions={<><Button size="xs" variant="ghost" onClick={() => navigate("/iocs", { q: name, status: "all" })}>Open in IOC table</Button>
          <a className="btn xs" href={`https://malpedia.caad.fkie.fraunhofer.de/search?q=${enc(name)}`} target="_blank" rel="noreferrer">Malpedia ↗</a></>}>
          <div className="tbl-wrap"><table className="tbl compact"><thead><tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Status</th><th>Seen</th></tr></thead>
            <tbody>{data.iocs.slice(0, 100).map(i => (
              <tr key={i.id} className="clickable" {...rowAction(() => navigate(entityRoute("ioc", i.id)))}>
                <td className="cellmono trunc" style={{ maxWidth: 420 }}>{i.value}</td><td><TypeBadge type={i.type} /></td>
                <td><Conf value={i.confidence} /></td><td><StatusBadge status={i.status} /></td><td className="muted">{timeAgo(i.created_at)}</td>
              </tr>))}</tbody></table></div>
        </Panel>
      </div>
      <div className="stack">
        <Panel title="Indicator types"><BarList items={data.types.map(x => ({ label: x.type, value: Number(x.n), color: TYPE_COLOR[x.type], dot: true }))} onClick={it => navigate("/iocs", { q: name, type: it.label, status: "all" })} /></Panel>
        <Panel title="Sources"><BarList items={data.sources.map(x => ({ label: x.source, value: Number(x.n) }))} color={T.text3} /></Panel>
        {data.campaigns.length > 0 && <Panel title="Campaigns" tight>{data.campaigns.map(c => (
          <div key={c.id} className="list-row clickable" {...actionable(() => navigate(entityRoute("campaign", c.id)))}><span style={{ flex: 1 }}>{c.name}</span>{c.threat_actor && <span className="faint xs">{c.threat_actor}</span>}</div>
        ))}</Panel>}
      </div>
    </div>
  );
}
