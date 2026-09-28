import React, { useMemo, useState } from "react";
import { useApi, apiJSON } from "../lib/api";
import { navigate, setQuery, entityRoute, enc } from "../lib/router";
import { useSession } from "../lib/session";
import { timeAgo } from "../lib/format";
import { PageHeader, Panel, Button, Badge, SearchInput, Select, EmptyState, ErrorState, SkeletonRows, useToast, Menu, IconButton } from "../components/ui";
import InvestigationPicker from "../components/InvestigationPicker";
import { SEV_COLOR } from "../design/tokens";

const CATS = ["All", "CVE", "APT", "Ransomware", "Malware", "Vulnerability", "IOC"];
const CAT_TONE = { CVE: "critical", APT: "violet", Ransomware: "high", Malware: "high", Vulnerability: "medium", IOC: "gold", General: "low" };

export default function IntelWall({ query }) {
  const [refresh, setRefresh] = useState(0);
  const { data, error, loading, reload } = useApi(`/v2/intel-wall${refresh ? "?refresh=true" : ""}`, [refresh]);
  const { can } = useSession();
  const toast = useToast();
  const cat = query.cat || "All";
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [source, setSource] = useState("");
  const [range, setRange] = useState("");
  const [mine, setMine] = useState(false);
  const [picker, setPicker] = useState(null);

  const items = useMemo(() => {
    const now = Date.now();
    return (data?.items || []).filter(it => {
      if (cat !== "All" && it.category !== cat) return false;
      if (sev && it.severity !== sev) return false;
      if (source && it.source !== source) return false;
      if (mine && !(it.affects || []).length) return false;
      if (range && it.date) {
        const age = (now - new Date(it.date).getTime()) / 864e5;
        if (age > Number(range)) return false;
      }
      if (q) {
        const s = `${it.title} ${it.summary} ${it.cves.join(" ")} ${it.actors.join(" ")}`.toLowerCase();
        if (!s.includes(q.toLowerCase())) return false;
      }
      return true;
    });
  }, [data, cat, sev, source, range, mine, q]);
  const sources = useMemo(() => [...new Set((data?.items || []).map(i => i.source))].sort(), [data]);
  const affectingCount = (data?.items || []).filter(i => (i.affects || []).length).length;
  const dead = (data?.feeds || []).filter(f => !f.ok);

  return (
    <div className="page narrow" style={{ maxWidth: 1240 }}>
      <PageHeader title="Intel Wall" sub="Threat news, advisories and vulnerability research — classified by content and cross-referenced with the software you monitor."
        actions={<>
          {data && <span className="faint xs">Fetched {timeAgo(data.fetched_at)}</span>}
          <Button size="sm" icon="refresh" loading={loading && !!data} onClick={() => { if (refresh) reload(); else setRefresh(1); }}>Refresh</Button>
        </>} />
      <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
        {CATS.map(c => (
          <button key={c} className={`chip ${cat === c ? "on" : ""}`} onClick={() => setQuery({ cat: c === "All" ? "" : c })}>
            {c}<span className="n">{c === "All" ? (data?.items.length ?? "") : (data?.counts?.[c] ?? 0)}</span>
          </button>
        ))}
        {can("data.workspace") && affectingCount > 0 && (
          <button className={`chip ${mine ? "on" : ""}`} onClick={() => setMine(m => !m)} style={{ marginLeft: 6 }}>
            Affects my software<span className="n">{affectingCount}</span>
          </button>
        )}
      </div>
      <div className="row wrap" style={{ gap: 8, marginBottom: 12 }}>
        <SearchInput value={q} onChange={setQ} placeholder="Search titles, CVEs, actors" style={{ width: 280 }} />
        <Select value={sev} onChange={setSev} options={[["", "Any severity"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]} />
        <Select value={source} onChange={setSource} options={[["", "All sources"], ...sources.map(s => [s, s])]} />
        <Select value={range} onChange={setRange} options={[["", "Any time"], ["1", "Last 24h"], ["7", "Last 7 days"], ["30", "Last 30 days"]]} />
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
                  <a className="feed-title" href={it.url || undefined} target="_blank" rel="noreferrer">{it.title}</a>
                  {it.summary && <div className="feed-sum">{it.summary}</div>}
                  <div className="feed-meta">
                    <Badge tone={CAT_TONE[it.category]}>{it.category}</Badge>
                    <Badge tone={it.severity} dot>{it.severity}</Badge>
                    {(it.affects || []).map(a => (
                      <a key={a.cve_id} className="badge critical" href={`#${entityRoute("software", a.asset_id)}`} title={`${a.cve_id} is tracked against ${a.asset_name}`}>Affects {a.asset_name}</a>
                    ))}
                    {it.cves.map(c => <a key={c} className="tag link mono" href={`#${entityRoute("cve", c)}`}>{c}</a>)}
                    {it.actors.map(a => <a key={a} className="tag link" href={`#${entityRoute("actor", a)}`}>{a}</a>)}
                  </div>
                </div>
                <div className="row" style={{ alignItems: "flex-start", gap: 4 }}>
                  {it.url && <a className="btn sm" href={it.url} target="_blank" rel="noreferrer">Read ↗</a>}
                  {can("data.workspace") && (
                    <Menu trigger={t => <IconButton icon="more" size="sm" title="Actions" onClick={t} />} items={[
                      { label: "Add to investigation", icon: "briefcase", onClick: () => setPicker(it) },
                      ...it.cves.slice(0, 3).map(c => ({ label: `Open ${c}`, icon: "shieldAlert", onClick: () => navigate(entityRoute("cve", c)) })),
                    ]} />
                  )}
                </div>
              </article>
            ))}
      </Panel>
      {picker && <InvestigationPicker onClose={() => setPicker(null)} onPick={async inv => {
        await apiJSON(`/v2/investigations/${enc(inv.id)}/events`, { method: "POST", body: { title: `Intel: ${picker.title}`, body: [picker.source, picker.url].filter(Boolean).join(" — "), occurred_at: picker.date ? `${picker.date}T00:00:00` : undefined } });
        for (const c of picker.cves.slice(0, 5)) {
          try { await apiJSON(`/v2/investigations/${enc(inv.id)}/items`, { method: "POST", body: { item_type: "cve", ref_id: c } }); } catch (e) { if (e.status !== 409) toast(e.message, "error"); }
        }
      }} />}
    </div>
  );
}
