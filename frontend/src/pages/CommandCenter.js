import React from "react";
import { useApi } from "../lib/api";
import { navigate, entityRoute, Link, enc } from "../lib/router";
import { fmtNum, timeAgo, trendPct, normSev } from "../lib/format";
import { KPI, Panel, PageHeader, Button, SevBadge, TypeBadge, Skeleton, ErrorState, EmptyState, Badge } from "../components/ui";
import { StackedBars, Donut, BarList, SevStack } from "../components/charts";
import { SEV_COLOR, TYPE_COLOR, T } from "../design/tokens";
import Icon from "../components/Icon";

const PULSE_TONE = { critical: T.critical, high: T.high, medium: T.medium };

export default function CommandCenter() {
  const { data, error, loading, reload } = useApi("/v2/command-center");

  if (error) return <div className="page"><ErrorState error={error} onRetry={reload} /></div>;
  const m = data?.metrics;
  const i = m?.iocs || {}, c = m?.cves || {}, camp = m?.campaigns || {};

  return (
    <div className="page">
      <PageHeader title="Command Center" sub="What is happening in your intelligence environment right now."
        actions={<>
          {data && <span className="faint xs">Updated {timeAgo(data.generated_at)}</span>}
          <Button size="sm" icon="refresh" onClick={() => reload()} loading={loading && !!data}>Refresh</Button>
          <Button size="sm" variant="primary" icon="plus" onClick={() => navigate("/iocs/new")}>Add IOC</Button>
        </>} />

      <div className="kpis" style={{ marginBottom: 12 }}>
        {!data ? Array.from({ length: 8 }).map((_, k) => (
          <div key={k} className="kpi"><Skeleton w="60%" h={10} /><Skeleton w="40%" h={22} style={{ margin: "6px 0" }} /><Skeleton w="50%" h={9} /></div>
        )) : <>
          <KPI label="Active IOCs" value={i.active} spark={m.ioc_series} sparkColor={T.text3}
            delta={trendPct(i.last7, i.prev7)} deltaLabel="added vs prior 7d" onClick={() => navigate("/iocs")} />
          <KPI label="High-confidence IOCs" value={i.high_conf} spark={m.high_series} sparkColor={T.high} tone={T.high}
            sub="confidence ≥ 80" onClick={() => navigate("/iocs", { min_conf: 80 })} />
          <KPI label="New intelligence today" value={i.today} delta={trendPct(i.today, i.yesterday)} deltaLabel={`vs ${fmtNum(i.yesterday)} yesterday`}
            onClick={() => navigate("/iocs", { since_days: 1 })} />
          <KPI label="Critical intelligence" value={i.critical} tone={T.critical} sub="confidence ≥ 90, active"
            onClick={() => navigate("/iocs", { min_conf: 90 })} />
          <KPI label="CVEs monitored" value={c.total} spark={m.cve_series} sparkColor={T.medium} sub={`${fmtNum(c.new7)} new this week`}
            onClick={() => navigate("/cve", { tab: "cves" })} />
          <KPI label="Unpatched CVEs" value={c.unpatched} tone={T.high} sub={`${fmtNum(c.critical_unpatched)} critical`} upIsBad
            onClick={() => navigate("/cve", { tab: "cves", patched: "no" })} />
          <KPI label="CISA KEV" value={c.kev} tone={T.critical} sub={`${fmtNum(c.kev_unpatched)} unpatched`}
            onClick={() => navigate("/cve", { tab: "cves", kev: "1" })} />
          <KPI label="Active campaigns" value={camp.active} sub={`of ${fmtNum(camp.total)} tracked · 30d`} onClick={() => navigate("/campaigns")} />
        </>}
      </div>

      <div className="grid g-main-side" style={{ marginBottom: 12 }}>
        <Panel title="IOC Activity" sub="last 30 days, by type"
          actions={<Link to="/iocs" className="link small">Open feed</Link>}>
          {!data ? <Skeleton h={200} /> : data.activity.series.length === 0
            ? <EmptyState icon="activity" title="No indicators in the last 30 days" desc="Enable a connector or add IOCs to see activity here." />
            : <>
              <StackedBars days={data.activity.days} height={230}
                series={data.activity.series.slice(0, 7).map(s => ({ key: s.type, label: s.type, color: TYPE_COLOR[s.type] || T.text3, values: s.values }))}
                onBarClick={() => navigate("/iocs", { since_days: 30 })} />
              <div className="row wrap xs muted" style={{ gap: 14, marginTop: 10 }}>
                {data.activity.series.slice(0, 7).map(s => (
                  <span key={s.type} className="row hover-link" style={{ gap: 5, cursor: "pointer" }} onClick={() => navigate("/iocs", { type: s.type, since_days: 30 })}>
                    <span className="sev-dot" style={{ background: TYPE_COLOR[s.type] || T.text3 }} />{s.type}<span className="num" style={{ color: "var(--text)" }}>{fmtNum(s.total)}</span>
                  </span>
                ))}
              </div>
            </>}
        </Panel>

        <Panel title={<><span className="live-dot" /> Threat Pulse</>} sub="derived from your data" tight bodyStyle={{ maxHeight: 330, overflowY: "auto" }} bodyProps={{ tabIndex: 0, "aria-label": "Threat pulse items" }}>
          {!data ? <div style={{ padding: 16 }}><Skeleton h={160} /></div>
            : data.pulse.length === 0
              ? <EmptyState icon="zap" title="Quiet" desc="No actively exploited CVEs, fresh malware activity or campaign movement right now." />
              : data.pulse.map((p, k) => (
                <div key={k} className="pulse-item" onClick={() => navigate(p.route)} role="link">
                  <div style={{ background: PULSE_TONE[p.severity] || T.text3, borderRadius: 2 }} />
                  <div style={{ minWidth: 0 }}>
                    <div className="pulse-label" style={{ color: PULSE_TONE[p.severity] || T.text3 }}>{p.label}</div>
                    <div className="pulse-title trunc">{p.title}</div>
                    <div className="pulse-detail">{p.detail}</div>
                  </div>
                  <div className="faint xs" style={{ whiteSpace: "nowrap" }}>{timeAgo(p.ts)}</div>
                </div>
              ))}
        </Panel>
      </div>

      <div className="grid g3" style={{ marginBottom: 12 }}>
        <Panel title="IOC Type Distribution" sub="active indicators">
          {!data ? <Skeleton h={140} /> : (() => {
            const rows = data.type_distribution.map(t => ({ label: t.type, value: Number(t.n), color: TYPE_COLOR[t.type] || T.text3 }));
            const total = rows.reduce((s, r) => s + r.value, 0);
            if (!total) return <EmptyState title="No active indicators" />;
            return (
              <div className="row" style={{ gap: 18, alignItems: "center" }}>
                <Donut data={rows} center={{ value: fmtNum(total), label: "active" }} onSlice={d => navigate("/iocs", { type: d.label })} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  {rows.slice(0, 7).map(r => (
                    <div key={r.label} className="row between small hover-link" style={{ height: 24, cursor: "pointer" }} onClick={() => navigate("/iocs", { type: r.label })}>
                      <span className="row" style={{ gap: 6 }}><span className="sev-dot" style={{ background: r.color }} />{r.label}</span>
                      <span className="num muted">{fmtNum(r.value)} <span className="faint">· {Math.round((r.value / total) * 100)}%</span></span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}
        </Panel>

        <Panel title="CVE Exposure" sub="by severity" actions={<Link to="/cve" className="link small">Software view</Link>}>
          {!data ? <Skeleton h={140} /> : (() => {
            const ex = Object.fromEntries(data.metrics.cve_exposure.map(r => [String(r.severity).toLowerCase(), r]));
            const keys = ["critical", "high", "medium", "low"];
            const un = Object.fromEntries(keys.map(k => [k, Number(ex[k]?.unpatched || 0)]));
            if (!c.total) return <EmptyState icon="shieldAlert" title="No CVEs monitored" desc="Add software in CVE Intelligence to start tracking exposure." action={<Button size="sm" onClick={() => navigate("/cve", { tab: "manage" })}>Add software</Button>} />;
            return (
              <>
                <div className="row between small" style={{ marginBottom: 8 }}><span className="muted">Unpatched</span><span className="num strong">{fmtNum(c.unpatched)} / {fmtNum(c.total)}</span></div>
                <SevStack counts={un} height={8} />
                <div style={{ marginTop: 12 }}>
                  {keys.map(k => (
                    <div key={k} className="row between small hover-link" style={{ height: 26, cursor: "pointer" }} onClick={() => navigate("/cve", { tab: "cves", severity: k, patched: "no" })}>
                      <span className="row" style={{ gap: 6, textTransform: "capitalize" }}><span className="sev-dot" style={{ background: SEV_COLOR[k] }} />{k}</span>
                      <span className="num"><span style={{ color: "var(--text)" }}>{fmtNum(un[k])}</span><span className="faint"> unpatched · {fmtNum(ex[k]?.patched || 0)} patched</span></span>
                    </div>
                  ))}
                </div>
              </>
            );
          })()}
        </Panel>

        <Panel title="Top Threat Actors & Malware" actions={<Link to="/actors" className="link small">All</Link>}>
          {!data ? <Skeleton h={140} /> : (data.actors.length + data.malware.length === 0)
            ? <EmptyState icon="skull" title="No attribution yet" desc="Link campaigns to threat actors, or enable ThreatFox/MalwareBazaar to populate malware families." />
            : <BarList
                items={[
                  ...data.actors.map(a => ({ label: a.name, value: Number(a.iocs), color: T.critical, dot: true, meta: "actor", kind: "actor" })),
                  ...data.malware.map(a => ({ label: a.name, value: Number(a.iocs), color: "#F472B6", dot: true, meta: a.recent ? `+${a.recent} 7d` : "malware", kind: "malware" })),
                ].sort((x, y) => y.value - x.value).slice(0, 8)}
                onClick={it => navigate(entityRoute(it.kind, it.label))} />}
        </Panel>
      </div>

      <div className="grid g-main-side">
        <Panel title="Recent Intelligence" tight actions={<Link to="/iocs" query={{ sort: "created" }} className="link small">View all</Link>}>
          {!data ? <div style={{ padding: 16 }}><Skeleton h={200} /></div> : (() => {
            const rows = [
              ...data.recent_iocs.map(r => ({ kind: "ioc", ts: r.created_at, r })),
              ...data.recent_cves.map(r => ({ kind: "cve", ts: r.created_at, r })),
            ].sort((a, b) => String(b.ts).localeCompare(String(a.ts))).slice(0, 12);
            if (!rows.length) return <EmptyState title="Nothing yet" />;
            return rows.map((x, k) => x.kind === "ioc" ? (
              <div key={k} className="list-row clickable" onClick={() => navigate(entityRoute("ioc", x.r.id))}>
                <TypeBadge type={x.r.type} />
                <span className="mono trunc" style={{ flex: 1 }}>{x.r.value}</span>
                {x.r.malware_family && x.r.malware_family !== "unknown" && <Badge tone="violet">{x.r.malware_family}</Badge>}
                {x.r.campaign_name && <Badge tone="high">{x.r.campaign_name}</Badge>}
                <span className="faint xs" style={{ width: 90 }}>{x.r.source}</span>
                <span className="faint xs num" style={{ width: 60, textAlign: "right" }}>{timeAgo(x.ts)}</span>
              </div>
            ) : (
              <div key={k} className="list-row clickable" onClick={() => navigate(entityRoute("cve", x.r.cve_id))}>
                <span className="badge type"><span className="sev-dot" style={{ background: SEV_COLOR[normSev(x.r.severity, x.r.cvss_score)], width: 6, height: 6 }} />CVE</span>
                <span className="mono" style={{ width: 140 }}>{x.r.cve_id}</span>
                <span className="trunc muted" style={{ flex: 1 }}>{x.r.asset_name}</span>
                {x.r.kev_listed && <Badge tone="critical">KEV</Badge>}
                <SevBadge severity={x.r.severity} score={x.r.cvss_score} />
                <span className="faint xs num" style={{ width: 60, textAlign: "right" }}>{timeAgo(x.ts)}</span>
              </div>
            ));
          })()}
        </Panel>

        <div className="stack">
          <Panel title="Open Investigations" tight actions={<Link to="/workspace" className="link small">Workspace</Link>}>
            {!data ? <div style={{ padding: 16 }}><Skeleton h={60} /></div>
              : data.investigations.length === 0
                ? <EmptyState icon="briefcase" title="No open investigations" action={<Button size="sm" onClick={() => navigate("/workspace", { new: "1" })}>Create investigation</Button>} />
                : data.investigations.map(inv => (
                  <div key={inv.id} className="list-row clickable" onClick={() => navigate(`/investigations/${enc(inv.id)}`)}>
                    <span className="sev-dot" style={{ background: SEV_COLOR[inv.severity] || T.text3 }} />
                    <span className="mono faint xs">{inv.key}</span>
                    <span className="trunc" style={{ flex: 1, color: "var(--text)" }}>{inv.name}</span>
                    <span className="faint xs">{timeAgo(inv.updated_at)}</span>
                  </div>
                ))}
          </Panel>
          <Panel title="System & Connector Health" tight actions={<Link to="/platform/health" className="link small">Details</Link>}>
            {!data ? <div style={{ padding: 16 }}><Skeleton h={80} /></div> : <HealthList h={data.health} />}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function HealthList({ h }) {
  const rows = [];
  const poll = h.last_cve_poll;
  if (poll) {
    const ageH = (Date.now() - new Date(poll.polled_at + (String(poll.polled_at).endsWith("Z") ? "" : "Z")).getTime()) / 36e5;
    rows.push({ name: "NVD CVE poll", ok: !poll.error && ageH < 8, detail: poll.error ? poll.error : `${timeAgo(poll.polled_at)} · ${poll.new_cves} new`, to: "/cve" });
  } else rows.push({ name: "NVD CVE poll", ok: false, detail: "No poll has run yet", to: "/cve" });
  h.connectors.forEach(cn => rows.push({ name: cn.name, ok: cn.ok, detail: cn.ok ? `${timeAgo(cn.ran_at)} · +${cn.added}` : (cn.error || "failed"), to: "/platform/connectors" }));
  if (h.backup) rows.push({ name: "Database backup", ok: !!h.backup.ok, detail: timeAgo(h.backup.at), to: "/platform/health" });
  if (!h.connectors.length) rows.push({ name: "Feed connectors", ok: null, detail: "Not configured", to: "/platform/connectors" });
  return rows.map(r => (
    <div key={r.name} className="list-row clickable" onClick={() => navigate(r.to)}>
      <Icon name={r.ok === null ? "info" : r.ok ? "check" : "alert"} size={14} style={{ color: r.ok === null ? "var(--text-4)" : r.ok ? "var(--success)" : "var(--critical)" }} />
      <span style={{ flex: 1, color: "var(--text-2)", textTransform: r.name.length < 16 ? "capitalize" : "none" }}>{r.name}</span>
      <span className="faint xs trunc" style={{ maxWidth: 180 }} title={r.detail}>{r.detail}</span>
    </div>
  ));
}
