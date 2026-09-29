import React, { useEffect, useMemo, useState } from "react";
import { useApi, apiJSON, qs, getToken } from "../lib/api";
import { navigate, setQuery, entityRoute, enc } from "../lib/router";
import { useSession, pushRecentEntity } from "../lib/session";
import { fmtNum } from "../lib/format";
import {
  PageHeader, Panel, Button, Badge, SevBadge, Tabs, KPI, SearchInput, Select, Pagination, Th, SkeletonRows,
  EmptyState, ErrorState, Loading, Callout, useDebounced, useToast, CopyButton, Segmented,
} from "../components/ui";
import { SevStack, YearBars, BarList } from "../components/charts";
import { SEV_COLOR, T, LEGACY_C } from "../design/tokens";
import { safeUrl } from "../lib/safe";
import { AssetManager, CVEDetail, CVELookup, CVEReportModal } from "../legacy/lazy";

const STATUS = {
  kev_exposed: { label: "KEV exposure", tone: "critical" },
  critical_exposed: { label: "Critical exposure", tone: "critical" },
  exposed: { label: "Exposed", tone: "high" },
  covered: { label: "Patched", tone: "success" },
  clean: { label: "No CVEs", tone: "low" },
};

function EpssCell({ v }) {
  if (v === null || v === undefined) return <span className="faint">—</span>;
  const p = v * 100;
  return <span className="num" style={{ color: p >= 50 ? "var(--critical)" : p >= 10 ? "var(--high)" : "var(--text-3)" }}>{p.toFixed(p < 1 ? 2 : 1)}%</span>;
}
function PatchCell({ available, url }) {
  return available
    ? <span className="row" style={{ gap: 4 }}><Badge tone="success" dot>Patched</Badge>{safeUrl(url) && <a href={safeUrl(url)} target="_blank" rel="noreferrer" className="link xs" onClick={e => e.stopPropagation()}>fix ↗</a>}</span>
    : <Badge tone="high" outline>No patch</Badge>;
}

export function CveIntel({ query }) {
  const { can } = useSession();
  const hasData = can("data.workspace");
  const tab = query.tab || (hasData ? "software" : "lookup");
  const summary = useApi(hasData ? "/v2/cve/summary" : null);
  const c = summary.data;
  const ex = useMemo(() => (c ? { critical: c.critical, high: c.high, medium: c.medium } : {}), [c]);
  const [polling, setPolling] = useState(false);
  const [pollMsg, setPollMsg] = useState("");
  const toast = useToast();

  // Polling NVD paces itself against its rate limit, so it runs in the background:
  // start it, then watch its status until it reports a result.
  async function poll() {
    setPolling(true); setPollMsg("Starting…");
    try {
      await apiJSON("/cves/poll-now", { method: "POST" });
      const t0 = Date.now();
      let st;
      do {
        await new Promise(r => setTimeout(r, 2500));
        st = await apiJSON("/cves/poll-status");
        setPollMsg(st.progress ? `Polling ${st.progress}` : "Finishing…");
      } while (st.running && Date.now() - t0 < 15 * 60 * 1000);
      const r = st.result;
      if (!r) toast("The poll is still running — check back shortly.", "info");
      else {
        toast(r.message || `Poll complete — ${r.new_cves} new CVEs, ${r.patches_detected} patches detected across ${r.assets_polled} software`, (r.errors || []).length ? "warn" : "ok");
        (r.errors || []).slice(0, 3).forEach(e => toast(e, "error"));
      }
      summary.reload(true);
    } catch (e) { toast(e.message, "error"); }
    setPolling(false); setPollMsg("");
  }

  return (
    <div className="page">
      <PageHeader title="CVE Intelligence" sub="Vulnerability exposure across the software you monitor — NVD, CISA KEV and EPSS, polled every 6 hours."
        actions={hasData && <>
          {can("admin.panel") && <Button size="sm" icon="refresh" onClick={poll} loading={polling}>{polling ? (pollMsg || "Polling…") : "Poll NVD now"}</Button>}
          <Button size="sm" variant="primary" icon="plus" onClick={() => setQuery({ tab: "manage" })}>Add software</Button>
        </>} />
      {hasData && (
        <div className="kpis" style={{ marginBottom: 14 }}>
          <KPI label="Total CVEs" value={c?.total} onClick={() => setQuery({ tab: "cves", severity: "", kev: "", patched: "" })} />
          <KPI label="Unpatched" value={c?.unpatched} tone={T.high} onClick={() => setQuery({ tab: "cves", patched: "no" })} />
          <KPI label="Patched" value={c?.patched} tone={T.success} onClick={() => setQuery({ tab: "cves", patched: "yes" })} />
          <KPI label="CISA KEV" value={c?.kev} tone={T.critical} sub={c ? `${fmtNum(c.kev_unpatched)} unpatched` : ""} onClick={() => setQuery({ tab: "cves", kev: "1" })} />
          <KPI label="Critical" value={ex.critical ?? (c ? 0 : undefined)} tone={SEV_COLOR.critical} onClick={() => setQuery({ tab: "cves", severity: "critical" })} />
          <KPI label="High" value={ex.high ?? (c ? 0 : undefined)} tone={SEV_COLOR.high} onClick={() => setQuery({ tab: "cves", severity: "high" })} />
          <KPI label="Medium" value={ex.medium ?? (c ? 0 : undefined)} tone={SEV_COLOR.medium} onClick={() => setQuery({ tab: "cves", severity: "medium" })} />
        </div>
      )}
      <Tabs value={tab} onChange={t => setQuery({ tab: t })} tabs={[
        hasData && { id: "software", label: "Software View", icon: "package" },
        hasData && { id: "cves", label: "CVE View", icon: "list" },
        { id: "lookup", label: "Multi-source Lookup", icon: "search" },
        hasData && { id: "manage", label: "Manage Software", icon: "settings" },
      ]} />
      {tab === "software" && hasData && <SoftwareView year={query.year || ""} />}
      {tab === "cves" && hasData && <CveView query={query} />}
      {tab === "lookup" && <div className="legacy-host"><CVELookup token={getToken()} C={LEGACY_C} initialId={query.id || ""} /></div>}
      {tab === "manage" && hasData && <div className="legacy-host"><AssetManager token={getToken()} C={LEGACY_C} onChanged={() => summary.reload(true)} /></div>}
    </div>
  );
}

function SoftwareView({ year }) {
  const { data, error, loading, reload } = useApi(`/v2/software${qs({ year })}`);
  const [q, setQ] = useState("");
  const [sort, setSort] = useState("risk");
  const [dir, setDir] = useState("desc");
  const rows = useMemo(() => {
    const rank = { kev_exposed: 5, critical_exposed: 4, exposed: 3, covered: 2, clean: 1 };
    let r = (data?.software || []).filter(s => !q || `${s.name} ${s.vendor}`.toLowerCase().includes(q.toLowerCase()));
    const key = sort === "risk" ? s => rank[s.status] * 1e6 + Number(s.kev) * 1e3 + Number(s.critical) : s => (sort === "name" ? s.name.toLowerCase() : Number(s[sort]) || 0);
    r = [...r].sort((a, b) => { const x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : 0) * (dir === "asc" ? 1 : -1); });
    return r;
  }, [data, q, sort, dir]);
  const onSort = id => { if (sort === id) setDir(d => (d === "asc" ? "desc" : "asc")); else { setSort(id); setDir(id === "name" ? "asc" : "desc"); } };
  const thisYear = new Date().getFullYear();

  if (error) return <ErrorState error={error} onRetry={reload} />;
  return (
    <>
      <div className="row wrap" style={{ gap: 8, marginBottom: 10 }}>
        <SearchInput value={q} onChange={setQ} placeholder="Filter software or vendor" style={{ width: 300 }} />
        <Segmented value={String(year || "")} onChange={v => setQuery({ year: v })} options={[["", "All time"], [String(thisYear), String(thisYear)], [String(thisYear - 1), String(thisYear - 1)], [String(thisYear - 2), String(thisYear - 2)]]} />
      </div>
      <Panel tight bodyStyle={{ padding: 0 }} footer={data && <span>{rows.length} software monitored · click a row for software intelligence</span>}>
        <div className="tbl-wrap">
          <table className="tbl tall">
            <thead><tr>
              <Th id="name" label="Software" sort={sort} dir={dir} onSort={onSort} />
              <Th id="total" label="CVEs" sort={sort} dir={dir} onSort={onSort} className="r" />
              <Th id="critical" label="Critical" sort={sort} dir={dir} onSort={onSort} className="r" />
              <Th id="high" label="High" sort={sort} dir={dir} onSort={onSort} className="r" />
              <Th id="medium" label="Medium" sort={sort} dir={dir} onSort={onSort} className="r" />
              <Th id="low" label="Low" sort={sort} dir={dir} onSort={onSort} className="r" />
              <Th id="kev" label="KEV" sort={sort} dir={dir} onSort={onSort} className="r" />
              <Th id="unpatched" label="Unpatched" sort={sort} dir={dir} onSort={onSort} className="r" />
              <th style={{ width: 160 }}>Severity mix</th>
              <Th id="risk" label="Status" sort={sort} dir={dir} onSort={onSort} />
            </tr></thead>
            <tbody>
              {loading && !data && <tr><td colSpan={10} style={{ padding: 0 }}><SkeletonRows rows={8} cols={8} /></td></tr>}
              {data && rows.length === 0 && <tr><td colSpan={10}><EmptyState icon="package" title="No software monitored" desc="Add software to the registry and TFII polls NVD for its CVEs every 6 hours." action={<Button size="sm" variant="primary" onClick={() => setQuery({ tab: "manage" })}>Add software</Button>} /></td></tr>}
              {rows.map(s => (
                <tr key={s.id} className="clickable" onClick={() => navigate(entityRoute("software", s.id))}>
                  <td className="primary">
                    <div className="strong" style={{ fontWeight: 500 }}>{s.name}</div>
                    <div className="faint xs">{[s.vendor, s.version && `v${s.version}`, s.asset_type].filter(Boolean).join(" · ")}</div>
                  </td>
                  <td className="r num strong">{fmtNum(s.total)}</td>
                  <td className="r num" style={{ color: s.critical ? SEV_COLOR.critical : "var(--text-4)" }}>{fmtNum(s.critical)}</td>
                  <td className="r num" style={{ color: s.high ? SEV_COLOR.high : "var(--text-4)" }}>{fmtNum(s.high)}</td>
                  <td className="r num" style={{ color: s.medium ? "#6EA8FF" : "var(--text-4)" }}>{fmtNum(s.medium)}</td>
                  <td className="r num faint">{fmtNum(s.low)}</td>
                  <td className="r num" style={{ color: s.kev ? SEV_COLOR.critical : "var(--text-4)", fontWeight: s.kev ? 600 : 400 }}>{fmtNum(s.kev)}</td>
                  <td className="r num">{fmtNum(s.unpatched)}</td>
                  <td><SevStack counts={s} /></td>
                  <td><Badge tone={STATUS[s.status].tone} dot>{STATUS[s.status].label}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </>
  );
}

function CveView({ query }) {
  const [text, setText] = useState(query.q || "");
  const dtext = useDebounced(text, 300);
  useEffect(() => { if (dtext !== (query.q || "")) setQuery({ q: dtext, offset: "" }); }, [dtext]); // eslint-disable-line react-hooks/exhaustive-deps
  const assets = useApi("/assets");
  const params = {
    q: query.q || "", severity: query.severity || "", kev_only: query.kev === "1", unpatched_only: query.patched === "no",
    asset_id: query.asset_id || "", year: query.year || "", limit: Number(query.limit || 50), offset: Number(query.offset || 0),
  };
  const { data, error, loading, reload } = useApi(`/cves/search${qs(params)}`);
  const [detail, setDetail] = useState(null);
  const set = patch => setQuery({ ...patch, offset: "" });
  let rows = data?.cves || [];
  if (query.patched === "yes") rows = rows.filter(r => r.patch_available);

  return (
    <>
      <div className="row wrap" style={{ gap: 8, marginBottom: 10 }}>
        <SearchInput value={text} onChange={setText} placeholder="Search CVE ID, title or description" style={{ width: 320 }} />
        <Select value={query.severity || ""} onChange={v => set({ severity: v })} options={[["", "Any severity"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]} />
        <Select value={query.patched || ""} onChange={v => set({ patched: v })} options={[["", "Patched or not"], ["no", "Unpatched"], ["yes", "Patched (this page)"]]} />
        <Select value={query.asset_id || ""} onChange={v => set({ asset_id: v })} options={[["", "All software"], ...((assets.data || []).map(a => [a.id, a.name]))]} />
        <Select value={query.year || ""} onChange={v => set({ year: v })} options={[["", "Any year"], ...Array.from({ length: 8 }).map((_, i) => { const y = String(new Date().getFullYear() - i); return [y, y]; })]} />
        <label className="check"><input type="checkbox" checked={query.kev === "1"} onChange={e => set({ kev: e.target.checked ? "1" : "" })} />CISA KEV only</label>
      </div>
      <Panel tight bodyStyle={{ padding: 0 }}
        footer={data && <><span>Sorted by KEV, then CVSS</span><Pagination total={data.total} limit={params.limit} offset={params.offset} onChange={o => setQuery({ offset: o || "" })} onLimit={l => set({ limit: l })} /></>}>
        {error ? <ErrorState error={error} onRetry={reload} /> : (
          <div className="tbl-wrap" style={{ maxHeight: "calc(100vh - 360px)", minHeight: 300 }}>
            <table className="tbl">
              <thead><tr><th>CVE</th><th>Severity</th><th>EPSS</th><th>Vulnerability</th><th>Software</th><th>Published</th><th>Patch</th></tr></thead>
              <tbody>
                {loading && !data && <tr><td colSpan={7} style={{ padding: 0 }}><SkeletonRows rows={10} cols={6} /></td></tr>}
                {data && rows.length === 0 && <tr><td colSpan={7}><EmptyState icon="shieldAlert" title="No CVEs match" desc="Adjust the filters, or run a poll to fetch the latest CVEs from NVD." /></td></tr>}
                {rows.map(cv => (
                  <tr key={cv.id} className="clickable" onClick={() => navigate(entityRoute("cve", cv.cve_id))}>
                    <td className="primary">
                      <div className="row" style={{ gap: 6 }}><span className="cellmono">{cv.cve_id}</span>{cv.kev_listed && <Badge tone="critical">KEV</Badge>}</div>
                    </td>
                    <td><SevBadge severity={cv.cvss_severity} score={cv.cvss_score} /></td>
                    <td><EpssCell v={cv.epss_score} /></td>
                    <td className="trunc" style={{ maxWidth: 420 }} title={cv.description}>{(cv.title || cv.description || "").replace(/^CVE-\d+-\d+:\s*/, "")}</td>
                    <td className="muted trunc" style={{ maxWidth: 160 }}>{cv.asset_name}</td>
                    <td className="muted num">{cv.published_date || "—"}</td>
                    <td onClick={e => { e.stopPropagation(); setDetail(cv); }}><PatchCell available={cv.patch_available} url={cv.patch_url} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {detail && <CVEDetail cve={detail} token={getToken()} C={LEGACY_C} onClose={() => setDetail(null)} />}
    </>
  );
}

// ── Software Intelligence (rendered inside the shared entity page) ──────────
export function SoftwareActions({ hd }) {
  return <Button size="sm" icon="list" onClick={() => navigate("/cve", { tab: "cves", asset_id: hd.ref })}>All CVEs in CVE View</Button>;
}

export function SoftwareOverview({ kd, hd, setTab }) {
  const { data, error, loading, reload } = kd;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading || !data) return <Loading label="Loading software intelligence" />;
  const s = data.software;
  const years = (() => {
    const m = {};
    data.by_year.forEach(r => { if (!r.year) return; m[r.year] = m[r.year] || { label: r.year }; m[r.year][String(r.severity).toLowerCase()] = Number(r.n); });
    return Object.values(m).sort((a, b) => a.label.localeCompare(b.label)).slice(-10);
  })();
  return (
    <>
      <div className="facts">
        <div className="fact"><div className="fact-l">Status</div><div className="fact-v"><Badge tone={STATUS[s.status].tone} dot>{STATUS[s.status].label}</Badge></div></div>
        {["critical", "high", "medium", "low"].map(k => <div key={k} className="fact"><div className="fact-l" style={{ textTransform: "capitalize" }}><span className="sev-dot" style={{ background: SEV_COLOR[k], marginRight: 5 }} />{k}</div><div className="fact-v num" style={{ fontSize: 18 }}>{fmtNum(s[k])}</div></div>)}
        <div className="fact"><div className="fact-l">Peak EPSS</div><div className="fact-v"><EpssCell v={s.max_epss} /></div></div>
      </div>
      <div className="grid g-main-side">
        <div className="stack">
          <Panel title="Severity distribution"><SevStack counts={s} height={10} showLegend /></Panel>
          <Panel title="CVEs by publication year" sub="stacked by severity">{years.length ? <YearBars rows={years} /> : <div className="faint small">No dated CVEs.</div>}</Panel>
          <Panel title="Recent CVEs" tight actions={<Button size="xs" variant="ghost" onClick={() => setTab("vulns")}>All vulnerabilities</Button>}>
            <CveRows rows={data.recent} />
          </Panel>
        </div>
        <div className="stack">
          <Panel title="Highest exploitation probability" sub="EPSS" tight><CveRows rows={data.top_epss} compact showEpss /></Panel>
          {data.cwes.length > 0 && <Panel title="Weakness types" sub="CWE"><BarList items={data.cwes.map(w => ({ label: w.cwe, value: Number(w.n) }))} color={T.medium} empty="No CWE data" /></Panel>}
          {data.linked_iocs > 0 && <Panel title="Linked indicators"><div className="small">{data.linked_iocs} IOCs were extracted from this software's CVE descriptions.</div></Panel>}
        </div>
      </div>
    </>
  );
}

// Software-specific tabs the shared page appends after its own. Only tabs with
// content are returned, matching the shared page's "no empty sections" rule.
export function softwareTabs(data, hd) {
  if (!data) return [];
  const s = data.software;
  const out = [];
  if (s.total > 0) out.push({ id: "vulns", label: "Vulnerabilities", count: s.total, render: () => <SoftwareVulns assetId={s.id} /> });
  if (data.kev.length > 0) out.push({ id: "kev", label: "KEV", count: data.kev.length, render: () => (
    <Panel title="Known exploited vulnerabilities" sub="CISA KEV catalog" tight><CveRows rows={data.kev} /></Panel>) });
  if (data.versions.length > 0) out.push({ id: "versions", label: "Affected Versions", count: data.versions.length, render: () => (
    <Panel title="Affected version ranges" sub="as published by NVD" tight>
      <table className="tbl compact"><thead><tr><th>Affected versions</th><th className="r">CVEs</th><th className="r">Critical / High</th><th className="r">Unpatched</th></tr></thead>
        <tbody>{data.versions.map((v, k) => (
          <tr key={k}><td className="cellmono wrapcell" style={{ overflowWrap: "anywhere" }}>{v.versions}</td><td className="r num">{v.n}</td><td className="r num">{v.severe}</td><td className="r num">{v.unpatched}</td></tr>
        ))}</tbody></table>
    </Panel>) });
  out.push({ id: "detection", label: "Detections", render: () => <SoftwareDetection s={s} kev={data.kev} /> });
  if (data.advisories.length + data.reference_domains.length > 0) out.push({ id: "refs", label: "References", count: data.advisories.length + data.reference_domains.length, render: () => (
    <div className="grid g2">
      <Panel title="Vendor advisories & patches" tight>
        {data.advisories.filter(safeUrl).map(u => <a key={u} className="list-row clickable" href={safeUrl(u)} target="_blank" rel="noreferrer"><span className="trunc link small">{u}</span></a>)}
      </Panel>
      <Panel title="Reference sources"><BarList items={data.reference_domains.map(d => ({ label: d.domain, value: d.n }))} empty="No references" /></Panel>
    </div>) });
  return out;
}

function SoftwareVulns({ assetId }) {
  const [offset, setOffset] = useState(0);
  const [sev, setSev] = useState("");
  const { data, error, loading, reload } = useApi(`/cves/search${qs({ asset_id: assetId, severity: sev, limit: 50, offset })}`);
  if (error) return <ErrorState error={error} onRetry={reload} />;
  return (
    <Panel tight bodyStyle={{ padding: 0 }} title={<Segmented value={sev} onChange={v => { setSev(v); setOffset(0); }} options={[["", "All"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]} />}
      footer={data && <><span /><Pagination total={data.total} limit={50} offset={offset} onChange={setOffset} /></>}>
      {loading && !data ? <SkeletonRows /> : <CveRows rows={data.cves} />}
    </Panel>
  );
}

function CveRows({ rows, compact, showEpss }) {
  if (!rows || !rows.length) return <div className="faint small" style={{ padding: 16 }}>None.</div>;
  return rows.map(cv => (
    <div key={cv.id || cv.cve_id} className="list-row clickable" onClick={() => navigate(entityRoute("cve", cv.cve_id))}>
      <span className="mono" style={{ width: 132, flexShrink: 0 }}>{cv.cve_id}</span>
      {!compact && <span className="trunc muted" style={{ flex: 1 }} title={cv.description}>{(cv.title || cv.description || "").replace(/^CVE-\d+-\d+:\s*/, "")}</span>}
      {compact && <span className="spacer" />}
      {cv.kev_listed && <Badge tone="critical">KEV</Badge>}
      {showEpss && <EpssCell v={cv.epss_score} />}
      <SevBadge severity={cv.severity || cv.cvss_severity} score={cv.cvss_score} />
      {!compact && <span className="faint xs num" style={{ width: 76, textAlign: "right" }}>{cv.published_date || ""}</span>}
    </div>
  ));
}

function SoftwareDetection({ s, kev }) {
  const name = (s.name || "").replace(/'/g, "");
  const kql = `// Hosts running ${s.name}${s.version ? ` (monitored version ${s.version})` : ""}
DeviceTvmSoftwareInventory
| where SoftwareName has '${name.toLowerCase().replace(/\s+/g, "_")}' or SoftwareName has '${name.toLowerCase()}'
| summarize Devices=dcount(DeviceId), Versions=make_set(SoftwareVersion) by SoftwareVendor, SoftwareName`;
  const kvq = kev.length ? `// Exposure to KEV-listed CVEs in ${s.name}
DeviceTvmSoftwareVulnerabilities
| where CveId in (${kev.slice(0, 50).map(k => `'${k.cve_id}'`).join(", ")})
| summarize Devices=dcount(DeviceId) by CveId, VulnerabilitySeverityLevel
| sort by Devices desc` : null;
  const spl = `index=* sourcetype IN ("*inventory*","*software*") ("${s.name}")
| stats dc(host) as hosts values(version) as versions by vendor, product`;
  return (
    <div className="stack">
      <Callout>Exposure-hunting queries for this software. Run them in Defender/Sentinel or Splunk to find which hosts are affected.</Callout>
      {[["Installed footprint — Defender TVM (KQL)", kql], kvq && ["KEV exposure — Defender TVM (KQL)", kvq], ["Installed footprint — Splunk (SPL)", spl]].filter(Boolean).map(([t, b]) => (
        <Panel key={t} title={t} actions={<CopyButton value={b} />}><pre className="code">{b}</pre></Panel>
      ))}
    </div>
  );
}

// ── CVE page for accounts without indicator-database access ─────────────────
// Full-access accounts use the shared entity page; explorers get the public,
// multi-source lookup only (the tracked-finding data is behind data.workspace).
export function CvePublicPage({ cveId }) {
  const [report, setReport] = useState(false);
  useEffect(() => { pushRecentEntity({ kind: "cve", ref: cveId, label: cveId }); }, [cveId]);
  return (
    <div className="page">
      <div className="entity-head">
        <div>
          <div className="row" style={{ gap: 6, marginBottom: 6 }}><Badge outline>Vulnerability</Badge></div>
          <div className="row" style={{ gap: 6 }}><div className="entity-value">{cveId}</div><CopyButton value={cveId} /></div>
        </div>
        <div className="page-actions">
          <Button size="sm" icon="fileText" onClick={() => setReport(true)}>Generate report</Button>
          <a className="btn sm" href={`https://nvd.nist.gov/vuln/detail/${enc(cveId)}`} target="_blank" rel="noreferrer">NVD ↗</a>
        </div>
      </div>
      <Panel title="Multi-source intelligence" sub="NVD · CVE.org · OSV · EPSS · CISA KEV · public PoCs">
        <div className="legacy-host"><CVELookup token={getToken()} C={LEGACY_C} initialId={cveId} key={cveId} /></div>
      </Panel>
      {report && <CVEReportModal cveId={cveId} token={getToken()} C={LEGACY_C} onClose={() => setReport(false)} />}
    </div>
  );
}
