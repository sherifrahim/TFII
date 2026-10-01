import React, { useCallback, useEffect, useState } from "react";
import { apiJSON, getToken } from "../lib/api";
import { safeUrl } from "../lib/safe";
import { LEGACY_C } from "../design/tokens";
import Icon from "../components/Icon";
import { Badge, Button, Callout, Panel, Skeleton } from "../components/ui";
import { CVEReportModal } from "../legacy/lazy";

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const SEV_TONE = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };

function SourceCard({ src }) {
  const ok = src.status === "ok";
  return (
    <Panel title={src.source} actions={<Badge tone={ok ? "success" : src.status === "not_found" ? "low" : "critical"} outline={!ok} dot={ok}>{ok ? "Found" : src.status === "not_found" ? "Not listed" : "Error"}</Badge>}>
      {ok && src.source === "NVD" && (
        <div className="stack" style={{ gap: 8 }}>
          {src.cvss && <div><Badge tone={SEV_TONE[src.cvss.severity] || "low"} dot>CVSS {src.cvss.version} · {src.cvss.score} {src.cvss.severity}</Badge></div>}
          {src.weaknesses?.length > 0 && <div className="small muted">Weakness: <span className="mono-soft">{src.weaknesses.join(", ")}</span></div>}
          {src.published && <div className="small muted">Published {src.published}</div>}
          {src.affected_cpes?.length > 0 && <div><div className="eyebrow" style={{ marginBottom: 4 }}>Affected</div>{src.affected_cpes.slice(0, 4).map((c, i) => <div key={i} className="mono-soft xs" style={{ overflowWrap: "anywhere" }}>{c}</div>)}</div>}
        </div>
      )}
      {ok && src.source === "CVE.org" && (
        <div className="stack" style={{ gap: 8 }}>
          {src.state && <div className="small muted">State <b style={{ color: "var(--accent-hi)" }}>{src.state}</b></div>}
          {src.affected?.length > 0 && <div><div className="eyebrow" style={{ marginBottom: 4 }}>Affected</div>{src.affected.slice(0, 4).map((a, i) => <div key={i} className="small">{a}</div>)}</div>}
        </div>
      )}
      {ok && src.source === "OSV" && (
        <div className="stack" style={{ gap: 8 }}>
          <div className="small muted">{src.count} related advisor{src.count === 1 ? "y" : "ies"}</div>
          {src.vulns?.slice(0, 2).map((v, i) => (
            <div key={i} className="callout" style={{ display: "block" }}>
              <div className="mono strong" style={{ fontSize: 12 }}>{v.id}</div>
              {v.packages?.slice(0, 3).map((p, j) => <div key={j} className="xs muted">{p.ecosystem}: <span style={{ color: "var(--text)" }}>{p.name}</span>{p.fix && <span style={{ color: "var(--success)" }}> → fixed in {p.fix}</span>}</div>)}
            </div>
          ))}
        </div>
      )}
      {ok && src.source === "CVE Trends" && (
        <div><div className="strong" style={{ color: src.trending ? "var(--accent-hi)" : "var(--text-3)" }}>{src.trending ? "Trending right now" : "Not trending"}</div>
          {src.count_24h > 0 && <div className="small muted" style={{ marginTop: 4 }}>{src.count_24h} mentions in the last 24 hours</div>}</div>
      )}
      {src.status === "error" && <div className="small" style={{ color: "var(--critical)" }}>{src.error || "Could not be fetched"}</div>}
      {src.status === "not_found" && <div className="small faint">This CVE is not in the {src.source} database.</div>}
    </Panel>
  );
}

export default function CveLookup({ initialId = "" }) {
  const [id, setId] = useState(initialId);
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [report, setReport] = useState(false);
  const [allRefs, setAllRefs] = useState(false);

  const lookup = useCallback(async (value) => {
    const q = (value || "").trim().toUpperCase();
    if (!CVE_RE.test(q)) { setErr("Enter a CVE ID such as CVE-2024-12345."); return; }
    setBusy(true); setErr(""); setRes(null); setAllRefs(false);
    try { setRes(await apiJSON(`/cve/lookup?id=${encodeURIComponent(q)}`)); } catch (e) { setErr(e.message); }
    setBusy(false);
  }, []);
  useEffect(() => { if (initialId && CVE_RE.test(initialId)) lookup(initialId); }, [initialId, lookup]);

  const nvd = res?.sources?.find(s => s.source === "NVD");
  const refs = res?.all_refs || [];
  return (
    <div className="stack" style={{ gap: 18 }}>
      <div className="row" style={{ gap: 10 }}>
        <input className="input mono" style={{ flex: 1, height: 46, fontSize: 16, borderRadius: 12 }} value={id} onChange={e => setId(e.target.value)} onKeyDown={e => e.key === "Enter" && lookup(id)} placeholder="CVE-2024-12345" aria-label="CVE ID" autoFocus={!initialId} />
        <Button variant="primary" size="lg" icon="search" loading={busy} disabled={!id.trim()} onClick={() => lookup(id)}>Look up</Button>
      </div>
      {err && <Callout tone="error">{err}</Callout>}
      {busy && <div className="grid g3"><Skeleton h={120} /><Skeleton h={120} /><Skeleton h={120} /></div>}
      {res && (
        <div className="stack" style={{ gap: 16 }}>
          <Panel>
            <div className="row between wrap" style={{ gap: 14, alignItems: "flex-start" }}>
              <div style={{ minWidth: 0 }}>
                <div className="entity-value">{res.cve_id}</div>
                <div className="row wrap" style={{ gap: 8, marginTop: 10 }}>
                  {res.in_kev && <Badge tone="critical" dot>CISA KEV · added {res.kev_date}</Badge>}
                  {res.epss && <Badge tone={res.epss.epss >= 0.5 ? "critical" : res.epss.epss >= 0.1 ? "high" : "low"}>EPSS {(res.epss.epss * 100).toFixed(1)}% · {(res.epss.percentile * 100).toFixed(0)}th percentile</Badge>}
                  {nvd?.cvss && <Badge tone={SEV_TONE[nvd.cvss.severity] || "low"} dot>{nvd.cvss.severity} {nvd.cvss.score}</Badge>}
                </div>
              </div>
              <div className="row wrap" style={{ gap: 8 }}>
                {[["NVD", `https://nvd.nist.gov/vuln/detail/${res.cve_id}`], ["CVE.org", `https://www.cve.org/CVERecord?id=${res.cve_id}`], ["OSV", `https://osv.dev/vulnerability/${res.cve_id}`]].map(([n, u]) => (
                  <a key={n} className="btn sm" href={u} target="_blank" rel="noreferrer">{n} <Icon name="external" size={12} /></a>
                ))}
                <Button size="sm" variant="primary" icon="fileText" onClick={() => setReport(true)}>Generate report</Button>
              </div>
            </div>
            {nvd?.description && <div className="callout" style={{ marginTop: 16, lineHeight: 1.75 }}>{nvd.description}</div>}
            {report && <CVEReportModal cveId={res.cve_id} token={getToken()} C={LEGACY_C} onClose={() => setReport(false)} />}
          </Panel>

          <div className="grid g2">{res.sources.map(s => <SourceCard key={s.source} src={s} />)}</div>

          {refs.length > 0 && (
            <Panel title={`References (${refs.length})`} tight>
              {(allRefs ? refs : refs.slice(0, 8)).map((r, i) => (
                <div key={i} className="list-row" style={{ alignItems: "flex-start", padding: "9px 20px" }}>
                  <div style={{ flex: 1, minWidth: 0 }}>{safeUrl(r.url) ? <a className="link small" href={safeUrl(r.url)} target="_blank" rel="noreferrer" style={{ overflowWrap: "anywhere" }}>{r.url}</a> : <span className="small" style={{ overflowWrap: "anywhere" }}>{r.url}</span>}</div>
                  <div className="row" style={{ gap: 4, flexShrink: 0 }}>{r.source && <Badge tone="accent">{r.source}</Badge>}{r.tags?.slice(0, 2).map(t => <span key={t} className="tag">{t}</span>)}</div>
                </div>
              ))}
              {refs.length > 8 && <div style={{ padding: "10px 20px" }}><Button size="sm" variant="ghost" onClick={() => setAllRefs(v => !v)}>{allRefs ? "Show fewer" : `Show all ${refs.length}`}</Button></div>}
            </Panel>
          )}
        </div>
      )}
    </div>
  );
}
