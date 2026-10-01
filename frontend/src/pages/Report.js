import React, { useCallback, useEffect, useMemo, useState } from "react";
import { apiJSON } from "../lib/api";
import { copy } from "../lib/format";
import { navigate, enc } from "../lib/router";
import { readReportItems, reportToMarkdown, VERDICT_TONE, VERDICT_LABEL } from "../lib/report";
import { safeUrl } from "../lib/safe";
import { Badge, Button, Callout, CopyButton, EmptyState, ErrorState, PageHeader, Panel, SkeletonRows, Tabs, TypeBadge, useToast } from "../components/ui";
import Icon from "../components/Icon";

// One display section from the server: key/value list, table, tag cloud or text block. All values are text.
export function Section({ s }) {
  if (s.type === "kv") {
    return (
      <Panel title={s.title}>
        <dl className="kv" style={{ gridTemplateColumns: "minmax(120px, 190px) minmax(0, 1fr)" }}>
          {s.rows.map(([k, v], i) => <React.Fragment key={i}><dt>{k}</dt><dd className="mono-soft" style={{ overflowWrap: "anywhere" }}>{v}</dd></React.Fragment>)}
        </dl>
      </Panel>
    );
  }
  if (s.type === "table") {
    return (
      <Panel title={s.title} tight>
        <div className="tbl-wrap" style={{ maxHeight: 360 }}>
          <table className="tbl compact">
            <thead><tr>{s.cols.map(c => <th key={c}>{c}</th>)}</tr></thead>
            <tbody>{s.rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j} className="wrapcell" style={{ maxWidth: 420, overflowWrap: "anywhere" }}>{c}</td>)}</tr>)}</tbody>
          </table>
        </div>
      </Panel>
    );
  }
  if (s.type === "tags") {
    return <Panel title={s.title}><div className="row wrap" style={{ gap: 6 }}>{s.items.map(t => <span key={t} className="tag" style={{ maxWidth: 260 }}>{t}</span>)}</div></Panel>;
  }
  return <Panel title={s.title}><pre className="code" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 260 }}>{s.text}</pre></Panel>;
}

const STATUS_NOTE = { skipped: "Not scanned: no API key available", error: "Not scanned: the provider returned an error" };

function ProviderCard({ p, onOpen }) {
  const ok = p.status === "ok", nf = p.status === "not_found";
  const tone = ok ? "success" : nf ? "low" : "high";
  return (
    <div className={`prov-card ${ok || nf ? "clickable" : ""}`} onClick={ok || nf ? onOpen : undefined} role={ok || nf ? "button" : undefined} tabIndex={ok || nf ? 0 : undefined}
      onKeyDown={e => { if ((ok || nf) && e.key === "Enter") onOpen(); }}>
      <div className="row between"><span className="strong">{p.name}</span><Badge tone={tone} outline={!ok}>{ok ? "Scanned" : nf ? "No record" : p.status === "skipped" ? "Skipped" : "Error"}</Badge></div>
      <div className="prov-headline">{p.headline || (ok || nf ? p.message || "Checked" : p.message || STATUS_NOTE[p.status])}</div>
      {(ok || nf) && <div className="xs faint">{p.sections.length ? `${p.sections.length} detail section${p.sections.length === 1 ? "" : "s"}` : "Summary only"}</div>}
      {!ok && !nf && <div className="xs faint">{STATUS_NOTE[p.status]}</div>}
    </div>
  );
}

function ItemDetail({ item, onRefresh, refreshing }) {
  const scanned = item.providers.filter(p => p.status === "ok" || p.status === "not_found");
  const tabs = [{ id: "summary", label: "Summary" }, ...scanned.map(p => ({ id: p.id, label: p.name, count: p.sections.length || undefined })), item.tfii.length ? { id: "tfii", label: "TFII analysis", count: item.tfii.length } : null];
  const [tab, setTab] = useState("summary");
  useEffect(() => { setTab("summary"); }, [item.value]);
  const cur = scanned.find(p => p.id === tab);
  const tone = VERDICT_TONE[item.verdict] || "low";
  return (
    <div className="stack" style={{ gap: 18 }}>
      <div className="report-head">
        <div style={{ minWidth: 0 }}>
          <div className="row wrap" style={{ gap: 8, marginBottom: 8 }}>
            <Badge tone={tone} dot>{VERDICT_LABEL[item.verdict] || item.verdict}{item.score ? <span className="num" style={{ opacity: .75, fontWeight: 500 }}>{item.score}</span> : null}</Badge>
            <TypeBadge type={item.type} />
            {item.already_tracked && <Badge tone="accent" outline>Tracked</Badge>}
            <span className="xs faint">{item.cached ? "from your recent lookup" : "just checked"}</span>
          </div>
          <div className="entity-value" style={{ fontSize: 22 }}>{item.defanged || item.value}</div>
          {item.reason && <div className="small muted" style={{ marginTop: 8, maxWidth: 820 }}>{item.reason}</div>}
        </div>
        <div className="row wrap" style={{ gap: 8, alignItems: "flex-start" }}>
          <CopyButton value={item.defanged || item.value} />
          {item.already_tracked && item.existing_id && <Button size="sm" icon="external" onClick={() => navigate(`/ioc/${enc(item.existing_id)}`)}>Open indicator</Button>}
          {!item.already_tracked && ["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256", "Email"].includes(item.type) && <Button size="sm" icon="plus" onClick={() => navigate("/iocs/new", { value: item.value })}>Track as IOC</Button>}
        </div>
      </div>

      {!item.has_detail && (
        <Callout tone="warn">
          <div className="row between wrap" style={{ gap: 10 }}>
            <span>This came from a saved summary, so the providers' full answers weren't kept. Fetching them again uses your provider quota.</span>
            <Button size="sm" loading={refreshing} onClick={onRefresh}>Fetch full details</Button>
          </div>
        </Callout>
      )}

      <Tabs tabs={tabs} value={tab} onChange={setTab} />

      {tab === "summary" && (
        <div className="stack" style={{ gap: 16 }}>
          {item.providers.length === 0
            ? <Callout tone="info">No provider checks this kind of value, or none of your keys applies. TFII's own analysis is shown on the "TFII analysis" tab when there is any.</Callout>
            : <div className="prov-grid">{item.providers.map(p => <ProviderCard key={p.id} p={p} onOpen={() => setTab(p.id)} />)}</div>}
          {item.tfii.slice(0, 2).map((s, i) => <Section key={i} s={s} />)}
        </div>
      )}
      {cur && (
        <div className="stack" style={{ gap: 16 }}>
          <div className="row between wrap">
            <div><div className="strong" style={{ fontSize: 15 }}>{cur.name}</div><div className="small muted">{cur.headline || cur.message}</div></div>
            {safeUrl(cur.link) && <a className="btn sm" href={safeUrl(cur.link)} target="_blank" rel="noreferrer">Open on {cur.name} <Icon name="external" size={13} /></a>}
          </div>
          {cur.sections.length === 0 ? <EmptyState icon="info" title="No further detail" desc={cur.status === "not_found" ? "The provider has no record of this indicator." : "Only the summary was kept for this lookup."} />
            : <div className="report-sections">{cur.sections.map((s, i) => <Section key={i} s={s} />)}</div>}
        </div>
      )}
      {tab === "tfii" && <div className="report-sections">{item.tfii.map((s, i) => <Section key={i} s={s} />)}</div>}
    </div>
  );
}

function Overview({ items, onOpen }) {
  const cellFor = (it, id) => { const p = it.providers.find(x => x.id === id); return p ? (p.status === "ok" || p.status === "not_found" ? p.headline || "Checked" : "Not scanned") : "—"; };
  return (
    <Panel title="Side by side" sub={`${items.length} indicators`} tight>
      <div className="tbl-wrap">
        <table className="tbl">
          <thead><tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>VirusTotal</th><th className="opt-lg">AbuseIPDB</th><th className="opt-lg">URLhaus</th><th>Location</th></tr></thead>
          <tbody>
            {items.map(it => {
              const loc = it.tfii.find(s => s.title === "Location");
              const where = loc ? (loc.rows.find(r => ["Country", "CDN edge node"].includes(r[0])) || loc.rows[0] || [])[1] : "";
              return (
                <tr key={it.value} className="clickable" onClick={() => onOpen(it.value)} tabIndex={0} onKeyDown={e => e.key === "Enter" && onOpen(it.value)}>
                  <td className="cellmono" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }} title={it.value}>{it.defanged || it.value}</td>
                  <td><TypeBadge type={it.type} /></td>
                  <td><Badge tone={VERDICT_TONE[it.verdict] || "low"} dot>{VERDICT_LABEL[it.verdict] || it.verdict}</Badge></td>
                  <td>{cellFor(it, "virustotal")}</td><td className="opt-lg">{cellFor(it, "abuseipdb")}</td><td className="opt-lg">{cellFor(it, "urlhaus")}</td>
                  <td className="muted">{where || "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

export default function ReportPage({ query }) {
  const toast = useToast();
  const values = useMemo(() => readReportItems(query), [query.items, query.s]); // eslint-disable-line react-hooks/exhaustive-deps
  const [items, setItems] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [cur, setCur] = useState("__overview");

  const load = useCallback(async (refresh = false) => {
    if (!values.length) { setItems([]); return; }
    setBusy(true); setErr(null);
    try { const d = await apiJSON("/iocs/detail-report", { method: "POST", body: { items: values, refresh } }); setItems(d.items); }
    catch (e) { setErr(e); }
    setBusy(false);
  }, [values]);
  useEffect(() => { setItems(null); load(false); }, [load]);
  useEffect(() => { setCur(values.length > 1 ? "__overview" : values[0] || "__overview"); }, [values]);

  const one = items && items.length === 1;
  const sel = items && (one ? items[0] : items.find(i => i.value === cur));

  return (
    <div className="page">
      <PageHeader title="Detailed report" sub="Everything each provider said about the indicators you picked: detections, registration, DNS, reports and more."
        actions={items && items.length > 0 && <>
          <Button size="sm" icon="copy" onClick={() => { copy(reportToMarkdown(items)); toast("Report copied as Markdown", "ok"); }}>Copy as Markdown</Button>
          <Button size="sm" icon="download" onClick={() => {
            const blob = new Blob([JSON.stringify(items, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob); const a = document.createElement("a");
            a.href = url; a.download = `tfii-report-${new Date().toISOString().slice(0, 10)}.json`; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
          }}>JSON</Button>
          <Button size="sm" icon="refresh" loading={busy && !!items} onClick={() => load(true)}>Check again</Button>
        </>} />
      {err && <ErrorState error={err} onRetry={() => load(false)} />}
      {!err && items === null && <div className="panel"><SkeletonRows rows={6} cols={4} /></div>}
      {items && items.length === 0 && <EmptyState icon="layers" title="Nothing to show yet" desc="Run a bulk lookup, tick the indicators you care about and choose “Detailed report”, or press “Details” on any result."
        action={<Button variant="primary" onClick={() => navigate("/osint/bulk")}>Open bulk lookup</Button>} />}
      {items && items.length > 0 && (
        <div className={items.length > 1 ? "report-layout" : ""}>
          {items.length > 1 && (
            <nav className="report-rail" aria-label="Indicators in this report">
              <button className={`rail-item ${cur === "__overview" ? "on" : ""}`} onClick={() => setCur("__overview")}><Icon name="grid" size={14} /> Side by side</button>
              {items.map(it => (
                <button key={it.value} className={`rail-item ${cur === it.value ? "on" : ""}`} onClick={() => setCur(it.value)} title={it.value}>
                  <span className="sev-dot" style={{ background: `var(--${VERDICT_TONE[it.verdict] === "success" ? "success" : VERDICT_TONE[it.verdict] || "low"})` }} />
                  <span className="trunc mono" style={{ fontSize: 12 }}>{it.defanged || it.value}</span>
                </button>
              ))}
            </nav>
          )}
          <div style={{ minWidth: 0 }}>
            {!one && cur === "__overview" ? <Overview items={items} onOpen={setCur} />
              : sel && <ItemDetail item={sel} onRefresh={() => load(true)} refreshing={busy} />}
          </div>
        </div>
      )}
    </div>
  );
}
