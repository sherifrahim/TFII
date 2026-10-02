import React, { useEffect, useState } from "react";
import { useApi, apiJSON } from "../lib/api";
import { timeAgo, fmtNum } from "../lib/format";
import { safeUrl } from "../lib/safe";
import { PageHeader, Panel, Button, Badge, Select, Callout, ErrorState, SkeletonRows, useToast } from "../components/ui";

const GROUPS = [
  ["abuse.ch", "abuse.ch", "Curated by abuse.ch. Needs the free Auth-Key (URLHAUS_AUTH_KEY)."],
  ["direct", "Direct feeds", "Each entry stands alone: it becomes an indicator if its own reliability clears the confidence floor."],
  ["consensus", "Consensus lists", "Noisy, unordered blocklists. A new indicator is only created when several lists agree (or IPsum's own multi-list count is high); anything TFII already holds is corroborated and its expiry refreshed."],
];

function LastRun({ r }) {
  if (!r) return <span className="faint">never</span>;
  return (
    <span title={r.error || ""}>
      {r.ok ? <Badge tone="success" dot>OK</Badge> : <Badge tone="high" dot>Failed</Badge>}{" "}
      <span className="muted small">
        {r.ok ? <>+{fmtNum(r.added || 0)} new · {fmtNum(r.skipped || 0)} seen again</> : <span style={{ color: "var(--high)" }}>{String(r.error || "error").slice(0, 80)}</span>}
        {" · "}{timeAgo(r.ran_at)}
      </span>
    </span>
  );
}

export function ConnectorsPage() {
  const { data, error, loading, reload } = useApi("/admin/connectors/catalog");
  const toast = useToast();
  const [busy, setBusy] = useState(null);
  const running = (data?.feeds || []).some(f => f.running);

  // Poll only while something is running.
  useEffect(() => {
    if (!running) return undefined;
    const t = setInterval(() => reload(true), 3000);
    return () => clearInterval(t);
  }, [running, reload]);

  async function save(body, msg) {
    try { await apiJSON("/admin/connectors/config", { method: "POST", body }); if (msg) toast(msg, "ok"); reload(true); }
    catch (e) { toast(e.message, "error"); }
  }
  async function run(f) {
    setBusy(f.id);
    try {
      const r = await apiJSON(`/admin/connectors/feeds/${f.id}/run`, { method: "POST" });
      toast(r.status === "running" ? `${f.name} is already running` : `${f.name} started — results appear here when it finishes`, "ok");
      reload(true);
    } catch (e) { toast(e.message, "error"); }
    setBusy(null);
  }

  return (
    <div className="page">
      <PageHeader title="Connectors" sub="Indicator feeds, how much TFII trusts each, and when they last ran. Failures raise a System notification."
        actions={data && (<>
          <label className="row" style={{ gap: 8 }}>
            <span className="faint small">Auto-enrich per run</span>
            <Select value={String(data.enrich_per_run)} onChange={v => save({ enrich_per_run: Number(v) }, "Updated")}
              options={[["0", "off"], ["5", "5 newest"], ["8", "8 (default)"], ["15", "15"], ["30", "30"]]} />
          </label>
          <label className="row" style={{ gap: 8 }}>
            <span className="faint small">Confidence floor for new indicators</span>
            <Select value={String(data.min_confidence)} onChange={v => save({ min_confidence: Number(v) }, "Floor updated")}
              options={[["60", "60 — permissive"], ["70", "70 — default"], ["75", "75"], ["80", "80 — strict"], ["90", "90 — only near-certain"]]} />
          </label></>
        )} />
      <Callout style={{ marginBottom: 14 }}>
        Confidence is <strong>corroborated</strong>: each source has a reliability, and an indicator reported by several independent sources is scored higher than any one of them
        (1 − Π(1 − reliabilityᵢ), capped at 97). Every sighting is recorded under the indicator’s <em>Source History</em>, and sightings keep it from expiring while a feed still lists it.
      </Callout>
      {error && <ErrorState error={error} onRetry={reload} />}
      {loading && !data && <Panel><SkeletonRows rows={6} cols={5} /></Panel>}
      {data && GROUPS.map(([gid, title, desc]) => {
        const rows = data.feeds.filter(f => f.group === gid);
        if (!rows.length) return null;
        return (
          <Panel key={gid} title={title} sub={desc} tight style={{ marginBottom: 14 }}>
            <div className="tbl-wrap" tabIndex={0}>
              <table className="tbl">
                <thead><tr><th>Feed</th><th className="r">Reliability</th><th className="r">In TFII</th><th className="r">≥ 80 conf.</th><th>Last run</th><th>Auto-run</th><th style={{ width: 110 }}><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {rows.map(f => (
                    <tr key={f.id}>
                      <td className="primary" style={{ maxWidth: 380 }}>
                        <div className="row" style={{ gap: 6 }}>
                          {safeUrl(f.homepage) ? <a className="link strong" href={safeUrl(f.homepage)} target="_blank" rel="noreferrer">{f.name} ↗</a> : <span className="strong">{f.name}</span>}
                          {f.needs_key && (f.key_configured ? <Badge tone="success" outline>key set</Badge> : <Badge tone="high" outline>key needed</Badge>)}
                        </div>
                        <div className="faint xs">{f.kinds}</div>
                        <div className="faint xs wrapcell" style={{ whiteSpace: "normal", maxWidth: 380 }}>{f.about}</div>
                      </td>
                      <td className="r num">{f.reliability}%</td>
                      <td className="r num">{fmtNum(f.iocs)}</td>
                      <td className="r num">{fmtNum(f.high_confidence)}</td>
                      <td style={{ maxWidth: 260 }}><LastRun r={f.last_run} /></td>
                      <td>
                        <label className="check">
                          <input type="checkbox" checked={f.enabled} disabled={f.needs_key && !f.key_configured}
                            onChange={e => save({ feeds: { [f.id]: { enabled: e.target.checked } } }, `${f.name} ${e.target.checked ? "enabled" : "disabled"}`)} />
                          {f.enabled ? (f.interval_hours ? `every ${f.interval_hours}h` : "daily") : "off"}
                        </label>
                      </td>
                      <td><Button size="xs" icon="refresh" loading={f.running || busy === f.id} disabled={f.needs_key && !f.key_configured} onClick={() => run(f)}>Run now</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        );
      })}
    </div>
  );
}
