import React, { useCallback, useEffect, useState } from "react";
import { apiJSON } from "../lib/api";
import { navigate } from "../lib/router";
import Icon from "../components/Icon";
import { Badge, Button, CopyButton, Disclosure, ErrorState, PageHeader, Panel, Skeleton } from "../components/ui";

const LABEL = { virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", urlhaus: "abuse.ch", shodan: "Shodan", groq: "Groq", nvd: "NVD", otx: "AlienVault OTX", ipqs: "IPQualityScore", mxtoolbox: "MxToolbox" };

function Meter({ pct }) {
  const p = Math.max(0, Math.min(100, Number(pct) || 0));
  const color = p > 90 ? "var(--critical)" : p > 75 ? "var(--high)" : "var(--success)";
  return <div className="meter"><i style={{ width: `${p}%`, background: color }} /></div>;
}

function Check({ title, icon, c }) {
  if (!c) return null;
  const ok = c.ok !== false;
  return (
    <div className={`health-card ${ok ? "" : "bad"}`}>
      <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
        <div className="health-ico" style={{ color: ok ? "var(--success)" : "var(--critical)" }}><Icon name={icon} size={16} /></div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="row between"><span className="strong">{title}</span><span className={`status-dot ${ok ? "ok" : "bad"}`} role="img" aria-label={ok ? "OK" : "Problem"} /></div>
          <div className="small" style={{ color: ok ? "var(--text-3)" : "#FFA3AC", marginTop: 2 }}>{c.status || ""}</div>
        </div>
      </div>
      {c.iocs !== undefined && (
        <div className="row wrap small muted" style={{ gap: 14, marginTop: 10 }}>
          {[["IOCs", c.iocs], ["CVE findings", c.cve_findings], ["Assets", c.assets], ["Users", c.active_users]].map(([l, v]) => v !== undefined && <span key={l}><b style={{ color: "var(--text)" }}>{v}</b> {l}</span>)}
        </div>
      )}
      {c.used_pct !== undefined && <Meter pct={c.used_pct} />}
      {c.age_hours !== undefined && <div className="small muted" style={{ marginTop: 10 }}>Polled {c.assets_polled} assets · {c.new_cves} new CVEs · {c.patches_detected} patches</div>}
    </div>
  );
}

export default function HealthPage() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [at, setAt] = useState(null);
  const run = useCallback(async () => {
    setBusy(true); setErr(null);
    try { setData(await apiJSON("/admin/health")); setAt(new Date()); } catch (e) { setErr(e); }
    setBusy(false);
  }, []);
  useEffect(() => { run(); }, [run]);

  const ok = data?.overall === "ok";
  const k = data?.checks || {};
  const pending = k.access_requests?.pending || 0;
  return (
    <div className="page">
      <PageHeader title="Health" sub="Database, schedulers, feeds, backups, notification delivery and upstream API reachability."
        actions={<>
          {at && <span className="xs faint">Checked {at.toLocaleTimeString()}</span>}
          <Button icon="refresh" loading={busy} onClick={run}>Re-check</Button>
        </>} />
      {err && <ErrorState error={err} onRetry={run} />}
      {!data && !err && <div className="grid g2"><Skeleton h={120} /><Skeleton h={120} /></div>}
      {data && (
        <div className="stack" style={{ gap: 20 }}>
          <div className={`health-hero ${ok ? "ok" : "bad"}`}>
            <div className="health-hero-ico"><Icon name={ok ? "check" : "alert"} size={22} /></div>
            <div>
              <div className="strong" style={{ fontSize: 18 }}>{ok ? "All systems are healthy" : "Something needs attention"}</div>
              <div className="small muted" style={{ marginTop: 2 }}>{ok ? "Every check below passed." : "Review the cards marked in red below."}</div>
            </div>
          </div>

          <div className="grid g3">
            <Check title="Database" icon="server" c={k.database} />
            <Check title="CVE poll" icon="shieldAlert" c={k.cve_poll} />
            <Check title="Disk" icon="folder" c={k.disk} />
            <Check title="Memory" icon="activity" c={k.memory} />
            <Check title="Notifications" icon="bell" c={k.notifications} />
            <Check title="Backups" icon="download" c={k.backups} />
          </div>

          <div className="grid g3">
            <Panel title="API keys" sub={k.api_keys?.status} actions={<Button size="xs" variant="ghost" onClick={() => navigate("/platform/settings", { tab: "keys" })}>Manage</Button>}>
              {Object.entries(k.api_keys?.services || {}).map(([svc, info]) => (
                <div key={svc} className="list-row" style={{ padding: 0, minHeight: 38 }}><span style={{ flex: 1 }}>{LABEL[svc] || svc}</span>
                  <Badge tone={info.configured ? "success" : "low"} outline={!info.configured}>{info.configured ? info.source : "not configured"}</Badge></div>
              ))}
            </Panel>
            <Panel title="External connectivity">
              {Object.entries(k.connectivity || {}).map(([name, c]) => (
                <div key={name} className="list-row" style={{ padding: 0, minHeight: 38 }}><span style={{ flex: 1 }}>{name}</span>
                  <Badge tone={c.ok ? "success" : "critical"} dot>{c.status}</Badge></div>
              ))}
            </Panel>
            <Panel title="Access requests" actions={pending > 0 && <Button size="xs" variant="primary" onClick={() => navigate("/platform/settings", { tab: "access" })}>Review</Button>}>
              <div className="row" style={{ gap: 10 }}>{pending > 0 ? <Badge tone="high" dot>{pending} pending</Badge> : <Badge tone="success" dot>None waiting</Badge>}</div>
              <div className="small muted" style={{ marginTop: 10 }}>{k.access_requests?.status}</div>
            </Panel>
          </div>

          <Panel>
            <Disclosure title="Deeper server check" hint="systemd, nginx, certificate expiry, disk and memory" defaultOpen={false}>
              <div className="small muted" style={{ marginBottom: 10 }}>Run this on the server itself:</div>
              <div className="row" style={{ gap: 8 }}><pre className="code" style={{ flex: 1 }}>bash /home/ubuntu/threatfeed-repo/scripts/health_check.sh</pre><CopyButton value="bash /home/ubuntu/threatfeed-repo/scripts/health_check.sh" /></div>
            </Disclosure>
          </Panel>
        </div>
      )}
    </div>
  );
}
