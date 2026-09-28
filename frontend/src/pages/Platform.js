import React, { useState } from "react";
import { useApi, apiJSON, getToken } from "../lib/api";
import { navigate, enc } from "../lib/router";
import { useSession } from "../lib/session";
import { fmtNum, fmtDate } from "../lib/format";
import { PageHeader, Panel, Button, Badge, Field, Select, Tabs, EmptyState, ErrorState, Skeleton, Callout, CopyButton, useToast } from "../components/ui";
import { StackedBars, BarList } from "../components/charts";
import Icon from "../components/Icon";
import { LEGACY_C } from "../design/tokens";
import {
  HealthPage as LegacyHealth, ConnectorsPage as LegacyConnectors, SettingsPage as LegacySettings, FilesPage as LegacyFiles,
  QueryGenerator, GeoMap, AdvisoryBuilder, PermissionsPanel, CVEReportModal,
} from "../legacy/LegacyComponents";

function Legacy({ title, sub, actions, children, narrow }) {
  return (
    <div className={`page ${narrow ? "narrow" : ""}`}>
      <PageHeader title={title} sub={sub} actions={actions} />
      <div className="legacy-host">{children}</div>
    </div>
  );
}

export function HealthPage() {
  return <Legacy title="Health" sub="Database, schedulers, feeds, backups, notification delivery and upstream API reachability."><LegacyHealth token={getToken()} C={LEGACY_C} /></Legacy>;
}
export function ConnectorsPage() {
  return <Legacy title="Connectors" sub="abuse.ch ThreatFox, MalwareBazaar and URLhaus ingestion. Failures raise a System notification."><LegacyConnectors token={getToken()} C={LEGACY_C} /></Legacy>;
}
export function SettingsPage({ onOpenApiKeys }) {
  const { me, logout } = useSession();
  return <Legacy title="Settings" sub="Account, personal API keys, notifications and access requests." narrow><LegacySettings token={getToken()} onLogout={logout} C={LEGACY_C} me={me} onOpenApiKeys={onOpenApiKeys} /></Legacy>;
}
export function FilesPage() {
  return <Legacy title="Files" sub="Owner-only file store with share links. Downloads are always forced as attachments."><LegacyFiles token={getToken()} C={LEGACY_C} /></Legacy>;
}
export function QueryPage() {
  return <Legacy title="Query Builder" sub="Generate KQL / SPL detections for a use case, or paste a query to have it explained line by line."><QueryGenerator token={getToken()} C={LEGACY_C} /></Legacy>;
}
export function GeoPage() {
  return <Legacy title="Geo Intelligence" sub="Country of origin for IP indicators, from AbuseIPDB and VirusTotal enrichment."><GeoMap token={getToken()} C={LEGACY_C} /></Legacy>;
}
export function AdvisoriesPage() {
  return <Legacy title="Advisories" sub="Build a threat advisory from suggested CVEs and your IOC pool, ready to send."><AdvisoryBuilder token={getToken()} C={LEGACY_C} /></Legacy>;
}

export function ReportsPage() {
  const [cve, setCve] = useState("");
  const [open, setOpen] = useState(null);
  const { can } = useSession();
  const valid = /^CVE-\d{4}-\d{4,}$/i.test(cve.trim());
  return (
    <div className="page">
      <PageHeader title="Reports" sub="Generate shareable outputs from TFII intelligence." />
      <div className="grid g3">
        <Panel title={<><Icon name="shieldAlert" size={15} /> CVE report</>}>
          <div className="small muted" style={{ marginBottom: 12 }}>Advisory email or summary brief for a single vulnerability, built from NVD, EPSS, KEV and public PoC sources.</div>
          <div className="row" style={{ gap: 8 }}>
            <input className="input mono" style={{ flex: 1 }} placeholder="CVE-2025-12345" value={cve} onChange={e => setCve(e.target.value)} onKeyDown={e => e.key === "Enter" && valid && setOpen(cve.trim().toUpperCase())} />
            <Button variant="primary" disabled={!valid} onClick={() => setOpen(cve.trim().toUpperCase())}>Generate</Button>
          </div>
        </Panel>
        {can("data.workspace") && (
          <Panel title={<><Icon name="briefcase" size={15} /> Investigation report</>}>
            <div className="small muted" style={{ marginBottom: 12 }}>Markdown export of an investigation: scope, indicators, linked intelligence, detections, timeline and notes. Open an investigation and choose Export report.</div>
            <Button onClick={() => navigate("/workspace")}>Open Workspace</Button>
          </Panel>
        )}
        {can("data.workspace") && (
          <Panel title={<><Icon name="megaphone" size={15} /> Threat advisory</>}>
            <div className="small muted" style={{ marginBottom: 12 }}>Compose an advisory for a sector from suggested CVEs and matching indicators.</div>
            <Button onClick={() => navigate("/advisories")}>Open Advisory builder</Button>
          </Panel>
        )}
        {can("data.workspace") && (
          <Panel title={<><Icon name="download" size={15} /> STIX 2.1 / TAXII</>}>
            <div className="small muted" style={{ marginBottom: 12 }}>Machine-readable export of active indicators for OpenCTI, MISP and SIEMs.</div>
            <Button onClick={() => navigate("/iocs/export")}>Export options</Button>
          </Panel>
        )}
      </div>
      {open && <CVEReportModal cveId={open} token={getToken()} C={LEGACY_C} onClose={() => setOpen(null)} />}
    </div>
  );
}

export function ApiUsagePage() {
  const [days, setDays] = useState(14);
  const { data, error, reload } = useApi(`/v2/api-usage?days=${days}`);
  const quota = useApi("/users/me/quota");
  const COLORS = ["#38BDF8", "#A78BFA", "#F472B6", "#34D399", "#FB923C", "#F59E0B", "#94A3B8"];
  return (
    <div className="page">
      <PageHeader title="API Usage" sub="Upstream enrichment calls (cache misses) per day. Enrichments are cached for 24 hours to protect quotas."
        actions={<select className="select" value={days} onChange={e => setDays(Number(e.target.value))}>{[7, 14, 30, 60].map(d => <option key={d} value={d}>Last {d} days</option>)}</select>} />
      {error && <ErrorState error={error} onRetry={reload} />}
      <div className="grid g-main-side">
        <Panel title="Calls per day" sub="stacked by service">
          {!data ? <Skeleton h={200} /> : data.services.length === 0 ? <EmptyState icon="barChart" title="No upstream calls in this window" /> : <>
            <StackedBars days={data.days} series={data.services.map((s, i) => ({ key: s.name, label: s.name, color: COLORS[i % COLORS.length], values: s.values }))} />
            <div className="row wrap xs muted" style={{ gap: 14, marginTop: 10 }}>
              {data.services.map((s, i) => <span key={s.name} className="row" style={{ gap: 5 }}><span className="sev-dot" style={{ background: COLORS[i % COLORS.length] }} />{s.name}<span className="num" style={{ color: "var(--text)" }}>{fmtNum(s.total)}</span></span>)}
              <span className="row" style={{ gap: 5 }}>cache hits <span className="num" style={{ color: "var(--success)" }}>{fmtNum((data.cache_hits || []).reduce((a, b) => a + b, 0))}</span></span>
            </div>
          </>}
        </Panel>
        <div className="stack">
          <Panel title="Your quota today" tight>
            {!quota.data ? <div style={{ padding: 16 }}><Skeleton h={80} /></div> : Object.entries(quota.data).map(([svc, q]) => (
              <div key={svc} className="list-row">
                <span style={{ flex: 1, textTransform: "capitalize" }}>{svc}</span>
                {q.unlimited ? <Badge tone="success">{q.has_personal_key ? "Personal key" : "Unlimited"}</Badge> : <span className="num">{q.quota_used ?? 0} / {q.quota_total}</span>}
              </div>
            ))}
          </Panel>
          <Panel title="Top consumers" sub="by user and service">
            {!data ? <Skeleton h={80} /> : <BarList items={data.by_user.slice(0, 10).map(r => ({ label: `${r.username || "system"} · ${r.api_name}`, value: Number(r.n) }))} empty="No calls" />}
          </Panel>
        </div>
      </div>
    </div>
  );
}

export function UsersPage() {
  const { me, can } = useSession();
  const users = useApi("/users");
  const invites = useApi("/invites");
  const [tab, setTab] = useState("users");
  const [nu, setNu] = useState({ username: "", password: "", role: "analyst" });
  const [inviteRole, setInviteRole] = useState("analyst");
  const [code, setCode] = useState(null);
  const [perm, setPerm] = useState(null);
  const toast = useToast();

  async function createUser() {
    try { await apiJSON("/users", { method: "POST", body: nu }); toast(`User ${nu.username} created`, "ok"); setNu({ username: "", password: "", role: "analyst" }); users.reload(true); }
    catch (e) { toast(e.message, "error"); }
  }
  async function toggle(u) {
    try { await apiJSON(`/users/${enc(u.id)}/${u.active ? "disable" : "enable"}`, { method: "PATCH" }); users.reload(true); } catch (e) { toast(e.message, "error"); }
  }
  async function invite() {
    try { const d = await apiJSON("/invites", { method: "POST", body: { role: inviteRole } }); setCode(d); invites.reload(true); } catch (e) { toast(e.message, "error"); }
  }

  return (
    <div className="page">
      <PageHeader title="Users" sub="Accounts, roles, per-user capabilities and invite codes." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "users", label: "Accounts", count: users.data?.length }, { id: "invites", label: "Invite codes", count: invites.data?.length }]} />
      {tab === "users" && (
        <div className="grid g-main-side">
          <div className="stack">
            <Panel tight bodyStyle={{ padding: 0 }}>
              {users.error ? <ErrorState error={users.error} onRetry={users.reload} /> : !users.data ? <div style={{ padding: 16 }}><Skeleton h={120} /></div> : (
                <table className="tbl"><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Created</th><th /></tr></thead>
                  <tbody>{users.data.map(u => (
                    <tr key={u.id} className={perm?.id === u.id ? "selected" : ""}>
                      <td className="primary"><div className="row" style={{ gap: 8 }}><span className="avatar">{u.username[0].toUpperCase()}</span>{u.username}{u.id === me?.id && <span className="faint xs">(you)</span>}</div></td>
                      <td><Badge tone={u.role === "admin" ? "gold" : u.role === "analyst" ? "medium" : "low"}>{u.role}</Badge></td>
                      <td>{u.active ? <Badge tone="success" dot>Active</Badge> : <Badge tone="critical" outline>Disabled</Badge>}</td>
                      <td className="muted">{fmtDate(u.created_at)}</td>
                      <td className="r"><div className="row" style={{ gap: 4, justifyContent: "flex-end" }}>
                        {can("admin.users") && <Button size="xs" onClick={() => setPerm(perm?.id === u.id ? null : u)}>Permissions</Button>}
                        {can("admin.users") && u.id !== me?.id && <Button size="xs" variant={u.active ? "danger" : undefined} onClick={() => toggle(u)}>{u.active ? "Disable" : "Enable"}</Button>}
                      </div></td>
                    </tr>))}</tbody></table>
              )}
            </Panel>
            {perm && <div className="legacy-host"><PermissionsPanel user={perm} token={getToken()} C={LEGACY_C} onClose={() => setPerm(null)} onChanged={() => users.reload(true)} /></div>}
          </div>
          {can("admin.users") && (
            <Panel title="Create user">
              <Field label="Username"><input className="input" value={nu.username} onChange={e => setNu({ ...nu, username: e.target.value })} autoComplete="off" /></Field>
              <Field label="Password"><input className="input" type="password" value={nu.password} onChange={e => setNu({ ...nu, password: e.target.value })} autoComplete="new-password" /></Field>
              <Field label="Role"><Select value={nu.role} onChange={v => setNu({ ...nu, role: v })} options={[["explorer", "Explorer — tools only"], ["analyst", "Analyst"], ["admin", "Admin"]]} /></Field>
              <Button variant="primary" onClick={createUser} disabled={!nu.username || !nu.password}>Create user</Button>
            </Panel>
          )}
        </div>
      )}
      {tab === "invites" && (
        <div className="grid g-main-side">
          <Panel tight bodyStyle={{ padding: 0 }}>
            {!invites.data ? <div style={{ padding: 16 }}><Skeleton h={100} /></div> : invites.data.length === 0 ? <EmptyState icon="mail" title="No invite codes" /> : (
              <table className="tbl"><thead><tr><th>Code</th><th>Role</th><th>Status</th><th>Created</th></tr></thead>
                <tbody>{invites.data.map(i => (
                  <tr key={i.code}><td className="cellmono" style={{ textDecoration: i.used ? "line-through" : "none", opacity: i.used ? .5 : 1 }}>{i.code}</td><td>{i.role}</td>
                    <td>{i.used ? <Badge outline>Used</Badge> : <Badge tone="success" dot>Available</Badge>}</td><td className="muted">{fmtDate(i.created_at)}</td></tr>))}</tbody></table>
            )}
          </Panel>
          <Panel title="Generate invite">
            <Field label="Role"><Select value={inviteRole} onChange={setInviteRole} options={[["analyst", "Analyst"], ["admin", "Admin"]]} /></Field>
            <Button variant="primary" onClick={invite} disabled={!can("admin.users")}>Generate code</Button>
            {code && <Callout tone="ok" style={{ marginTop: 12 }}><div className="row" style={{ gap: 6 }}><span className="mono">{code.code}</span><CopyButton value={code.code} /></div><div className="xs">Role: {code.role}. Share it with the new user for sign-up.</div></Callout>}
          </Panel>
        </div>
      )}
    </div>
  );
}
