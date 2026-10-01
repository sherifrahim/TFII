import React, { useCallback, useEffect, useState } from "react";
import { api, apiJSON } from "../lib/api";
import { setQuery } from "../lib/router";
import { usePrefs } from "../lib/prefs";
import { useSession } from "../lib/session";
import { timeAgo } from "../lib/format";
import Icon from "../components/Icon";
import { ApiKeysPanel } from "../components/ApiKeys";
import { Badge, Button, Callout, Disclosure, Field, PageHeader, Panel, Segmented, Setting, Settings, Switch, useToast } from "../components/ui";

function Account() {
  const { me, logout } = useSession();
  const toast = useToast();
  const [prefs, setPref] = usePrefs();
  const [cur, setCur] = useState(""); const [nw, setNw] = useState(""); const [conf, setConf] = useState("");
  const [show, setShow] = useState(false); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");

  async function change(e) {
    e.preventDefault();
    if (!cur || !nw || !conf) { setErr("Fill in all three fields."); return; }
    if (nw !== conf) { setErr("The new passwords don't match."); return; }
    if (nw.length < 8) { setErr("Use at least 8 characters."); return; }
    setBusy(true); setErr("");
    const r = await api("/auth/change-password", { method: "POST", body: JSON.stringify({ current_password: cur, new_password: nw }) });
    if (r.ok) { toast("Password changed", "ok"); setCur(""); setNw(""); setConf(""); }
    else { const d = await r.json().catch(() => ({})); setErr(typeof d.detail === "string" ? d.detail : "Could not change the password."); }
    setBusy(false);
  }
  return (
    <div className="stack" style={{ gap: 20 }}>
      <Panel>
        <div className="row" style={{ gap: 16 }}>
          <div className="avatar" style={{ width: 52, height: 52, fontSize: 20 }}>{(me?.username || "?")[0].toUpperCase()}</div>
          <div style={{ flex: 1 }}>
            <div className="strong" style={{ fontSize: 17 }}>{me?.username}</div>
            <div className="row" style={{ gap: 8, marginTop: 4 }}><Badge tone="accent" style={{ textTransform: "capitalize" }}>{me?.role}</Badge>{me?.email && <span className="small muted">{me.email}</span>}</div>
          </div>
          <Button variant="danger" icon="logout" onClick={logout}>Sign out</Button>
        </div>
      </Panel>

      <Panel title="Display" sub="Saved in this browser">
        <Settings>
          <Setting title="Table density" hint="Compact fits more rows on screen."><Segmented value={prefs.density} onChange={v => setPref({ density: v })} options={[["comfortable", "Comfortable"], ["compact", "Compact"]]} /></Setting>
          <Setting title="Animations" hint="Smooth transitions and chart effects. Turn off if you prefer a still interface."><Switch checked={prefs.motion} onChange={v => setPref({ motion: v })} /></Setting>
          <Setting title="Easter eggs" hint="A few harmless surprises. Hint: it involves a famous cheat code."><Switch checked={prefs.fun} onChange={v => setPref({ fun: v })} /></Setting>
        </Settings>
      </Panel>

      <Panel title="Change password">
        <form onSubmit={change} style={{ maxWidth: 380 }}>
          <Field label="Current password"><input className="input" type={show ? "text" : "password"} value={cur} onChange={e => setCur(e.target.value)} autoComplete="current-password" /></Field>
          <Field label="New password" hint="At least 8 characters."><input className="input" type={show ? "text" : "password"} value={nw} onChange={e => setNw(e.target.value)} autoComplete="new-password" /></Field>
          <Field label="Confirm new password"><input className="input" type={show ? "text" : "password"} value={conf} onChange={e => setConf(e.target.value)} autoComplete="new-password" /></Field>
          <div style={{ marginBottom: 14 }}><Switch checked={show} onChange={setShow} label="Show passwords" /></div>
          {err && <Callout tone="error" style={{ marginBottom: 14 }}>{err}</Callout>}
          <Button variant="primary" type="submit" loading={busy}>Change password</Button>
        </form>
      </Panel>
    </div>
  );
}

function NField({ label, value, onChange, type = "text", placeholder, mono }) {
  return <Field label={label}><input className={`input ${mono ? "mono" : ""}`} type={type} value={value ?? ""} onChange={e => onChange(e.target.value)} placeholder={placeholder} autoComplete="off" /></Field>;
}

function Notifications() {
  const toast = useToast();
  const [s, setS] = useState(null);
  const [busy, setBusy] = useState("");
  const [preview, setPreview] = useState(null);
  const set = patch => setS(p => ({ ...p, ...patch }));

  useEffect(() => {
    apiJSON("/admin/notify/settings").then(d => setS({ enabled: true, daily_enabled: true, weekly_enabled: true, ntfy_topic: "", ntfy_server: "https://ntfy.sh", ntfy_priority: "urgent",
      telegram_token: "", telegram_chat_id: "", email_to: "", smtp_host: "", smtp_port: 587, smtp_user: "", smtp_pass: "", smtp_from: "", ...d })).catch(e => toast(e.message, "error"));
  }, [toast]);

  async function act(name, path, opts, okMsg) {
    setBusy(name);
    try { const d = await apiJSON(path, opts); toast(typeof okMsg === "function" ? okMsg(d) : okMsg, "ok"); return d; }
    catch (e) { toast(e.message, "error"); }
    finally { setBusy(""); }
    return null;
  }
  if (!s) return <div className="state"><span className="spinner" /></div>;
  const publicNtfy = (s.ntfy_server || "https://ntfy.sh") === "https://ntfy.sh";
  return (
    <div className="stack" style={{ gap: 20 }}>
      <Panel title="Admin notifications" sub="A daily CVE digest to your phone or inbox">
        <Settings>
          <Setting title="Send notifications" hint="Turn everything below on or off in one place."><Switch checked={!!s.enabled} onChange={v => set({ enabled: v })} /></Setting>
          <Setting title="Daily brief" hint="Every morning at 8:00."><Switch checked={!!s.daily_enabled} onChange={v => set({ daily_enabled: v })} disabled={!s.enabled} /></Setting>
          <Setting title="Weekly summary" hint="Sundays."><Switch checked={!!s.weekly_enabled} onChange={v => set({ weekly_enabled: v })} disabled={!s.enabled} /></Setting>
        </Settings>
      </Panel>

      <div className="grid g2">
        <Panel title={<><Icon name="bell" size={15} /> Push (ntfy)</>} sub="Free push to Android and iOS">
          <NField label="Topic" value={s.ntfy_topic} onChange={v => set({ ntfy_topic: v })} placeholder="my-secret-tfii-alerts" mono />
          <div className="small faint" style={{ marginTop: -8, marginBottom: 14 }}>Anyone who knows the topic name can read it. Make it hard to guess.</div>
          <Field label="Server"><Segmented value={publicNtfy ? "public" : "own"} onChange={v => set({ ntfy_server: v === "public" ? "https://ntfy.sh" : (publicNtfy ? "https://your-ntfy-server.example" : s.ntfy_server) })} options={[["public", "ntfy.sh"], ["own", "Self-hosted"]]} /></Field>
          {!publicNtfy && <NField label="Server address" value={s.ntfy_server} onChange={v => set({ ntfy_server: v })} placeholder="https://ntfy.example.com" mono />}
          <Field label="Priority" hint="Urgent bypasses Android battery saving."><Segmented value={s.ntfy_priority || "urgent"} onChange={v => set({ ntfy_priority: v })} options={[["min", "Min"], ["low", "Low"], ["default", "Default"], ["high", "High"], ["urgent", "Urgent"]]} /></Field>
          <Disclosure title="Android battery tips">
            <div className="small muted" style={{ lineHeight: 1.7 }}>With <b>Urgent</b> priority and ntfy.sh (or a self-hosted server with FCM), messages arrive even in Doze mode. For a self-hosted server without FCM: in the ntfy app enable <b>Instant delivery</b>, then set the app's battery usage to <b>Unrestricted</b>.</div>
          </Disclosure>
        </Panel>
        <Panel title={<><Icon name="mail" size={15} /> Telegram</>} sub="Create a bot with @BotFather">
          <NField label="Bot token" value={s.telegram_token} onChange={v => set({ telegram_token: v })} type="password" placeholder="1234567890:ABC…" mono />
          <NField label="Chat ID" value={s.telegram_chat_id} onChange={v => set({ telegram_chat_id: v })} placeholder="Message the bot, then use its chat id" mono />
          <Disclosure title="Email (SMTP)" hint="Also used for approval emails">
            <div className="grid g2" style={{ gap: 12 }}>
              <NField label="Send to" value={s.email_to} onChange={v => set({ email_to: v })} placeholder="you@example.com" />
              <NField label="SMTP host" value={s.smtp_host} onChange={v => set({ smtp_host: v })} placeholder="smtp.example.com" />
              <NField label="Port" value={s.smtp_port} onChange={v => set({ smtp_port: v })} placeholder="587" />
              <NField label="User" value={s.smtp_user} onChange={v => set({ smtp_user: v })} />
              <NField label="Password" value={s.smtp_pass} onChange={v => set({ smtp_pass: v })} type="password" />
              <NField label="From" value={s.smtp_from} onChange={v => set({ smtp_from: v })} placeholder="TFII <alerts@example.com>" />
            </div>
          </Disclosure>
        </Panel>
      </div>

      <div className="row wrap" style={{ gap: 10 }}>
        <Button variant="primary" icon="check" loading={busy === "save"} onClick={() => act("save", "/admin/notify/settings", { method: "POST", body: s }, "Settings saved")}>Save settings</Button>
        <Button loading={busy === "test"} onClick={() => act("test", "/admin/notify/test", { method: "POST" }, "Test sent. Check your device.")}>Send a test</Button>
        <Button variant="ghost" loading={busy === "daily"} onClick={() => act("daily", "/admin/notify/send-now?type=daily", { method: "POST" }, d => `Daily brief sent (${d.cves_found} CVEs)`)}>Send daily now</Button>
        <Button variant="ghost" loading={busy === "weekly"} onClick={() => act("weekly", "/admin/notify/send-now?type=weekly", { method: "POST" }, d => `Weekly summary sent (${d.cves_found} CVEs)`)}>Send weekly now</Button>
        <Button variant="ghost" icon="eye" loading={busy === "preview"} onClick={async () => { setBusy("preview"); try { setPreview(await apiJSON("/admin/notify/preview?type=daily")); } catch (e) { toast(e.message, "error"); } setBusy(""); }}>Preview</Button>
      </div>
      {preview && <Panel title="Brief preview" actions={<Button size="xs" variant="ghost" onClick={() => setPreview(null)}>Close</Button>}><pre className="code" style={{ whiteSpace: "pre-wrap", maxHeight: 360 }}>{preview.body}</pre></Panel>}
    </div>
  );
}

function AccessRequests() {
  const toast = useToast();
  const [rows, setRows] = useState(null);
  const [busy, setBusy] = useState(null);
  const load = useCallback(() => { apiJSON("/admin/access-requests?status=pending").then(setRows).catch(e => { setRows([]); toast(e.message, "error"); }); }, [toast]);
  useEffect(() => { load(); }, [load]);
  async function decide(req, action, role) {
    setBusy(req.id);
    try {
      const d = await apiJSON(`/admin/access-requests/${req.id}/${action}`, { method: "POST", body: action === "approve" ? { role: role || "analyst" } : undefined });
      toast(action === "approve" ? `Approved as ${d.granted_role}${d.email_sent ? ", welcome email sent" : ". No email was sent: set up SMTP under Notifications."}` : "Request denied", "ok");
      load();
    } catch (e) { toast(e.message, "error"); }
    setBusy(null);
  }
  return (
    <Panel title="Access requests" sub="People who signed up and asked for full access" actions={<Button size="sm" variant="ghost" icon="refresh" onClick={load}>Refresh</Button>}>
      {rows === null ? <div className="state"><span className="spinner" /></div>
        : rows.length === 0 ? <div className="state" style={{ padding: "28px 0" }}><div className="d">No pending requests.</div></div>
        : <div className="stack" style={{ gap: 10 }}>{rows.map(r => (
          <div key={r.id} className="key-row" style={{ gridTemplateColumns: "minmax(0, 1fr) auto" }}>
            <div style={{ minWidth: 0 }}>
              <div className="strong">{r.username} <span className="faint small" style={{ fontWeight: 400 }}>{r.email}</span></div>
              {r.message && <div className="small muted" style={{ marginTop: 4, fontStyle: "italic" }}>“{r.message}”</div>}
              <div className="xs faint" style={{ marginTop: 4 }}>Asked {timeAgo(r.requested_at)}</div>
            </div>
            <div className="row" style={{ gap: 8 }}>
              <Button size="sm" variant="primary" loading={busy === r.id} onClick={() => decide(r, "approve", "analyst")}>Approve</Button>
              <Button size="sm" variant="ghost" disabled={busy === r.id} onClick={() => decide(r, "deny")}>Deny</Button>
            </div>
          </div>))}</div>}
    </Panel>
  );
}

function Maintenance() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  return (
    <Panel title="IOC feed cleanup">
      <div className="small muted" style={{ maxWidth: 620, marginBottom: 14, lineHeight: 1.7 }}>Removes indicators that were auto-added from CVE reference links (vendor advisory pages, Google, CISA, GitHub and other trusted domains) and should never have been in the feed. Indicators that came from a feed are never touched. Safe to run repeatedly.</div>
      <Button icon="trash" loading={busy} onClick={async () => { setBusy(true); try { const d = await apiJSON("/admin/cleanup-advisory-iocs", { method: "POST" }); toast(d.message || "Cleanup finished", "ok"); } catch (e) { toast(e.message, "error"); } setBusy(false); }}>Run cleanup now</Button>
    </Panel>
  );
}

const SECTIONS = [
  { id: "account", label: "Account & display", icon: "users" },
  { id: "keys", label: "API keys", icon: "key" },
  { id: "notifications", label: "Notifications", icon: "bell", admin: true },
  { id: "access", label: "Access requests", icon: "lock", admin: true },
  { id: "maintenance", label: "Maintenance", icon: "settings", admin: true },
];

export default function SettingsPage({ query }) {
  const { me } = useSession();
  const admin = me?.role === "admin";
  const items = SECTIONS.filter(s => !s.admin || admin);
  const tab = items.some(s => s.id === query.tab) ? query.tab : "account";
  return (
    <div className="page">
      <PageHeader title="Settings" sub="Your account, your keys and how TFII looks and behaves for you." />
      <div className="settings-layout">
        <nav className="set-nav" aria-label="Settings sections">
          {items.map(s => <button key={s.id} className={`rail-item ${tab === s.id ? "on" : ""}`} onClick={() => setQuery({ tab: s.id === "account" ? "" : s.id })}><Icon name={s.icon} size={15} /> {s.label}</button>)}
        </nav>
        <div style={{ minWidth: 0 }}>
          {tab === "account" && <Account />}
          {tab === "keys" && <Panel title="API keys"><ApiKeysPanel /></Panel>}
          {tab === "notifications" && <Notifications />}
          {tab === "access" && <AccessRequests />}
          {tab === "maintenance" && <Maintenance />}
        </div>
      </div>
    </div>
  );
}
