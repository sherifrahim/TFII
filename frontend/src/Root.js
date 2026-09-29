import React, { Suspense, lazy, useCallback, useEffect, useMemo, useState } from "react";
import "./design/tfii.css";
import { API_BASE } from "./config";
import { api, apiJSON, TOKEN_KEY, getToken } from "./lib/api";
import { useRoute } from "./lib/router";
import { installLinkGuard } from "./lib/safe";
import { useNewVersion } from "./lib/update";
import { SessionContext } from "./lib/session";
import { ToastProvider, Button, Callout, Loading } from "./components/ui";
import { LEGACY_C } from "./design/tokens";
import Shell from "./shell/Shell";
import ErrorBoundary from "./components/ErrorBoundary";
import { activeNav } from "./shell/nav";
import { ApiKeyModal, DemoLockedPage } from "./legacy/lazy";

import CommandCenter from "./pages/CommandCenter";
import { IocIntel, AddIoc, ImportIocs, ExportIocs } from "./pages/Iocs";
import EntityPage from "./pages/EntityPage";
import { CveIntel, CvePublicPage } from "./pages/Cve";
import { ActorsPage, ActorPublicPage } from "./pages/Actors";
import { CampaignsPage } from "./pages/Campaigns";
import IntelWall from "./pages/IntelWall";
import { SearchPage, ExplorerPage } from "./pages/Search";
import { WorkspacePage, InvestigationPage } from "./pages/Workspace";
// Platform / OSINT screens sit on the large legacy component library, so they
// load on demand rather than with the first paint.
const OsintToolkit = lazy(() => import("./pages/Osint"));
const platform = name => lazy(() => import("./pages/Platform").then(m => ({ default: m[name] })));
const HealthPage = platform("HealthPage"), ConnectorsPage = platform("ConnectorsPage"), ApiUsagePage = platform("ApiUsagePage"),
  UsersPage = platform("UsersPage"), SettingsPage = platform("SettingsPage"), FilesPage = platform("FilesPage"),
  QueryPage = platform("QueryPage"), GeoPage = platform("GeoPage"), AdvisoriesPage = platform("AdvisoriesPage"), ReportsPage = platform("ReportsPage");

function Login({ onToken }) {
  const [tab, setTab] = useState("login");
  const [u, setU] = useState(""); const [p, setP] = useState(""); const [invite, setInvite] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(e) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      const r = tab === "login"
        ? await fetch(`${API_BASE}/auth/login`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: u, password: p }) })
        : await fetch(`${API_BASE}/auth/signup`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: u, password: p, invite_code: invite }) });
      const d = await r.json().catch(() => ({}));
      if (r.ok) { localStorage.setItem(TOKEN_KEY, d.access_token); onToken(d.access_token); }
      else setErr(typeof d.detail === "string" ? d.detail : "Sign-in failed");
    } catch { setErr("Cannot reach the TFII server."); }
    setBusy(false);
  }
  return (
    <div className="login">
      <div className="login-card">
        <div className="row" style={{ gap: 10, justifyContent: "center", marginBottom: 24 }}>
          <div className="sb-logo" style={{ width: 34, height: 34, fontSize: 13 }}>TF</div>
          <div><div className="sb-name" style={{ fontSize: 17 }}>TFII</div><div className="sb-sub">Threat Intelligence Platform</div></div>
        </div>
        <form className="panel" style={{ padding: 24 }} onSubmit={submit}>
          <div className="seg" style={{ width: "100%", marginBottom: 18 }}>
            {[["login", "Sign in"], ["signup", "Create account"]].map(([id, l]) => (
              <button type="button" key={id} className={tab === id ? "on" : ""} style={{ flex: 1 }} onClick={() => { setTab(id); setErr(""); }}>{l}</button>
            ))}
          </div>
          <div className="field"><label>Username</label><input className="input" value={u} onChange={e => setU(e.target.value)} autoFocus autoComplete="username" /></div>
          <div className="field"><label>Password</label><input className="input" type="password" value={p} onChange={e => setP(e.target.value)} autoComplete={tab === "login" ? "current-password" : "new-password"} /></div>
          {tab === "signup" && (
            <div className="field">
              <label>Invite code (optional)</label>
              <input className="input mono" value={invite} onChange={e => setInvite(e.target.value)} />
              <div className="hint">Without an invite you get explorer access: CVE lookup, OSINT tools, query builder and bulk lookup. Full access can be requested from inside the app.</div>
            </div>
          )}
          {err && <Callout tone="error" style={{ marginBottom: 14 }}>{err}</Callout>}
          <Button variant="primary" size="lg" style={{ width: "100%" }} loading={busy} disabled={!u || !p} type="submit">
            {tab === "login" ? "Sign in" : "Create account"}
          </Button>
        </form>
        <div className="faint xs" style={{ textAlign: "center", marginTop: 14 }}>{API_BASE.replace(/^https?:\/\//, "")}</div>
      </div>
    </div>
  );
}

// Route table → {crumbs, element}. Kept as one function so the whole IA is readable in one place.
function resolve(route, ctx) {
  const s = route.segments, q = route.query;
  const [a, b, c] = s;
  const IOC = { label: "IOC Intelligence", to: "/iocs" };
  const CVE = { label: "CVE Intelligence", to: "/cve" };
  switch (a) {
    case undefined:
      // Explorer accounts have no indicator database; their home is the Intel Wall.
      if (!ctx.hasData) return { crumbs: [{ label: "Intel Wall" }], el: <IntelWall query={q} /> };
      return { crumbs: [{ label: "Command Center" }], el: <CommandCenter /> };
    case "iocs":
      if (b === "new") return { crumbs: [IOC, { label: "Add IOC" }], el: <AddIoc /> };
      if (b === "import") return { crumbs: [IOC, { label: "Import" }], el: <ImportIocs /> };
      if (b === "export") return { crumbs: [IOC, { label: "Export" }], el: <ExportIocs /> };
      return { crumbs: [IOC], el: <IocIntel query={q} /> };
    // Every entity kind renders through one page (pages/EntityPage.js); `inv`
    // carries the investigation the analyst came from.
    case "ioc": return { crumbs: [IOC, { label: "Indicator" }], el: <EntityPage kind="indicator" refv={b} tab={q.tab} inv={q.inv} /> };
    case "observable": return { crumbs: [IOC, { label: "Indicator" }], el: <EntityPage kind="indicator" refv={b} tab={q.tab} inv={q.inv} /> };
    case "cve":
      if (b && !ctx.hasData) return { crumbs: [CVE, { label: b.toUpperCase() }], el: <CvePublicPage cveId={b.toUpperCase()} /> };
      if (b) return { crumbs: [CVE, { label: b.toUpperCase() }], el: <EntityPage kind="cve" refv={b.toUpperCase()} tab={q.tab} inv={q.inv} /> };
      return { crumbs: [CVE], el: <CveIntel query={q} /> };
    case "software": return { crumbs: [CVE, { label: "Software" }], el: <EntityPage kind="software" refv={b} tab={q.tab} inv={q.inv} /> };
    case "actors":
      if (b && !ctx.hasData) return { crumbs: [{ label: "Threat Actors", to: "/actors" }, { label: b }], el: <ActorPublicPage name={b} /> };
      if (b) return { crumbs: [{ label: "Threat Actors", to: "/actors" }, { label: b }], el: <EntityPage kind="actor" refv={b} tab={q.tab} inv={q.inv} /> };
      return { crumbs: [{ label: "Threat Actors" }], el: <ActorsPage query={q} /> };
    case "malware": return { crumbs: [{ label: "Threat Actors", to: "/actors" }, { label: "Malware" }, { label: b }], el: <EntityPage kind="malware" refv={b} tab={q.tab} inv={q.inv} /> };
    case "campaigns":
      if (b) return { crumbs: [{ label: "Campaigns", to: "/campaigns" }, { label: "Campaign" }], el: <EntityPage kind="campaign" refv={b} tab={q.tab} inv={q.inv} /> };
      return { crumbs: [{ label: "Campaigns" }], el: <CampaignsPage /> };
    case "intel": return { crumbs: [{ label: "Intel Wall" }], el: <IntelWall query={q} /> };
    case "search": return { crumbs: [{ label: "Global Search" }], el: <SearchPage q={q.q || ""} kinds={q.kinds || ""} /> };
    case "explorer": return { crumbs: [{ label: "Entity Explorer" }], el: <ExplorerPage query={q} /> };
    case "osint": return { crumbs: [{ label: "OSINT Toolkit", to: "/osint" }, ...(b ? [{ label: b }] : [])], el: <OsintToolkit tool={b} /> };
    case "query": return { crumbs: [{ label: "Query Builder" }], el: <QueryPage /> };
    case "geo": return { crumbs: [{ label: "Geo Intelligence" }], el: <GeoPage /> };
    case "workspace": return { crumbs: [{ label: "Workspace" }], el: <WorkspacePage query={q} /> };
    case "investigations": return { crumbs: [{ label: "Workspace", to: "/workspace" }, { label: "Investigation" }], el: <InvestigationPage id={b} tab={q.tab} /> };
    case "advisories": return { crumbs: [{ label: "Advisories" }], el: <AdvisoriesPage /> };
    case "reports": return { crumbs: [{ label: "Reports" }], el: <ReportsPage /> };
    case "platform": {
      const P = { label: "Platform" };
      if (b === "health") return { crumbs: [P, { label: "Health" }], el: <HealthPage /> };
      if (b === "connectors") return { crumbs: [P, { label: "Connectors" }], el: <ConnectorsPage /> };
      if (b === "api-usage") return { crumbs: [P, { label: "API Usage" }], el: <ApiUsagePage /> };
      if (b === "users") return { crumbs: [P, { label: "Users" }], el: <UsersPage /> };
      if (b === "files") return { crumbs: [P, { label: "Files" }], el: <FilesPage /> };
      return { crumbs: [P, { label: "Settings" }], el: <SettingsPage onOpenApiKeys={ctx.openApiKeys} /> };
    }
    default:
      void c;
      return { crumbs: [{ label: "Not found" }], el: <div className="page"><div className="state"><div className="t">Page not found</div><a className="link" href="#/">Go to Command Center</a></div></div> };
  }
}

export default function Root() {
  const [token, setToken] = useState(getToken);
  const [me, setMe] = useState(null);
  const [meErr, setMeErr] = useState(null);
  const [showKeys, setShowKeys] = useState(false);
  const route = useRoute();
  const newVersion = useNewVersion();
  useEffect(() => installLinkGuard(), []);

  const logout = useCallback(() => {
    try { localStorage.removeItem(TOKEN_KEY); } catch {}
    setToken(null); setMe(null);
  }, []);

  useEffect(() => {
    if (!token) return;
    setMeErr(null);
    apiJSON("/auth/me").then(d => {
      setMe(d);
      // Preserve the original first-run behaviour: prompt for API keys once.
      const k = `apikeys_setup_done_${d.id}`;
      if (localStorage.getItem(k)) return;
      api("/users/me/api-keys").then(r => (r.ok ? r.json() : null)).then(keys => {
        if (!keys) return;
        if (Array.isArray(keys) && keys.some(x => x.has_key)) localStorage.setItem(k, "1");
        else setShowKeys(true);
      }).catch(() => {});
    }).catch(e => setMeErr(e));
  }, [token]);

  const session = useMemo(() => {
    const caps = me?.capabilities || [];
    return { me, token, caps, can: cap => caps.includes(cap), logout };
  }, [me, token, logout]);

  if (!token) return <ToastProvider><Login onToken={setToken} /></ToastProvider>;
  if (meErr) return (
    <div className="login"><div className="login-card"><Callout tone="error">{meErr.message}</Callout>
      <div className="row" style={{ marginTop: 12, justifyContent: "center" }}><Button onClick={() => window.location.reload()}>Retry</Button><Button variant="ghost" onClick={logout}>Sign out</Button></div></div></div>
  );
  if (!me) return <div className="login"><Loading label="Loading TFII" /></div>;

  const hasData = session.can("data.workspace");
  const { crumbs, el } = resolve(route, { openApiKeys: () => setShowKeys(true), hasData });
  const nav = activeNav(route.path);
  const locked = nav?.data && !hasData && route.path !== "/";

  return (
    <SessionContext.Provider value={session}>
      <ToastProvider>
        <Shell route={route} crumbs={crumbs}>
          {locked
            ? <div className="page narrow legacy-host"><DemoLockedPage token={token} C={LEGACY_C} featureLabel={nav.label} /></div>
            : <ErrorBoundary key={route.path}><Suspense fallback={<div className="page"><Loading label="Loading" /></div>}>{el}</Suspense></ErrorBoundary>}
        </Shell>
        {newVersion && (
          <div role="status" style={{ position: "fixed", bottom: 16, left: "50%", transform: "translateX(-50%)", zIndex: 900, maxWidth: "calc(100vw - 32px)" }}>
            <Callout tone="ok"><div className="row" style={{ gap: 12 }}>
              <span>A new version of TFII is available. Reload to use the latest fixes.</span>
              <Button size="sm" onClick={() => window.location.reload()}>Reload</Button>
            </div></Callout>
          </div>
        )}
        {showKeys && (
          <ApiKeyModal token={token} C={LEGACY_C} onClose={() => {
            setShowKeys(false);
            if (me?.id) localStorage.setItem(`apikeys_setup_done_${me.id}`, "1");
          }} />
        )}
      </ToastProvider>
    </SessionContext.Provider>
  );
}
