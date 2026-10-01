import React, { useCallback, useEffect, useRef, useState } from "react";
import Icon from "../components/Icon";
import { IconButton, Menu, useClickOutside, useHotkey, useLocal } from "../components/ui";
import Logo, { Wordmark } from "../components/Logo";
import { Eggs, logoClicked } from "./Eggs";
import { NAV } from "./nav";
import { navigate, href } from "../lib/router";
import { useSession } from "../lib/session";
import { api, apiJSON } from "../lib/api";
import { timeAgo } from "../lib/format";
import CommandPalette from "./CommandPalette";

export default function Shell({ route, crumbs, children }) {
  const { me, can, logout } = useSession();
  const [collapsed, setCollapsed] = useLocal("tf_sidebar_collapsed", typeof window !== "undefined" && window.innerWidth < 900);
  const [closed, setClosed] = useLocal("tf_nav_closed", { Platform: true });
  const [palette, setPalette] = useState(false);
  const openPalette = useCallback(() => setPalette(true), []);

  useHotkey("mod+k", () => setPalette(p => !p), []);
  useHotkey("/", () => setPalette(true), []);
  useHotkey("mod+b", () => setCollapsed(c => !c), []);
  useEffect(() => {
    const h = () => setPalette(true);
    window.addEventListener("tf:palette", h);
    return () => window.removeEventListener("tf:palette", h);
  }, []);

  // Close the palette on navigation.
  useEffect(() => { setPalette(false); }, [route.path]);

  const isExplorer = !can("data.workspace");
  const mac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || "");
  const mod = mac ? "⌘" : "Ctrl";
  const [logoSpin, setLogoSpin] = useState(0);
  // A thin bar sweeps across the top on every navigation.
  const [bar, setBar] = useState(0);
  useEffect(() => { setBar(b => b + 1); }, [route.path]);

  const newItems = can("data.workspace") ? [
    { label: "Add an indicator", icon: "plus", onClick: () => navigate("/iocs/new") },
    { label: "Bulk lookup", icon: "layers", onClick: () => navigate("/osint/bulk") },
    { label: "New investigation", icon: "briefcase", onClick: () => navigate("/workspace", { new: "1" }) },
    "sep",
    { label: "Import indicators", icon: "upload", onClick: () => navigate("/iocs/import") },
  ] : [
    { label: "Bulk lookup", icon: "layers", onClick: () => navigate("/osint/bulk") },
    { label: "Look up a CVE", icon: "shieldAlert", onClick: () => navigate("/cve", { tab: "lookup" }) },
  ];

  return (
    <div className="app">
      <div key={bar} className="route-bar" aria-hidden />
      <Eggs />
      <aside className={`sidebar ${collapsed ? "collapsed" : ""}`}>
        <div className="sb-brand">
          <span className="logo-hit" onClick={() => { if (logoClicked()) setLogoSpin(n => n + 1); }} role="presentation">
            <Logo key={logoSpin} size={32} animate spin={logoSpin > 0} title="TFII" />
          </span>
          <div className="sb-brand-text" style={{ minWidth: 0 }}>
            <Wordmark />
            <div className="sb-sub">Threat Intelligence</div>
          </div>
        </div>
        <nav className="sb-nav" aria-label="Primary">
          {NAV.map(section => {
            const items = section.items.filter(it =>
              (!it.cap || can(it.cap)) && (!it.root || me?.is_root_admin));
            if (!items.length) return null;
            return (
              <div key={section.sec}>
                {collapsed ? <div className="sb-sec">{section.sec}</div> : (
                  <button className={`sb-sec sb-sec-btn ${closed[section.sec] ? "closed" : ""}`} aria-expanded={!closed[section.sec]}
                    onClick={() => setClosed(c => ({ ...c, [section.sec]: !c[section.sec] }))}>
                    {section.sec}<Icon name="chevronDown" size={12} />
                  </button>
                )}
                {(collapsed || !closed[section.sec] || items.some(it => it.match(route.path))) && items.map(it => {
                  const active = it.match(route.path);
                  const locked = isExplorer && it.data;
                  return (
                    <a key={it.id} href={href(it.to)} className={`sb-item ${active ? "active" : ""} ${locked ? "locked" : ""}`}
                      data-tip={collapsed ? it.label : locked ? "Requires full access" : undefined} aria-current={active ? "page" : undefined}>
                      <Icon name={it.icon} size={16} />
                      <span className="sb-label">{it.label}</span>
                      {locked && <Icon name="lock" size={12} className="sb-count" />}
                    </a>
                  );
                })}
              </div>
            );
          })}
        </nav>
        <div className="sb-foot">
          <button className="sb-item" onClick={() => setCollapsed(c => !c)} data-tip={collapsed ? `Expand sidebar (${mod} B)` : undefined}>
            <Icon name="panel" size={16} /><span className="sb-label">Collapse</span><span className="sb-count"><kbd>{mod} B</kbd></span>
          </button>
          <Menu align="left" width={216} trigger={(toggle) => (
            <button className="sb-user" onClick={toggle} aria-label="Account menu" style={{ border: 0, cursor: "pointer", textAlign: "left", width: "100%", color: "inherit" }}>
              <div className="avatar">{(me?.username || "?")[0].toUpperCase()}</div>
              <div className="sb-label" style={{ minWidth: 0, flex: 1 }}>
                <div className="trunc" style={{ color: "var(--text)", fontSize: 13, fontWeight: 550 }}>{me?.username}</div>
                <div className="faint xs" style={{ textTransform: "capitalize" }}>{me?.role}</div>
              </div>
              {!collapsed && <Icon name="chevronUp" size={14} style={{ color: "var(--text-4)" }} />}
            </button>
          )} items={[
            { label: "Settings", icon: "settings", onClick: () => navigate("/platform/settings") },
            { label: "API keys", icon: "key", onClick: () => window.dispatchEvent(new Event("tf:keys")) },
            "sep",
            { label: "Sign out", icon: "logout", onClick: logout, danger: true },
          ]} />
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="crumbs">
            {crumbs.map((c, i) => (
              <React.Fragment key={i}>
                {i > 0 && <Icon name="chevronRight" size={12} className="sep" />}
                {c.to && i < crumbs.length - 1 ? <a href={href(c.to)}>{c.label}</a> : <span className={i === crumbs.length - 1 ? "cur" : ""}>{c.label}</span>}
              </React.Fragment>
            ))}
          </div>
          <button className="search-trigger" onClick={openPalette} aria-label="Search (Ctrl+K)">
            <Icon name="search" size={14} />
            <span>Search IOCs, CVEs, actors, campaigns…</span>
            <kbd>{mod} K</kbd>
          </button>
          <Menu width={220} trigger={(toggle) => (
            <button className="btn primary" onClick={toggle} aria-label="Create new"><Icon name="plus" size={14} />New</button>
          )} items={newItems} />
          <NotificationCenter />
        </header>
        <main className="content" id="tf-content">{children}</main>
      </div>
      {palette && <CommandPalette onClose={() => setPalette(false)} />}
    </div>
  );
}

// ── Notification center ───────────────────────────────────────────────────────
const GROUPS = [["all", "All"], ["critical", "Critical"], ["intelligence", "Intelligence"], ["system", "System"]];
const GROUP_TONE = { critical: "var(--critical)", intelligence: "var(--medium)", system: "var(--high)" };

function NotificationCenter() {
  const { can } = useSession();
  const enabled = can("admin.panel");
  const [count, setCount] = useState(0);
  const [open, setOpen] = useState(false);
  const [data, setData] = useState(null);
  const [group, setGroup] = useState("all");
  const [err, setErr] = useState(null);
  const ref = useRef(null);
  useClickOutside(ref, () => setOpen(false), open);

  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    // No polling while the tab is hidden; refresh as soon as it is shown again.
    const poll = () => { if (document.hidden) return; api("/notifications/count").then(r => (r.ok ? r.json() : null)).then(d => { if (alive && d) setCount(d.count); }).catch(() => {}); };
    poll();
    const t = setInterval(poll, 60000);
    document.addEventListener("visibilitychange", poll);
    return () => { alive = false; clearInterval(t); document.removeEventListener("visibilitychange", poll); };
  }, [enabled]);

  const load = useCallback(async () => {
    setErr(null);
    try { const d = await apiJSON("/v2/notifications"); setData(d); setCount(d.unread); } catch (e) { setErr(e); }
  }, []);

  useEffect(() => { if (open) load(); }, [open, load]);

  if (!enabled) return null;

  async function openItem(n) {
    if (!n.read) {
      api(`/notifications/${n.id}/read`, { method: "PATCH" });
      setData(d => ({ ...d, items: d.items.map(x => (x.id === n.id ? { ...x, read: true } : x)) }));
      setCount(c => Math.max(0, c - 1));
    }
    if (n.route) { setOpen(false); navigate(n.route); }
  }
  async function readAll() {
    await api("/notifications/read-all", { method: "PATCH" });
    setData(d => d && { ...d, items: d.items.map(x => ({ ...x, read: true })), groups: { critical: 0, intelligence: 0, system: 0 } });
    setCount(0);
  }

  const items = (data?.items || []).filter(n => group === "all" || n.group === group);

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <IconButton icon="bell" title="Notifications" badge={count} onClick={() => setOpen(o => !o)} />
      {open && (
        <div className="popover nc">
          <div className="row between" style={{ padding: "10px 14px 0" }}>
            <div className="strong" style={{ fontSize: 13 }}>Notifications</div>
            {count > 0 && <button className="btn ghost xs" onClick={readAll}>Mark all read</button>}
          </div>
          <div className="tabs" style={{ margin: "6px 0 0", padding: "0 8px" }}>
            {GROUPS.map(([id, label]) => (
              <button key={id} className={`tab ${group === id ? "on" : ""}`} style={{ height: 30, fontSize: 12 }} onClick={() => setGroup(id)}>
                {label}{id !== "all" && data?.groups?.[id] ? <span className="n">{data.groups[id]}</span> : null}
              </button>
            ))}
          </div>
          <div style={{ overflowY: "auto", flex: 1 }}>
            {!data && !err && <div className="state"><span className="spinner" /></div>}
            {err && <div className="state error"><div className="d">{err.message}</div></div>}
            {data && items.length === 0 && <div className="state"><div className="d">Nothing here.</div></div>}
            {items.map(n => (
              <div key={n.id} className={`nc-item ${n.read ? "" : "unread"}`} onClick={() => openItem(n)}>
                <span className="sev-dot" style={{ marginTop: 5, background: n.read ? "var(--border-strong)" : GROUP_TONE[n.group] }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="row between" style={{ gap: 8, alignItems: "flex-start" }}>
                    <div className="nc-title">{n.title}</div>
                    <span className="faint xs" style={{ whiteSpace: "nowrap" }}>{timeAgo(n.created_at)}</span>
                  </div>
                  {n.body && <div className="nc-body">{n.body.length > 140 ? n.body.slice(0, 140) + "…" : n.body}</div>}
                  <div className="row xs" style={{ gap: 8, marginTop: 4 }}>
                    <span className="faint" style={{ textTransform: "capitalize" }}>{n.group}</span>
                    {n.route && <span className="link">Open →</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
