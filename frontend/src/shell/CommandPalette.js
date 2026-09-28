import React, { useEffect, useMemo, useRef, useState } from "react";
import Icon from "../components/Icon";
import { TypeBadge, SevBadge, useDebounced } from "../components/ui";
import { apiJSON } from "../lib/api";
import { navigate, entityRoute, enc } from "../lib/router";
import { detectType, refang } from "../lib/format";
import { useSession, recentEntities, recentSearches, pushRecentSearch } from "../lib/session";
import { flatNav } from "./nav";

const ACTIONS = [
  { id: "add-ioc", label: "Add IOC", icon: "plus", to: "/iocs/new", data: true, kw: "new indicator create" },
  { id: "new-inv", label: "Create Investigation", icon: "briefcase", to: "/workspace", query: { new: "1" }, data: true, kw: "workspace case" },
  { id: "bulk", label: "Run Bulk Lookup", icon: "layers", to: "/osint/bulk", kw: "validate enrich many" },
  { id: "osint", label: "Open OSINT Toolkit", icon: "radar", to: "/osint", kw: "tools dns whois" },
  { id: "import", label: "Import IOCs (STIX / TAXII / MISP / CSV)", icon: "upload", to: "/iocs/import", data: true, kw: "stix taxii misp csv" },
  { id: "export", label: "Export STIX bundle / TAXII", icon: "download", to: "/iocs/export", data: true, kw: "stix taxii opencti" },
  { id: "cve-lookup", label: "Multi-source CVE lookup", icon: "shieldAlert", to: "/cve", query: { tab: "lookup" }, kw: "nvd epss kev" },
  { id: "query", label: "Build a KQL / SPL query", icon: "code", to: "/query", kw: "detection sentinel splunk" },
  { id: "advisory", label: "Generate advisory", icon: "megaphone", to: "/advisories", data: true, kw: "email brief" },
];

export default function CommandPalette({ onClose }) {
  const { can } = useSession();
  const [q, setQ] = useState("");
  const [res, setRes] = useState(null);
  const [loading, setLoading] = useState(false);
  const [idx, setIdx] = useState(0);
  const dq = useDebounced(q.trim(), 180);
  const listRef = useRef(null);

  useEffect(() => {
    if (dq.length < 2) { setRes(null); return; }
    let alive = true;
    setLoading(true);
    apiJSON(`/v2/search?q=${enc(dq)}&limit=5`).then(d => { if (alive) setRes(d); }).catch(() => { if (alive) setRes(null); })
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [dq]);

  const items = useMemo(() => {
    const out = [];
    const ql = q.trim().toLowerCase();
    const add = (group, it) => out.push({ group, ...it });
    const hasData = can("data.workspace");
    const val = refang(q.trim());
    const t = q.trim() ? detectType(q) : null;

    if (q.trim()) {
      if (t === "CVE") add("Jump to", { key: "cve-jump", icon: "shieldAlert", label: <span>Open <span className="mono">{val.toUpperCase()}</span></span>, meta: "CVE intelligence", run: () => navigate(`/cve/${enc(val.toUpperCase())}`) });
      else if (t && hasData) add("Jump to", { key: "ent-jump", icon: "crosshair", label: <span>Open entity <span className="mono">{val}</span></span>, meta: t, run: () => navigate(`/observable/${enc(val)}`) });
      add("Jump to", { key: "search-all", icon: "search", label: <span>Search everything for “{q.trim()}”</span>, meta: "Enter", run: () => { pushRecentSearch(q.trim()); navigate("/search", { q: q.trim() }); } });
    }

    const g = res?.groups || {};
    (g.iocs || []).forEach(r => add("Indicators", { key: `ioc-${r.id}`, icon: "crosshair", label: <span className="mono trunc">{r.value}</span>, badge: <TypeBadge type={r.type} />, meta: `conf ${r.confidence}`, run: () => navigate(entityRoute("ioc", r.id)) }));
    (g.cves || []).forEach(r => add("CVEs", { key: `cve-${r.cve_id}`, icon: "shieldAlert", label: <span className="mono">{r.cve_id}</span>, badge: <SevBadge severity={r.severity} score={r.cvss_score} />, meta: r.asset_name || "", run: () => navigate(entityRoute("cve", r.cve_id)) }));
    (g.software || []).forEach(r => add("Software", { key: `sw-${r.id}`, icon: "package", label: r.name, meta: `${r.cve_count} CVEs`, run: () => navigate(entityRoute("software", r.id)) }));
    (g.actors || []).forEach(r => add("Threat actors", { key: `ac-${r.name}`, icon: "skull", label: r.name, meta: `${r.campaigns} campaign(s)`, run: () => navigate(entityRoute("actor", r.name)) }));
    (g.malware || []).forEach(r => add("Malware", { key: `mw-${r.name}`, icon: "bug", label: r.name, meta: `${r.iocs} IOCs`, run: () => navigate(entityRoute("malware", r.name)) }));
    (g.campaigns || []).forEach(r => add("Campaigns", { key: `cp-${r.id}`, icon: "flag", label: r.name, meta: `${r.ioc_count} IOCs`, run: () => navigate(entityRoute("campaign", r.id)) }));
    (g.investigations || []).forEach(r => add("Investigations", { key: `inv-${r.id}`, icon: "briefcase", label: r.name, meta: r.key, run: () => navigate(entityRoute("investigation", r.id)) }));
    (g.notes || []).forEach(r => add("Notes", { key: `note-${r.id}`, icon: "note", label: r.title || (r.snippet || "").slice(0, 60), meta: "note", run: () => navigate(r.investigation_id ? `/investigations/${enc(r.investigation_id)}` : "/workspace", r.investigation_id ? { tab: "notes" } : { tab: "notes" }) }));

    if (!q.trim()) {
      recentEntities().forEach(r => add("Recent", { key: `re-${r.kind}-${r.ref}`, icon: r.kind === "cve" ? "shieldAlert" : r.kind === "investigation" ? "briefcase" : "clock", label: <span className={r.kind === "ioc" ? "mono" : ""}>{r.label}</span>, meta: r.kind, run: () => navigate(entityRoute(r.kind, r.ref)) }));
      recentSearches().forEach(s => add("Recent searches", { key: `rs-${s}`, icon: "search", label: s, run: () => setQ(s) }));
    }

    ACTIONS.filter(a => (!a.data || hasData) && (!ql || a.label.toLowerCase().includes(ql) || a.kw.includes(ql)))
      .forEach(a => add("Actions", { key: a.id, icon: a.icon, label: a.label, run: () => navigate(a.to, a.query) }));
    flatNav().filter(n => (!n.cap || can(n.cap)) && (!ql || n.label.toLowerCase().includes(ql)))
      .slice(0, ql ? 6 : 0).forEach(n => add("Go to", { key: `nav-${n.id}`, icon: n.icon, label: n.label, meta: n.sec, run: () => navigate(n.to) }));
    return out;
  }, [q, res, can]);

  useEffect(() => { setIdx(0); }, [q, res]);
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-i="${idx}"]`);
    if (el) el.scrollIntoView({ block: "nearest" });
  }, [idx]);

  function onKey(e) {
    if (e.key === "Escape") { e.preventDefault(); onClose(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); setIdx(i => Math.min(items.length - 1, i + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setIdx(i => Math.max(0, i - 1)); }
    else if (e.key === "Enter") {
      e.preventDefault();
      const it = items[idx];
      if (it) { if (q.trim()) pushRecentSearch(q.trim()); it.run(); if (!it.key.startsWith("rs-")) onClose(); }
    }
  }

  let lastGroup = null;
  return (
    <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }} style={{ paddingTop: "12vh" }}>
      <div className="cmdk" role="dialog" aria-label="Command palette">
        <div className="cmdk-in">
          <Icon name="search" size={16} />
          <input autoFocus value={q} onChange={e => setQ(e.target.value)} onKeyDown={onKey} spellCheck={false}
            placeholder="Search IOCs, CVEs, domains, hashes, actors, campaigns — or type a command" />
          {loading && <span className="spinner" />}
          <kbd>Esc</kbd>
        </div>
        <div className="cmdk-list" ref={listRef}>
          {items.length === 0 && <div className="state"><div className="d">{dq.length >= 2 && !loading ? "No matches." : "Type to search across the platform."}</div></div>}
          {items.map((it, i) => {
            const header = it.group !== lastGroup ? <div className="cmdk-group">{it.group}</div> : null;
            lastGroup = it.group;
            return (
              <React.Fragment key={it.key}>
                {header}
                <div data-i={i} className={`cmdk-item ${i === idx ? "on" : ""}`} onMouseMove={() => setIdx(i)}
                  onClick={() => { if (q.trim()) pushRecentSearch(q.trim()); it.run(); if (!it.key.startsWith("rs-")) onClose(); }}>
                  <span className="ci-ico"><Icon name={it.icon} size={13} /></span>
                  <span className="ci-main"><span className="trunc">{it.label}</span>{it.badge}</span>
                  {it.meta && <span className="ci-meta">{it.meta}</span>}
                </div>
              </React.Fragment>
            );
          })}
          {res?.limited && q.trim() && <div className="faint xs" style={{ padding: "8px 10px" }}>Explorer accounts search tools and public sources only — the IOC database needs full access.</div>}
        </div>
        <div className="cmdk-foot">
          <span><kbd>↑</kbd> <kbd>↓</kbd> navigate</span><span><kbd>Enter</kbd> open</span><span><kbd>Ctrl K</kbd> toggle</span>
        </div>
      </div>
    </div>
  );
}
