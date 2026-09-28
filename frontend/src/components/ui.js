import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import Icon from "./Icon";
import { copy as copyText, confBand, fmtNum, normSev } from "../lib/format";
import { SEV_COLOR, TYPE_COLOR } from "../design/tokens";

// ── Hooks ─────────────────────────────────────────────────────────────────────
export function useClickOutside(ref, onOutside, active = true) {
  useEffect(() => {
    if (!active) return;
    const h = e => { if (ref.current && !ref.current.contains(e.target)) onOutside(e); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [ref, onOutside, active]);
}

export function useHotkey(combo, handler, deps = []) {
  useEffect(() => {
    const h = e => {
      const k = e.key.toLowerCase();
      const want = combo.toLowerCase().split("+");
      const key = want[want.length - 1];
      const mod = want.includes("mod");
      if (mod && !(e.ctrlKey || e.metaKey)) return;
      if (!mod && (e.ctrlKey || e.metaKey || e.altKey)) return;
      if (k !== key) return;
      if (!mod) {
        const t = e.target;
        if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
      }
      e.preventDefault();
      handler(e);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, deps); // eslint-disable-line react-hooks/exhaustive-deps
}

export function useDebounced(value, ms = 250) {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

export function useLocal(key, initial) {
  const [v, setV] = useState(() => {
    try { const s = localStorage.getItem(key); return s === null ? initial : JSON.parse(s); } catch { return initial; }
  });
  const set = useCallback(next => {
    setV(prev => {
      const val = typeof next === "function" ? next(prev) : next;
      try { localStorage.setItem(key, JSON.stringify(val)); } catch {}
      return val;
    });
  }, [key]);
  return [v, set];
}

// ── Buttons ───────────────────────────────────────────────────────────────────
export function Button({ variant, size, icon, iconRight, children, className = "", loading, ...rest }) {
  const cls = ["btn", variant, size, className].filter(Boolean).join(" ");
  return (
    <button className={cls} {...rest} disabled={rest.disabled || loading}>
      {loading ? <span className="spinner" style={{ width: 12, height: 12 }} /> : icon && <Icon name={icon} size={size === "xs" ? 12 : 14} />}
      {children}
      {iconRight && <Icon name={iconRight} size={14} />}
    </button>
  );
}

export function IconButton({ icon, title, badge, size, className = "", ...rest }) {
  return (
    <button className={`iconbtn ${size || ""} ${className}`} title={title} aria-label={title} {...rest}>
      <Icon name={icon} size={size === "sm" ? 14 : 16} />
      {badge ? <span className="dot-badge">{badge > 99 ? "99+" : badge}</span> : null}
    </button>
  );
}

export function CopyButton({ value, size = "sm" }) {
  const [done, setDone] = useState(false);
  return (
    <IconButton icon={done ? "check" : "copy"} size={size} title={done ? "Copied" : "Copy"}
      onClick={e => { e.stopPropagation(); copyText(value); setDone(true); setTimeout(() => setDone(false), 1200); }} />
  );
}

// ── Badges ────────────────────────────────────────────────────────────────────
export function Badge({ tone, children, dot, outline, title, style }) {
  return (
    <span className={`badge ${tone || ""} ${outline ? "outline" : ""}`} title={title} style={style}>
      {dot && <span className="dot" />}{children}
    </span>
  );
}

const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "None" };
export function SevBadge({ severity, score, showScore = true }) {
  const s = normSev(severity, score);
  return (
    <Badge tone={s} dot>
      {SEV_LABEL[s]}{showScore && score ? <span className="num" style={{ opacity: .8, fontWeight: 500 }}>{Number(score).toFixed(1)}</span> : null}
    </Badge>
  );
}

export function TypeBadge({ type }) {
  return (
    <span className="badge type" title={type}>
      <span className="sev-dot" style={{ background: TYPE_COLOR[type] || "#8B929D", width: 6, height: 6 }} />{type || "?"}
    </span>
  );
}

export function TLPBadge({ tlp }) {
  if (!tlp) return null;
  return <span className={`badge tlp-${String(tlp).toLowerCase()}`}>TLP:{tlp}</span>;
}

export function Conf({ value }) {
  const v = Number(value) || 0;
  const c = SEV_COLOR[confBand(v)];
  return (
    <span className="conf" title={`Confidence ${v}/100`}>
      <span className="conf-bar"><i style={{ width: `${Math.min(100, v)}%`, background: c }} /></span>
      <span className="num" style={{ color: "var(--text-2)", minWidth: 20 }}>{v}</span>
    </span>
  );
}

export function StatusBadge({ status }) {
  if (status === "false_positive") return <Badge tone="high" outline>False positive</Badge>;
  if (status === "expired") return <Badge tone="low" outline>Expired</Badge>;
  return <Badge tone="success" dot>Active</Badge>;
}

export function Mono({ children, copy, title, className = "", style }) {
  return (
    <span className={`mono ${className}`} title={title || (typeof children === "string" ? children : undefined)}
      style={{ color: "var(--text)", display: "inline-flex", alignItems: "center", gap: 4, minWidth: 0, ...style }}>
      <span className="trunc">{children}</span>
      {copy && <CopyButton value={copy} />}
    </span>
  );
}

// ── Layout ────────────────────────────────────────────────────────────────────
export function PageHeader({ title, sub, eyebrow, actions, children }) {
  return (
    <div className="page-head">
      <div style={{ minWidth: 0 }}>
        {eyebrow && <div className="eyebrow" style={{ marginBottom: 4 }}>{eyebrow}</div>}
        <h1 className="page-title">{title}</h1>
        {sub && <div className="page-sub">{sub}</div>}
        {children}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function Panel({ title, sub, actions, children, footer, tight, bordered, className = "", style, bodyStyle, id }) {
  return (
    <section className={`panel ${className}`} style={style} id={id}>
      {(title || actions) && (
        <div className={`panel-h ${bordered ? "bordered" : ""}`}>
          <div className="panel-t">{title}{sub && <span className="sub">{sub}</span>}</div>
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      <div className={`panel-b ${tight ? "tight" : ""}`} style={bodyStyle}>{children}</div>
      {footer && <div className="panel-f">{footer}</div>}
    </section>
  );
}

export function Tabs({ tabs, value, onChange, style }) {
  return (
    <div className="tabs" role="tablist" style={style}>
      {tabs.filter(Boolean).map(t => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={`tab ${value === t.id ? "on" : ""}`}
          onClick={() => onChange(t.id)}>
          {t.icon && <Icon name={t.icon} size={14} />}{t.label}
          {t.count !== undefined && t.count !== null && <span className="n num">{fmtNum(t.count)}</span>}
        </button>
      ))}
    </div>
  );
}

export function Segmented({ options, value, onChange }) {
  return (
    <div className="seg" role="radiogroup">
      {options.map(o => {
        const [id, label] = Array.isArray(o) ? o : [o, o];
        return <button key={id} role="radio" aria-checked={value === id} className={value === id ? "on" : ""} onClick={() => onChange(id)}>{label}</button>;
      })}
    </div>
  );
}

export function SearchInput({ value, onChange, placeholder, autoFocus, style, onKeyDown, inputRef }) {
  return (
    <div className="search-box" style={style}>
      <Icon name="search" size={14} />
      <input ref={inputRef} className="input" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        autoFocus={autoFocus} onKeyDown={onKeyDown} spellCheck={false} />
    </div>
  );
}

export function Field({ label, hint, children, style }) {
  return (
    <div className="field" style={style}>
      {label && <label>{label}</label>}
      {children}
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Select({ value, onChange, options, style, className = "" }) {
  return (
    <select className={`select ${className}`} value={value} onChange={e => onChange(e.target.value)} style={style}>
      {options.map(o => {
        const [v, l] = Array.isArray(o) ? o : [o, o];
        return <option key={v} value={v}>{l}</option>;
      })}
    </select>
  );
}

export function Callout({ tone, icon, children, style }) {
  const ico = icon || (tone === "error" ? "alert" : tone === "warn" ? "alert" : tone === "ok" ? "check" : "info");
  return <div className={`callout ${tone || ""}`} style={style}><Icon name={ico} size={15} style={{ marginTop: 1 }} /><div style={{ minWidth: 0 }}>{children}</div></div>;
}

// ── States ────────────────────────────────────────────────────────────────────
export function Skeleton({ w = "100%", h = 12, style }) {
  return <div className="skel" style={{ width: w, height: h, ...style }} />;
}

export function SkeletonRows({ rows = 8, cols = 5 }) {
  return (
    <div style={{ padding: "6px 16px" }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="row" style={{ height: 36, gap: 16 }}>
          {Array.from({ length: cols }).map((__, j) => (
            <Skeleton key={j} w={j === 0 ? "28%" : `${10 + ((i * 7 + j * 13) % 14)}%`} h={10} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ icon = "inbox", title, desc, action }) {
  return (
    <div className="state">
      <div className="ico"><Icon name={icon} size={18} /></div>
      {title && <div className="t">{title}</div>}
      {desc && <div className="d">{desc}</div>}
      {action && <div style={{ marginTop: 6 }}>{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, title = "Couldn't load this" }) {
  const locked = error && error.status === 403;
  return (
    <div className="state error">
      <div className="ico"><Icon name={locked ? "lock" : "alert"} size={18} /></div>
      <div className="t">{locked ? "Not available for your account" : title}</div>
      <div className="d">{error?.message || String(error || "Unknown error")}</div>
      {onRetry && !locked && <Button size="sm" icon="refresh" onClick={() => onRetry()} style={{ marginTop: 6 }}>Retry</Button>}
    </div>
  );
}

export function Loading({ label = "Loading" }) {
  return <div className="state"><span className="spinner" /><div className="d">{label}</div></div>;
}

// ── Overlays ──────────────────────────────────────────────────────────────────
export function Modal({ title, onClose, children, footer, wide }) {
  useEffect(() => {
    const h = e => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal ${wide ? "wide" : ""}`} role="dialog" aria-modal="true">
        <div className="modal-h"><h3>{title}</h3><IconButton icon="x" size="sm" title="Close" onClick={onClose} /></div>
        <div className="modal-b">{children}</div>
        {footer && <div className="modal-f">{footer}</div>}
      </div>
    </div>
  );
}

export function Menu({ trigger, items, align = "right", width }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useClickOutside(ref, () => setOpen(false), open);
  return (
    <div ref={ref} style={{ position: "relative", display: "inline-flex" }} onClick={e => e.stopPropagation()}>
      {trigger(() => setOpen(o => !o), open)}
      {open && (
        <div className="popover menu" style={{ top: "calc(100% + 4px)", [align]: 0, minWidth: width }}>
          {items.filter(Boolean).map((it, i) => it === "sep" ? <div key={i} className="menu-sep" /> : (
            <button key={i} className="menu-item" onClick={() => { setOpen(false); it.onClick(); }}
              style={it.danger ? { color: "var(--critical)" } : undefined} disabled={it.disabled}>
              {it.icon && <Icon name={it.icon} size={14} />}{it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Pagination ────────────────────────────────────────────────────────────────
export function Pagination({ total, limit, offset, onChange, onLimit }) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="row" style={{ gap: 10 }}>
      <span className="num">{total ? `${fmtNum(offset + 1)}–${fmtNum(Math.min(offset + limit, total))} of ${fmtNum(total)}` : "0 results"}</span>
      {onLimit && <Select value={String(limit)} onChange={v => onLimit(Number(v))} options={[["25", "25 / page"], ["50", "50 / page"], ["100", "100 / page"], ["200", "200 / page"]]} style={{ height: 24, fontSize: 11.5 }} />}
      <div className="row" style={{ gap: 2 }}>
        <IconButton icon="chevronLeft" size="sm" title="Previous page" disabled={page <= 1} onClick={() => onChange(Math.max(0, offset - limit))} />
        <span className="num" style={{ minWidth: 56, textAlign: "center" }}>{page} / {pages}</span>
        <IconButton icon="chevronRight" size="sm" title="Next page" disabled={page >= pages} onClick={() => onChange(offset + limit)} />
      </div>
    </div>
  );
}

// ── Sortable table header ─────────────────────────────────────────────────────
export function Th({ id, label, sort, dir, onSort, className = "", style, title }) {
  const sortable = !!onSort && !!id;
  const active = sortable && sort === id;
  return (
    <th className={`${className} ${sortable ? "sortable" : ""} ${active ? "sorted" : ""}`} style={style} title={title}
      onClick={sortable ? () => onSort(id) : undefined}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
        {label}
        {active && <Icon name={dir === "asc" ? "arrowUp" : "arrowDown"} size={11} />}
      </span>
    </th>
  );
}

// ── Toasts ────────────────────────────────────────────────────────────────────
const ToastCtx = createContext({ push: () => {} });
export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const push = useCallback((msg, tone = "info") => {
    const id = Math.random().toString(36).slice(2);
    setItems(p => [...p, { id, msg, tone }]);
    setTimeout(() => setItems(p => p.filter(t => t.id !== id)), tone === "error" ? 6000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={{ push }}>
      {children}
      <div className="toasts" aria-live="polite">
        {items.map(t => (
          <div key={t.id} className={`toast ${t.tone}`}>
            <Icon name={t.tone === "error" ? "alert" : t.tone === "ok" ? "check" : "info"} size={15}
              style={{ color: t.tone === "error" ? "var(--critical)" : t.tone === "ok" ? "var(--success)" : "var(--text-3)", marginTop: 1 }} />
            <div style={{ flex: 1 }}>{t.msg}</div>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
export function useToast() { return useContext(ToastCtx).push; }

// ── KPI tile ──────────────────────────────────────────────────────────────────
// `upIsBad`: for exposure counts (unpatched, KEV) a rise is coloured red; for
// neutral volume counts the arrow alone carries the direction.
export function KPI({ label, value, sub, delta, deltaLabel, upIsBad = false, spark, sparkColor, onClick, tone, title }) {
  let dcls = "delta-flat", dicon = null;
  if (delta !== null && delta !== undefined && delta !== 0) {
    const up = delta > 0;
    if (upIsBad) dcls = up ? "delta-up" : "delta-down";
    dicon = up ? "arrowUp" : "arrowDown";
  }
  return (
    <div className={`kpi ${onClick ? "clickable" : ""}`} onClick={onClick} title={title} role={onClick ? "button" : undefined} tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? e => { if (e.key === "Enter") onClick(); } : undefined}>
      <div className="kpi-l">{tone && <span className="sev-dot" style={{ background: tone }} />}{label}</div>
      <div className="kpi-row">
        <div className="kpi-v">{typeof value === "number" ? fmtNum(value) : value ?? "—"}</div>
        {spark && spark.length > 1 && <SparkInline data={spark} color={sparkColor} />}
      </div>
      <div className="kpi-d">
        {dicon && <span className={dcls} style={{ display: "inline-flex", alignItems: "center", gap: 2 }}><Icon name={dicon} size={11} />{Math.abs(delta)}%</span>}
        {delta === 0 && <span className="delta-flat">0%</span>}
        <span>{deltaLabel || sub || " "}</span>
      </div>
    </div>
  );
}

function SparkInline({ data, color = "#8B929D", w = 72, h = 26 }) {
  const max = Math.max(...data, 1), min = Math.min(...data, 0);
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - 2 - ((v - min) / (max - min || 1)) * (h - 4)]);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  return (
    <svg width={w} height={h} style={{ flexShrink: 0, overflow: "visible" }} aria-hidden>
      <path d={`${d} L${w},${h} L0,${h} Z`} fill={color} opacity={0.12} />
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
