import React, { useMemo, useState } from "react";
import { fmtNum } from "../lib/format";
import { SEV_COLOR } from "../design/tokens";

export function Sparkline({ data = [], color = "#8B929D", w = 120, h = 32, fill = true }) {
  if (!data.length) return null;
  const max = Math.max(...data, 1), min = Math.min(...data, 0);
  const pts = data.map((v, i) => [(i / Math.max(1, data.length - 1)) * w, h - 2 - ((v - min) / (max - min || 1)) * (h - 4)]);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  return (
    <svg width={w} height={h} aria-hidden style={{ overflow: "visible" }}>
      {fill && <path d={`${d} L${w},${h} L0,${h} Z`} fill={color} opacity={0.1} />}
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" />
    </svg>
  );
}

// Stacked daily columns with a hover readout. `series` = [{key,label,color,values[]}]
export function StackedBars({ days, series, height = 180, onBarClick }) {
  const [hover, setHover] = useState(null);
  const totals = useMemo(() => days.map((_, i) => series.reduce((s, x) => s + (x.values[i] || 0), 0)), [days, series]);
  const max = Math.max(1, ...totals);
  const W = 1000, H = height, pad = 22;
  const bw = W / days.length;
  const ticks = [0, 0.5, 1].map(f => Math.round(max * f));
  return (
    <div style={{ position: "relative" }}>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" width="100%" height={H} style={{ display: "block" }}
        onMouseLeave={() => setHover(null)}>
        {ticks.map((t, i) => {
          const y = H - pad - (t / max) * (H - pad - 6);
          return <line key={i} x1={0} x2={W} y1={y} y2={y} stroke="#1A1F26" strokeWidth={1} vectorEffect="non-scaling-stroke" />;
        })}
        {days.map((d, i) => {
          let y = H - pad;
          return (
            <g key={d} onMouseEnter={() => setHover(i)} onClick={onBarClick ? () => onBarClick(d) : undefined}
              style={{ cursor: onBarClick ? "pointer" : "default" }}>
              <rect x={i * bw} y={0} width={bw} height={H - pad} fill={hover === i ? "rgba(255,255,255,0.03)" : "transparent"} />
              {series.map(s => {
                const v = s.values[i] || 0;
                if (!v) return null;
                const bh = (v / max) * (H - pad - 6);
                y -= bh;
                return <rect key={s.key} x={i * bw + bw * 0.18} y={y} width={bw * 0.64} height={Math.max(bh, 1)} fill={s.color}
                  opacity={hover === null || hover === i ? 0.9 : 0.45} rx={1} />;
              })}
            </g>
          );
        })}
      </svg>
      <div className="row between faint xs" style={{ marginTop: 2 }}>
        <span>{days[0]?.slice(5)}</span><span>{days[Math.floor(days.length / 2)]?.slice(5)}</span><span>{days[days.length - 1]?.slice(5)}</span>
      </div>
      <div className="faint xs num" style={{ position: "absolute", top: 0, right: 0 }}>max {fmtNum(max)}/day</div>
      {hover !== null && (
        <div className="popover" style={{ top: 8, left: `min(calc(${(hover / days.length) * 100}% + 16px), calc(100% - 190px))`, padding: "8px 10px", width: 180, pointerEvents: "none" }}>
          <div className="small strong" style={{ marginBottom: 4 }}>{days[hover]} · {fmtNum(totals[hover])}</div>
          {series.filter(s => s.values[hover]).map(s => (
            <div key={s.key} className="row between xs"><span className="row" style={{ gap: 6 }}><span className="sev-dot" style={{ background: s.color }} />{s.label}</span><span className="num">{fmtNum(s.values[hover])}</span></div>
          ))}
        </div>
      )}
    </div>
  );
}

export function Donut({ data, size = 132, thickness = 16, center, onSlice }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const r = (size - thickness) / 2, c = 2 * Math.PI * r;
  let acc = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0 }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#171B21" strokeWidth={thickness} />
      {data.filter(d => d.value > 0).map(d => {
        const len = (d.value / total) * c;
        const el = (
          <circle key={d.label} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={d.color} strokeWidth={thickness}
            strokeDasharray={`${Math.max(len - 1.5, 0.5)} ${c}`} strokeDashoffset={-acc} transform={`rotate(-90 ${size / 2} ${size / 2})`}
            style={{ cursor: onSlice ? "pointer" : "default" }} onClick={onSlice ? () => onSlice(d) : undefined}>
            <title>{`${d.label}: ${d.value}`}</title>
          </circle>
        );
        acc += len;
        return el;
      })}
      {center && (
        <>
          <text x="50%" y="48%" textAnchor="middle" fill="#F5F7FA" fontSize={20} fontWeight={600} fontFamily="Inter, system-ui, sans-serif">{center.value}</text>
          <text x="50%" y="62%" textAnchor="middle" fill="#5E6570" fontSize={10.5} fontFamily="Inter, system-ui, sans-serif">{center.label}</text>
        </>
      )}
    </svg>
  );
}

// Ranked horizontal bars; rows are clickable for drill-down.
export function BarList({ items, color = "#8B929D", onClick, max: maxProp, format = fmtNum, empty = "No data" }) {
  const max = maxProp || Math.max(1, ...items.map(i => i.value));
  if (!items.length) return <div className="faint small" style={{ padding: "8px 0" }}>{empty}</div>;
  return (
    <div className="stack" style={{ gap: 4 }}>
      {items.map(it => (
        <div key={it.label} className={onClick ? "hover-link" : ""} onClick={onClick ? () => onClick(it) : undefined}
          style={{ position: "relative", height: 26, display: "flex", alignItems: "center", cursor: onClick ? "pointer" : "default", borderRadius: 4, overflow: "hidden" }}>
          <div style={{ position: "absolute", inset: 0, width: `${(it.value / max) * 100}%`, background: it.color || color, opacity: 0.13, borderRadius: 4 }} />
          <div className="row between" style={{ position: "relative", width: "100%", padding: "0 8px", gap: 8 }}>
            <span className="row trunc small" style={{ gap: 6, color: "var(--text-2)" }}>
              {it.dot && <span className="sev-dot" style={{ background: it.color || color }} />}
              <span className="trunc">{it.label}</span>
              {it.meta && <span className="faint xs">{it.meta}</span>}
            </span>
            <span className="num small" style={{ color: "var(--text)" }}>{format(it.value)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// Horizontal severity stack, e.g. Critical/High/Medium/Low in one bar.
export function SevStack({ counts, height = 6, showLegend = false }) {
  const keys = ["critical", "high", "medium", "low"];
  const total = keys.reduce((s, k) => s + (Number(counts[k]) || 0), 0);
  return (
    <div>
      <div style={{ display: "flex", height, borderRadius: height, overflow: "hidden", background: "#171B21", gap: total ? 1 : 0 }}>
        {total > 0 && keys.map(k => counts[k] > 0 && (
          <div key={k} title={`${k}: ${counts[k]}`} style={{ width: `${(counts[k] / total) * 100}%`, background: SEV_COLOR[k] }} />
        ))}
      </div>
      {showLegend && (
        <div className="row wrap xs muted" style={{ gap: 12, marginTop: 8 }}>
          {keys.map(k => <span key={k} className="row" style={{ gap: 5 }}><span className="sev-dot" style={{ background: SEV_COLOR[k] }} /><span style={{ textTransform: "capitalize" }}>{k}</span><span className="num" style={{ color: "var(--text)" }}>{fmtNum(counts[k] || 0)}</span></span>)}
        </div>
      )}
    </div>
  );
}

// Simple vertical bars (e.g. CVEs per year), optionally stacked by severity.
export function YearBars({ rows, height = 140 }) {
  // rows: [{label, critical, high, medium, low}]
  const keys = ["low", "medium", "high", "critical"];
  const max = Math.max(1, ...rows.map(r => keys.reduce((s, k) => s + (r[k] || 0), 0)));
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 6, height, paddingTop: 16 }}>
      {rows.map(r => {
        const tot = keys.reduce((s, k) => s + (r[k] || 0), 0);
        return (
          <div key={r.label} style={{ flex: 1, minWidth: 14, display: "flex", flexDirection: "column", alignItems: "center", gap: 4, height: "100%" }} title={`${r.label}: ${tot}`}>
            <div className="faint xs num">{tot || ""}</div>
            <div style={{ flex: 1, width: "70%", display: "flex", flexDirection: "column-reverse", borderRadius: 2, overflow: "hidden" }}>
              {keys.map(k => r[k] ? <div key={k} style={{ height: `${(r[k] / max) * 100}%`, background: SEV_COLOR[k], opacity: .9 }} /> : null)}
            </div>
            <div className="faint xs num">{r.label}</div>
          </div>
        );
      })}
    </div>
  );
}
