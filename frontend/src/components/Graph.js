import React, { useEffect, useMemo, useRef, useState } from "react";
import Icon from "./Icon";
import { Button, IconButton } from "./ui";
import { KIND_COLOR, TYPE_COLOR } from "../design/tokens";
import { navigate, entityRoute } from "../lib/router";

const KIND_LABEL = { ioc: "Indicator", campaign: "Campaign", actor: "Threat actor", malware: "Malware",
  cve: "CVE", investigation: "Investigation", observable: "Observable", asset: "Software" };

function nodeColor(n) {
  if (n.kind === "ioc" || n.kind === "observable") return TYPE_COLOR[n.ioc_type] || KIND_COLOR.ioc;
  return KIND_COLOR[n.kind] || "#8B929D";
}

// Deterministic force layout computed up front (no perpetual animation): a few
// hundred iterations of repulsion + springs + gravity. Seeded by node index so
// the same graph always lands the same way.
function layout(nodes, edges, W, H, centerId) {
  const pos = {};
  const n = nodes.length;
  nodes.forEach((nd, i) => {
    const a = (i / Math.max(n, 1)) * Math.PI * 2;
    const r = nd.id === centerId ? 0 : 120 + (i % 5) * 30;
    pos[nd.id] = { x: W / 2 + Math.cos(a) * r, y: H / 2 + Math.sin(a) * r, vx: 0, vy: 0 };
  });
  const idx = {};
  nodes.forEach(nd => { idx[nd.id] = pos[nd.id]; });
  const iters = n > 150 ? 160 : 260;
  // Ideal edge length: dense graphs pack tighter, tiny graphs don't sprawl.
  const k = Math.max(55, Math.min(130, Math.sqrt((W * H) / Math.max(n, 1)) * 0.55));
  for (let it = 0; it < iters; it++) {
    const t = 1 - it / iters;
    for (let i = 0; i < n; i++) {
      const a = pos[nodes[i].id];
      for (let j = i + 1; j < n; j++) {
        const b = pos[nodes[j].id];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.5; }
        if (d2 > 250000) continue;
        const f = (k * k) / d2;
        a.vx += dx * f * 0.05; a.vy += dy * f * 0.05;
        b.vx -= dx * f * 0.05; b.vy -= dy * f * 0.05;
      }
    }
    edges.forEach(e => {
      const a = idx[e.source], b = idx[e.target];
      if (!a || !b) return;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = (d - k) * 0.02;
      a.vx += (dx / d) * f; a.vy += (dy / d) * f;
      b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    });
    nodes.forEach(nd => {
      const p = pos[nd.id];
      p.vx += (W / 2 - p.x) * 0.004; p.vy += (H / 2 - p.y) * 0.004;
      if (nd.id === centerId) { p.vx += (W / 2 - p.x) * 0.1; p.vy += (H / 2 - p.y) * 0.1; }
      const sp = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
      const lim = 30 * t + 1;
      if (sp > lim) { p.vx = (p.vx / sp) * lim; p.vy = (p.vy / sp) * lim; }
      p.x += p.vx; p.y += p.vy;
      p.vx *= 0.6; p.vy *= 0.6;
    });
  }
  const out = {};
  Object.entries(pos).forEach(([id, p]) => { out[id] = { x: p.x, y: p.y }; });
  return out;
}

// Centre the bounding box of all nodes, leaving room for labels and the
// overlay controls; never zoom in past 1.4x on tiny graphs.
function fitView(points, W, H) {
  if (!points.length) return { x: 0, y: 0, k: 1 };
  const xs = points.map(p => p.x), ys = points.map(p => p.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
  const k = Math.min(1.4, Math.max(0.2, Math.min((W - 160) / (maxX - minX || 1), (H - 140) / (maxY - minY || 1))));
  return { k, x: W / 2 - ((minX + maxX) / 2) * k, y: H / 2 + 10 - ((minY + maxY) / 2) * k };
}

export default function Graph({ data, height = 520, centerId, onExpand, emptyText = "No relationships to show yet." }) {
  const wrapRef = useRef(null);
  const [width, setWidth] = useState(900);
  const [hiddenKinds, setHiddenKinds] = useState(new Set());
  const [hiddenEdges, setHiddenEdges] = useState(new Set());
  const [selected, setSelected] = useState(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [pos, setPos] = useState({});
  const drag = useRef(null);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => setWidth(Math.max(320, entries[0].contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, [(data?.nodes?.length || 0) >= 2]); // eslint-disable-line react-hooks/exhaustive-deps

  const nodes = useMemo(() => (data?.nodes || []).filter(n => !hiddenKinds.has(n.kind)), [data, hiddenKinds]);
  const nodeIds = useMemo(() => new Set(nodes.map(n => n.id)), [nodes]);
  const edges = useMemo(() => (data?.edges || []).filter(e => !hiddenEdges.has(e.type) && nodeIds.has(e.source) && nodeIds.has(e.target)), [data, hiddenEdges, nodeIds]);
  const kinds = useMemo(() => [...new Set((data?.nodes || []).map(n => n.kind))], [data]);
  const edgeTypes = useMemo(() => [...new Set((data?.edges || []).map(e => e.type))], [data]);

  useEffect(() => {
    const p = layout(data?.nodes || [], data?.edges || [], width, height, centerId);
    setPos(p);
    setView(fitView(Object.values(p), width, height));
  }, [data, width, height, centerId]);

  const degree = useMemo(() => {
    const d = {};
    edges.forEach(e => { d[e.source] = (d[e.source] || 0) + 1; d[e.target] = (d[e.target] || 0) + 1; });
    return d;
  }, [edges]);

  const neighbors = useMemo(() => {
    if (!selected) return null;
    const s = new Set([selected]);
    edges.forEach(e => { if (e.source === selected) s.add(e.target); if (e.target === selected) s.add(e.source); });
    return s;
  }, [selected, edges]);

  function toGraph(clientX, clientY) {
    const r = wrapRef.current.getBoundingClientRect();
    return { x: (clientX - r.left - view.x) / view.k, y: (clientY - r.top - view.y) / view.k };
  }

  function onWheel(e) {
    e.preventDefault();
    const r = wrapRef.current.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    setView(v => {
      const k = Math.min(3, Math.max(0.25, v.k * (e.deltaY < 0 ? 1.12 : 0.89)));
      return { k, x: mx - ((mx - v.x) / v.k) * k, y: my - ((my - v.y) / v.k) * k };
    });
  }
  // React's onWheel is passive; attach natively so preventDefault stops page scroll.
  useEffect(() => {
    const el = wrapRef.current?.querySelector("svg");
    if (!el) return;
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  });

  function onDown(e, nodeId) {
    e.stopPropagation();
    if (nodeId) {
      const p = toGraph(e.clientX, e.clientY);
      drag.current = { node: nodeId, dx: p.x - pos[nodeId].x, dy: p.y - pos[nodeId].y, moved: false };
    } else {
      drag.current = { pan: true, sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y, moved: false };
    }
  }
  function onMove(e) {
    const d = drag.current;
    if (!d) return;
    d.moved = true;
    if (d.pan) setView(v => ({ ...v, x: d.vx + (e.clientX - d.sx), y: d.vy + (e.clientY - d.sy) }));
    else { const p = toGraph(e.clientX, e.clientY); setPos(ps => ({ ...ps, [d.node]: { x: p.x - d.dx, y: p.y - d.dy } })); }
  }
  function onUp(e, nodeId) {
    const d = drag.current;
    drag.current = null;
    if (!d) return;
    if (!d.moved) setSelected(nodeId && !d.pan ? nodeId : null);
  }

  const toggle = (set, setter, key) => { const n = new Set(set); n.has(key) ? n.delete(key) : n.add(key); setter(n); };
  const sel = selected ? (data?.nodes || []).find(n => n.id === selected) : null;
  const selEdges = sel ? (data?.edges || []).filter(e => e.source === sel.id || e.target === sel.id) : [];
  const nodeById = useMemo(() => Object.fromEntries((data?.nodes || []).map(n => [n.id, n])), [data]);

  if (!data || !data.nodes?.length || data.nodes.length < 2) {
    return (
      <div className="graph-wrap" ref={wrapRef} style={{ height: 220, display: "grid", placeItems: "center" }}>
        <div className="faint small">{emptyText}</div>
      </div>
    );
  }

  const fit = () => setView(fitView(nodes.map(n => pos[n.id]).filter(Boolean), width, height));

  return (
    <div className="graph-wrap" ref={wrapRef} style={{ height }}>
      <div className="graph-tools">
        {kinds.map(k => (
          <button key={k} className={`chip ${hiddenKinds.has(k) ? "" : "on"}`} style={{ height: 22, fontSize: 11 }}
            onClick={() => toggle(hiddenKinds, setHiddenKinds, k)} title="Show / hide node type">
            <span className="sev-dot" style={{ background: KIND_COLOR[k] || "#8B929D" }} />{KIND_LABEL[k] || k}
          </button>
        ))}
        {edgeTypes.length > 1 && <span style={{ width: 1, background: "var(--border)", margin: "0 2px" }} />}
        {edgeTypes.length > 1 && edgeTypes.map(t => (
          <button key={t} className={`chip ${hiddenEdges.has(t) ? "" : "on"}`} style={{ height: 22, fontSize: 11 }}
            onClick={() => toggle(hiddenEdges, setHiddenEdges, t)} title="Show / hide relationship type">{t.replace(/_/g, " ")}</button>
        ))}
      </div>
      <svg width={width} height={height} className={drag.current?.pan ? "panning" : ""}
        onMouseDown={e => onDown(e, null)} onMouseMove={onMove} onMouseUp={e => onUp(e, null)} onMouseLeave={() => { drag.current = null; }}>
        <defs>
          <marker id="tf-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="#3A424D" />
          </marker>
        </defs>
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {edges.map((e, i) => {
            const a = pos[e.source], b = pos[e.target];
            if (!a || !b) return null;
            const dim = neighbors && !(neighbors.has(e.source) && neighbors.has(e.target));
            const hot = selected && (e.source === selected || e.target === selected);
            const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
            const rb = 8 + Math.min(10, (degree[e.target] || 0));
            const ex = b.x - (dx / d) * (rb + 3), ey = b.y - (dy / d) * (rb + 3);
            return (
              <g key={i} opacity={dim ? 0.12 : 1}>
                <line x1={a.x} y1={a.y} x2={ex} y2={ey} stroke={hot ? "#D7A83D" : "#2A313A"} strokeWidth={hot ? 1.6 : 1} markerEnd="url(#tf-arrow)" />
                {(hot || view.k > 1.4) && <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4} textAnchor="middle" fontSize={9} fill="#8B929D" fontFamily="Inter, system-ui, sans-serif">{e.type.replace(/_/g, " ")}</text>}
              </g>
            );
          })}
          {nodes.map(n => {
            const p = pos[n.id];
            if (!p) return null;
            const r = n.id === centerId ? 13 : 7 + Math.min(10, (degree[n.id] || 0));
            const c = nodeColor(n);
            const dim = neighbors && !neighbors.has(n.id);
            const isSel = n.id === selected;
            const showLabel = isSel || n.id === centerId || n.kind !== "ioc" || view.k > 1.15 || nodes.length < 40 || (neighbors && neighbors.has(n.id));
            return (
              <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={dim ? 0.18 : 1} style={{ cursor: "pointer" }}
                onMouseDown={e => onDown(e, n.id)} onMouseUp={e => { e.stopPropagation(); onUp(e, n.id); }}
                onDoubleClick={() => navigate(entityRoute(n.kind, n.ref))}>
                {(isSel || n.id === centerId) && <circle r={r + 5} fill="none" stroke={isSel ? "#D7A83D" : c} strokeOpacity={0.5} strokeWidth={1.5} />}
                <circle r={r} fill="#0D0F12" stroke={c} strokeWidth={n.kind === "ioc" ? 1.8 : 2.4} />
                <circle r={r * 0.45} fill={c} opacity={0.85} />
                {showLabel && (
                  <text y={r + 13} textAnchor="middle" fontSize={10.5 / Math.min(1, Math.max(view.k, 0.45))} fill={isSel ? "#F5F7FA" : "#C4C9D1"}
                    fontFamily={n.kind === "ioc" ? "JetBrains Mono, ui-monospace, monospace" : "Inter, system-ui, sans-serif"} style={{ pointerEvents: "none" }}>
                    {String(n.label || "").length > 28 ? String(n.label).slice(0, 26) + "…" : n.label}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>
      <div className="graph-zoom">
        <IconButton icon="plus" size="sm" title="Zoom in" onClick={() => setView(v => ({ ...v, k: Math.min(3, v.k * 1.2) }))} />
        <IconButton icon="minus" size="sm" title="Zoom out" onClick={() => setView(v => ({ ...v, k: Math.max(0.25, v.k / 1.2) }))} />
        <IconButton icon="maximize" size="sm" title="Fit to view" onClick={fit} />
      </div>
      <div className="graph-legend">
        <span>{nodes.length} nodes · {edges.length} edges{data.truncated ? " · truncated" : ""}</span>
        <span className="faint">scroll to zoom · drag to pan · double-click to open</span>
      </div>
      {sel && (
        <div className="graph-inspect">
          <div className="panel-h bordered" style={{ padding: "10px 12px" }}>
            <div className="row" style={{ gap: 6, minWidth: 0 }}>
              <span className="sev-dot" style={{ background: nodeColor(sel) }} />
              <span className="xs faint">{KIND_LABEL[sel.kind] || sel.kind}{sel.ioc_type ? ` · ${sel.ioc_type}` : ""}</span>
            </div>
            <IconButton icon="x" size="sm" title="Close" onClick={() => setSelected(null)} />
          </div>
          <div style={{ padding: "10px 12px" }}>
            <div className={sel.kind === "ioc" ? "mono" : "strong"} style={{ color: "var(--text)", wordBreak: "break-all", marginBottom: 8 }}>{sel.label}</div>
            {sel.confidence !== undefined && sel.confidence !== null && <div className="xs muted" style={{ marginBottom: 8 }}>Confidence {sel.confidence}</div>}
            <div className="row" style={{ gap: 6, marginBottom: 12 }}>
              <Button size="sm" variant="primary" icon="arrowRight" onClick={() => navigate(entityRoute(sel.kind, sel.ref))}>Open</Button>
              {onExpand && sel.kind === "ioc" && <Button size="sm" icon="graph" onClick={() => onExpand(sel)}>Expand</Button>}
            </div>
            <div className="eyebrow" style={{ marginBottom: 6 }}>Relationships ({selEdges.length})</div>
            {selEdges.slice(0, 40).map((e, i) => {
              const out = e.source === sel.id;
              const other = nodeById[out ? e.target : e.source];
              return (
                <div key={i} className="row small" style={{ gap: 6, padding: "4px 0", cursor: "pointer" }} onClick={() => setSelected(other?.id)}>
                  <Icon name={out ? "arrowRight" : "chevronLeft"} size={12} style={{ color: "var(--text-4)" }} />
                  <span className="faint xs" style={{ minWidth: 70 }}>{e.type.replace(/_/g, " ")}</span>
                  <span className="trunc hover-link" style={{ color: "var(--text-2)" }}>{other?.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
