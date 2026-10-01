import React, { useMemo, useState } from "react";
import { useApi } from "../lib/api";
import { fmtNum } from "../lib/format";
import { BarList } from "../components/charts";
import { COUNTRY_CENTER, COUNTRY_NAMES, COUNTRY_PATHS, MAP_H, MAP_W } from "../components/worldmap";
import { Callout, EmptyState, ErrorState, KPI, PageHeader, Panel, Skeleton } from "../components/ui";

// Where the IP indicators we hold are located, from AbuseIPDB and VirusTotal enrichment: a heat map plus a ranking.
export default function GeoPage() {
  const { data, error, loading, reload } = useApi("/stats/geo");
  const [hover, setHover] = useState(null);

  const byCode = useMemo(() => Object.fromEntries((data?.countries || []).map(c => [c.code, c.count])), [data]);
  const max = Math.max(1, ...(data?.countries || []).map(c => c.count));
  const shade = n => {
    if (!n) return null;
    const t = Math.log(1 + n) / Math.log(1 + max);                 // log scale: one huge country must not flatten the rest
    return `rgba(94, 234, 212, ${0.18 + t * 0.72})`;
  };
  const top = data?.countries?.[0];
  const name = c => COUNTRY_NAMES[c] || c;

  return (
    <div className="page">
      <PageHeader title="Geo intelligence" sub="Where the IP indicators in your feed are located, from AbuseIPDB and VirusTotal enrichment. A location is where an address sits, not where its operators are." />
      {error && <ErrorState error={error} onRetry={reload} />}
      {loading && !data && <Skeleton h={420} />}
      {data && data.countries.length === 0 && <EmptyState icon="globe" title="No location data yet" desc="Add IP indicators and enrich them to see where they are." />}
      {data && data.countries.length > 0 && (
        <div className="stack" style={{ gap: 18 }}>
          <div className="kpis" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))" }}>
            <KPI label="Countries" value={data.countries.length} sub="with at least one indicator" />
            <KPI label="Located IPs" value={data.located ?? data.countries.reduce((s, c) => s + c.count, 0)} sub={typeof data.total_ips === "number" ? `of ${fmtNum(data.total_ips)} IP indicators` : undefined} />
            <KPI label="Most indicators" value={top ? name(top.code) : "—"} sub={top ? `${fmtNum(top.count)} indicators` : undefined} />
          </div>

          <div className="grid g-main-side" style={{ alignItems: "start" }}>
            <Panel title="World map" sub="darker = fewer, brighter = more" bodyStyle={{ padding: "6px 14px 14px" }}>
              <div className="worldmap" onMouseLeave={() => setHover(null)}>
                <svg viewBox={`0 0 ${MAP_W} ${MAP_H}`} role="img" aria-label="World map of indicator locations">
                  {Object.entries(COUNTRY_PATHS).map(([code, d]) => {
                    const n = byCode[code];
                    return <path key={code} d={d} className={`country ${n ? "has" : ""}`} style={n ? { fill: shade(n) } : undefined} onMouseEnter={() => setHover(code)}><title>{`${name(code)}${n ? `: ${fmtNum(n)}` : ""}`}</title></path>;
                  })}
                  {(data.countries.slice(0, 8)).map(c => COUNTRY_CENTER[c.code] && (
                    <circle key={c.code} className="pulse-pin" cx={COUNTRY_CENTER[c.code][0]} cy={COUNTRY_CENTER[c.code][1]} r={3.2} />
                  ))}
                </svg>
                {hover && <div className="map-tip"><b>{name(hover)}</b><span>{byCode[hover] ? `${fmtNum(byCode[hover])} indicator${byCode[hover] === 1 ? "" : "s"}` : "none"}</span></div>}
              </div>
            </Panel>
            <Panel title="Ranking" sub="top countries">
              <BarList items={data.countries.slice(0, 15).map(c => ({ label: name(c.code), meta: c.code, value: c.count, color: "#5EEAD4" }))} />
            </Panel>
          </div>

          {typeof data.total_ips === "number" && data.unlocated > 0 && (
            <Callout tone="info">{fmtNum(data.located)} of {fmtNum(data.total_ips)} IP indicators carry a country. The other {fmtNum(data.unlocated)} came from feeds that supply none (mostly ThreatFox), so this is a partial view.</Callout>
          )}
        </div>
      )}
    </div>
  );
}
