import React, { useState } from "react";
import { apiJSON } from "../../lib/api";
import { Panel, Button, Badge, Callout, useToast } from "../../components/ui";

// The host to look up for a Domain or URL indicator; "" for anything a DNS lookup does not apply to.
export function dnsHost(value, type) {
  let host = "";
  if (type === "Domain") host = String(value || "");
  else if (type === "URL") {
    try { host = new URL(String(value || "").replace(/^hxxp/i, "http")).hostname; } catch { host = ""; }
  }
  host = host.trim().replace(/\.$/, "").toLowerCase();
  return host && !/^[\d.]+$/.test(host) && !host.includes(":") ? host : "";
}

const TONE = { warn: "high", info: "low", ok: "success" };
const LABEL = { warn: "Check", info: "Note", ok: "Good" };

function Section({ title, children }) {
  return (
    <div style={{ marginTop: 14 }}>
      <div className="eyebrow" style={{ marginBottom: 6 }}>{title}</div>
      {children}
    </div>
  );
}

export function DnsResult({ d }) {
  const spf = d.spf, dmarc = d.dmarc;
  return (
    <>
      {d.signals?.length > 0 && (
        <div className="stack" style={{ gap: 6 }}>
          {d.signals.map((s, i) => (
            <div key={i} className="row" style={{ gap: 8, alignItems: "flex-start" }}>
              <Badge tone={TONE[s.level] || "low"} outline>{LABEL[s.level] || "Note"}</Badge>
              <span className="small" style={{ minWidth: 0, overflowWrap: "anywhere" }}>{s.text}</span>
            </div>
          ))}
        </div>
      )}

      <Section title={`Addresses (${d.addresses.length})`}>
        {d.addresses.length === 0 ? <div className="small faint">No A or AAAA records{d.cname?.length ? `; CNAME → ${d.cname.join(", ")}` : ""}.</div> : (
          <dl className="kv" style={{ gridTemplateColumns: "minmax(120px, auto) 1fr" }}>
            {d.addresses.map((a, i) => (
              <React.Fragment key={i}>
                <dt className="mono">{a.ip}</dt>
                <dd className="small" style={{ overflowWrap: "anywhere" }}>
                  {a.geo ? [a.geo.org || a.geo.asname, a.geo.asn, [a.geo.city, a.geo.country].filter(Boolean).join(", ")].filter(Boolean).join(" · ") : <span className="faint">no network data</span>}
                </dd>
              </React.Fragment>
            ))}
          </dl>
        )}
      </Section>

      <div className="grid g2">
        <Section title={`Name servers (${d.ns.length})`}>
          {d.ns.length ? d.ns.map(n => <div key={n} className="mono small" style={{ overflowWrap: "anywhere" }}>{n}</div>) : <div className="small faint">None returned.</div>}
        </Section>
        <Section title={`Mail servers (${d.mx.length})`}>
          {d.mx.length ? d.mx.map(m => <div key={m.host} className="mono small" style={{ overflowWrap: "anywhere" }}><span className="faint">{m.priority ?? "?"} </span>{m.host}</div>) : <div className="small faint">No MX records.</div>}
        </Section>
      </div>

      <Section title="Email authentication">
        <dl className="kv" style={{ gridTemplateColumns: "70px 1fr" }}>
          <dt>SPF</dt>
          <dd className="small" style={{ overflowWrap: "anywhere" }}>{spf ? <><span className="mono">{spf.record}</span></> : <span className="faint">not published</span>}</dd>
          <dt>DMARC</dt>
          <dd className="small" style={{ overflowWrap: "anywhere" }}>
            {dmarc ? <><Badge tone={dmarc.policy === "none" || !dmarc.policy ? "low" : "success"} outline>p={dmarc.policy || "?"}</Badge>{" "}<span className="mono">{dmarc.record}</span></> : <span className="faint">not published</span>}
          </dd>
        </dl>
      </Section>

      <div className="grid g2">
        <Section title="CAA">
          {d.caa.length ? d.caa.map((c, i) => <div key={i} className="mono small">{c.tag} {c.value}</div>) : <div className="small faint">Not published.</div>}
        </Section>
        <Section title="SOA">
          {d.soa ? <dl className="kv" style={{ gridTemplateColumns: "70px 1fr", margin: 0 }}>
            <dt className="xs">Primary</dt><dd className="mono xs" style={{ overflowWrap: "anywhere" }}>{d.soa.host}</dd>
            <dt className="xs">Contact</dt><dd className="mono xs" style={{ overflowWrap: "anywhere" }}>{d.soa.admin}</dd>
            <dt className="xs">Serial</dt><dd className="mono xs">{d.soa.serial}</dd>
          </dl> : <div className="small faint">None returned.</div>}
        </Section>
      </div>

      {d.txt.length > 0 && (
        <Section title={`TXT records (${d.txt.length})`}>
          <div className="stack" style={{ gap: 4, maxHeight: 220, overflowY: "auto" }}>
            {d.txt.map((t, i) => <div key={i} className="mono xs" style={{ overflowWrap: "anywhere" }}>{t}</div>)}
          </div>
        </Section>
      )}
    </>
  );
}

export function HistoryList({ h }) {
  if (!h.addresses.length) return <div className="small faint">VirusTotal has no earlier addresses on record for this name.</div>;
  return (
    <>
      <div className="small" style={{ marginBottom: 6 }}>
        {h.not_cdn > 0
          ? <>{h.not_cdn} of {h.total} past address{h.total === 1 ? " is" : "es are"} <strong>not a CDN</strong>: if the site moved behind a CDN later, these are the best clue to where it is really hosted.</>
          : <>All {h.total} past address{h.total === 1 ? " is" : "es are"} CDN addresses, so there is no earlier origin on record.</>}
      </div>
      <dl className="kv" style={{ gridTemplateColumns: "minmax(120px, auto) 1fr" }}>
        {h.addresses.map(a => (
          <React.Fragment key={a.ip}>
            <dt className="mono">{a.ip}</dt>
            <dd className="small" style={{ overflowWrap: "anywhere" }}>
              {a.cdn ? <Badge tone="low" outline>CDN: {a.cdn}</Badge> : <Badge tone="high" outline>not a CDN</Badge>}{" "}
              {[a.org, a.asn, a.country].filter(Boolean).join(" · ")}
              {a.last_seen && <span className="faint"> · last seen {a.last_seen}</span>}
            </dd>
          </React.Fragment>
        ))}
      </dl>
    </>
  );
}

function History({ host }) {
  const [h, setH] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  async function load() {
    setBusy(true); setErr(null);
    try { setH(await apiJSON(`/v2/dns/history?domain=${encodeURIComponent(host)}`)); } catch (e) { setErr(e); }
    setBusy(false);
  }
  return (
    <Section title="Past addresses">
      {!h && (
        <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
          <Button size="sm" loading={busy} onClick={load}>Show past addresses</Button>
          <span className="small faint" style={{ maxWidth: 520 }}>What this name resolved to earlier (VirusTotal passive DNS, uses your VirusTotal key). Useful behind a CDN.</span>
        </div>
      )}
      {err && <div className="small" style={{ color: "var(--critical)", marginTop: 6 }}>{err.message}</div>}
      {h && <HistoryList h={h} />}
    </Section>
  );
}

// Looked up on request, not automatically: NSLookup.io allows 30 requests a minute per IP, shared by every user.
export default function DnsPanel({ value, type }) {
  const host = dnsHost(value, type);
  const [d, setD] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const toast = useToast();
  if (!host) return null;

  async function run(refresh) {
    setBusy(true); setErr(null);
    try {
      const r = await apiJSON(`/v2/dns?domain=${encodeURIComponent(host)}${refresh ? "&refresh=true" : ""}`);
      setD(r);
      if (r.stale) toast(r.warning || "Showing a saved answer", "info");
    } catch (e) { setErr(e); }
    setBusy(false);
  }

  const sub = d ? `${d.source} · via ${d.resolver} resolver · ${d.cached ? (d.age_minutes ? `saved ${d.age_minutes} min ago` : "just fetched") : "just fetched"}` : "NSLookup.io";
  return (
    <Panel title="DNS records" sub={sub}
      actions={<Button size="sm" icon="search" loading={busy} onClick={() => run(!!d)}>{d ? "Refresh" : "Look up DNS records"}</Button>}>
      {err && <Callout tone="error">{err.message}</Callout>}
      {d?.stale && <Callout tone="warn" style={{ marginBottom: 10 }}>{d.warning || "This is a saved answer."}</Callout>}
      {!d && !err && (
        <div className="small faint">
          Name servers, mail servers, TXT and CAA records, and whether {host} publishes SPF and DMARC. The domain name is sent to the NSLookup.io public API.
        </div>
      )}
      {d && <DnsResult d={d} />}
      {d && <History host={host} />}
    </Panel>
  );
}
