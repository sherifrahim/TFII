import React, { useState } from "react";
import { apiJSON } from "../../lib/api";
import { timeAgo } from "../../lib/format";
import { Panel, Button, Badge, Callout, useToast } from "../../components/ui";

const TONE = { warn: "high", info: "low", ok: "success" };
const LABEL = { warn: "Check", info: "Note", ok: "Good" };

export function MailSignals({ mail }) {
  if (!mail) return null;
  const spf = mail.posture?.spf, dmarc = mail.posture?.dmarc, mx = mail.posture?.mx || [];
  const reg = mail.registration;
  return (
    <>
      {mail.signals?.length > 0 && (
        <div className="stack" style={{ gap: 6 }}>
          {mail.signals.map((s, i) => (
            <div key={i} className="row" style={{ gap: 8, alignItems: "flex-start" }}>
              <Badge tone={TONE[s.level] || "low"} outline>{LABEL[s.level] || "Note"}</Badge>
              <span className="small" style={{ minWidth: 0, overflowWrap: "anywhere" }}>{s.text}</span>
            </div>
          ))}
        </div>
      )}
      <dl className="kv" style={{ gridTemplateColumns: "110px 1fr", marginTop: 12 }}>
        <dt>Domain</dt><dd className="mono small">{mail.domain}</dd>
        {reg?.created && <><dt>Registered</dt><dd className="small">{[reg.registrar, `${reg.created} (${timeAgo(reg.created)})`].filter(Boolean).join(" · ")}</dd></>}
        {mail.posture?.checked && <>
          <dt>Mail servers</dt><dd className="mono small" style={{ overflowWrap: "anywhere" }}>{mx.length ? mx.map(m => `${m.priority ?? "?"} ${m.host}`).join(", ") : <span className="faint">none published</span>}</dd>
          <dt>SPF</dt><dd className="mono small" style={{ overflowWrap: "anywhere" }}>{spf ? spf.record : <span className="faint">not published</span>}</dd>
          <dt>DMARC</dt><dd className="small" style={{ overflowWrap: "anywhere" }}>{dmarc ? <><Badge tone={!dmarc.policy || dmarc.policy === "none" ? "low" : "success"} outline>p={dmarc.policy || "?"}</Badge>{" "}<span className="mono">{dmarc.record}</span></> : <span className="faint">not published</span>}</dd>
        </>}
      </dl>
    </>
  );
}

export function ExposureResult({ r }) {
  if (!r.found) return <div className="small">No known breach lists this address. That is not proof it was never exposed.</div>;
  return (
    <>
      <div className="small" style={{ marginBottom: 6 }}><strong>{r.count}</strong> known breach{r.count === 1 ? "" : "es"} include this address:</div>
      <div className="row wrap" style={{ gap: 4 }}>{r.breaches.map(b => <span key={b} className="tag">{b}</span>)}</div>
    </>
  );
}

const yn = v => v === true ? "yes" : v === false ? "no" : null;

export function RiskResult({ r }) {
  const score = r.fraud_score;
  const tone = score === null || score === undefined ? "low" : score >= 85 ? "critical" : score >= 60 ? "high" : "success";
  const rows = [
    ["Valid address", yn(r.valid)], ["Deliverability", r.deliverability], ["Disposable", yn(r.disposable)], ["Recent abuse", yn(r.recent_abuse)],
    ["In a data leak", yn(r.leaked)], ["Honeypot", yn(r.honeypot)], ["Spam trap", r.spam_trap && r.spam_trap !== "none" ? r.spam_trap : null],
    ["Suspect", yn(r.suspect)], ["First seen", r.first_seen], ["Domain age", r.domain_age],
  ].filter(([, v]) => v !== null && v !== undefined && v !== "");
  return (
    <>
      <div className="row" style={{ gap: 8, marginBottom: 8 }}>
        <Badge tone={tone} dot>{score === null || score === undefined ? "no score" : `fraud score ${score} / 100`}</Badge>
        <span className="xs faint">Higher means riskier. It is a provider estimate, not proof.</span>
      </div>
      <dl className="kv" style={{ gridTemplateColumns: "130px 1fr", margin: 0 }}>
        {rows.map(([k, v]) => <React.Fragment key={k}><dt className="xs">{k}</dt><dd className="xs">{String(v)}</dd></React.Fragment>)}
      </dl>
    </>
  );
}

// Uses the caller's own IPQualityScore key (free plan: 1,000 checks a month), so it is asked for on request only.
function Risk({ address }) {
  const [r, setR] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  async function run(refresh) {
    setBusy(true); setErr(null);
    try { setR(await apiJSON(`/v2/mail/risk?address=${encodeURIComponent(address)}${refresh ? "&refresh=true" : ""}`)); } catch (e) { setErr(e); }
    setBusy(false);
  }
  return (
    <div style={{ marginTop: 14 }}>
      <div className="eyebrow" style={{ marginBottom: 6 }}>Address risk</div>
      {!r && (
        <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
          <Button size="sm" loading={busy} onClick={() => run(false)}>Check address risk</Button>
          <span className="small faint" style={{ maxWidth: 520 }}>Asks IPQualityScore about this exact address using your own key (Settings → Manage API Keys; its free plan includes 1,000 checks a month). The full address is sent to them.</span>
        </div>
      )}
      {err && <div className="small" style={{ color: "var(--critical)", marginTop: 6 }}>{err.message}</div>}
      {r && <>
        <RiskResult r={r} />
        <div className="xs faint" style={{ marginTop: 6 }}>IPQualityScore · {r.cached ? `saved ${timeAgo(r.checked_at)}` : "just checked"}</div>
      </>}
    </div>
  );
}

// Breach exposure is asked for on request: the full address goes to a third party (XposedOrNot) and its free
// tier is small and shared by every user of this server.
function Exposure({ address }) {
  const [r, setR] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const toast = useToast();
  async function run(refresh) {
    setBusy(true); setErr(null);
    try {
      const d = await apiJSON(`/v2/mail/exposure?address=${encodeURIComponent(address)}${refresh ? "&refresh=true" : ""}`);
      setR(d);
      if (d.stale) toast(d.warning || "Showing a saved answer", "info");
    } catch (e) { setErr(e); }
    setBusy(false);
  }
  return (
    <div style={{ marginTop: 14 }}>
      <div className="eyebrow" style={{ marginBottom: 6 }}>Breach exposure of this mailbox</div>
      {!r && (
        <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
          <Button size="sm" loading={busy} onClick={() => run(false)}>Check breach exposure</Button>
          <span className="small faint" style={{ maxWidth: 520 }}>Sends this full address to XposedOrNot (a public breach database). Its free allowance is small and shared by everyone on this server, so it is only asked when you press the button.</span>
        </div>
      )}
      {err && <div className="small" style={{ color: "var(--critical)", marginTop: 6 }}>{err.message}</div>}
      {r && <>
        <ExposureResult r={r} />
        <div className="xs faint" style={{ marginTop: 6 }}>XposedOrNot · {r.cached ? `saved ${timeAgo(r.checked_at)}` : "just checked"}
          {r.stale ? " · limit reached, saved answer" : ""}
        </div>
      </>}
    </div>
  );
}

export default function MailPanel({ address, mail }) {
  if (!address) return null;
  return (
    <Panel title="Mail address" sub={mail?.provider_kind === "free" ? "free mailbox service" : mail?.provider_kind === "disposable" ? "disposable mail service" : "judged through its domain"}>
      {!mail
        ? <Callout tone="info">Run Re-enrich (or a lookup) to check this address's domain: reputation, age and how it is set up to send mail. TFII judges the domain, not the person: no free source rates an individual mailbox.</Callout>
        : <MailSignals mail={mail} />}
      <Risk address={address} />
      <Exposure address={address} />
    </Panel>
  );
}
