import React, { useState } from "react";
import { apiJSON } from "../lib/api";
import { safeUrl } from "../lib/safe";
import { Badge, Button, Callout, CopyButton, Field, PageHeader, Panel, Segmented, Select, Tabs } from "../components/ui";
import Icon from "../components/Icon";

const TACTICS = ["", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Command & Control", "Impact"];
const EXAMPLES = {
  kql: ["PowerShell downloading a file with Invoke-WebRequest, spawned from an Office app", "A new local administrator was added outside business hours", "Rare parent-child process pairs on servers"],
  spl: ["More than 10 failed logins in 5 minutes from one IP, then a success", "Outbound DNS to newly registered domains", "A service account logging in interactively"],
};
const SEV_TONE = { Critical: "critical", High: "high", Medium: "medium", Low: "low" };
const confTone = c => (c >= 80 ? "success" : c >= 60 ? "high" : "low");

function Bullets({ title, items, tone }) {
  if (!items || !items.length) return null;
  return (
    <Panel title={title}>
      <ul className="bullets" style={tone ? { "--bullet": `var(--${tone})` } : undefined}>{items.map((t, i) => <li key={i}>{t}</li>)}</ul>
    </Panel>
  );
}

function Builder({ qt }) {
  const [useCase, setUseCase] = useState("");
  const [context, setContext] = useState("");
  const [tactic, setTactic] = useState("");
  const [res, setRes] = useState(null);
  const [v, setV] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function generate() {
    if (!useCase.trim()) return;
    setBusy(true); setErr(""); setRes(null); setV(0);
    try { setRes(await apiJSON("/query-gen/generate", { method: "POST", body: { use_case: useCase, query_type: qt, context, tactic_hint: tactic } })); }
    catch (e) { setErr(e.message); }
    setBusy(false);
  }
  const variant = res?.queries?.[v];
  const tables = res && (res.required_tables || res.required_indexes);
  return (
    <div className="stack" style={{ gap: 20 }}>
      <Panel>
        <Field label="What do you want to detect?">
          <textarea className="textarea" rows={4} value={useCase} onChange={e => setUseCase(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) generate(); }}
            placeholder="Describe the behaviour in plain language. Mention what to flag and what to exclude." />
        </Field>
        <div className="row wrap" style={{ gap: 8, marginTop: -4, marginBottom: 16 }}>
          <span className="small faint">Try:</span>
          {EXAMPLES[qt].map(x => <button key={x} className="chip" onClick={() => setUseCase(x)}>{x}</button>)}
        </div>
        <div className="grid g2" style={{ gap: 16 }}>
          <Field label="MITRE tactic" hint="Optional. Narrows the technique TFII maps it to."><Select value={tactic} onChange={setTactic} options={TACTICS.map(t => [t, t || "Any"])} style={{ width: "100%" }} /></Field>
          <Field label="Your environment" hint="Optional. For example: Azure AD P2, Defender for Endpoint, no EDR on servers."><input className="input" value={context} onChange={e => setContext(e.target.value)} /></Field>
        </div>
        <div className="row" style={{ gap: 12 }}>
          <Button variant="primary" size="lg" icon="sparkle" loading={busy} disabled={!useCase.trim()} onClick={generate}>Generate detection queries</Button>
          <span className="small faint">or press Ctrl + Enter</span>
        </div>
      </Panel>

      {err && <Callout tone="error">{err}</Callout>}
      {busy && <Panel><div className="state"><span className="spinner" /><div className="t">Writing detection queries…</div><div className="d">Building three variants: high fidelity, balanced and threat hunting.</div></div></Panel>}

      {res && (
        <div className="stack" style={{ gap: 16 }}>
          <Tabs value={String(v)} onChange={x => setV(Number(x))} tabs={(res.queries || []).map((q, i) => ({ id: String(i), label: q.label }))} style={{ marginBottom: 0 }} />
          {variant && (
            <div className="query-grid">
              <div className="stack" style={{ gap: 12 }}>
                <Panel title={<>{variant.label} {variant.severity && <Badge tone={SEV_TONE[variant.severity] || "low"} dot>{variant.severity}</Badge>}{variant.confidence ? <Badge tone={confTone(variant.confidence)} outline>{variant.confidence}% confidence</Badge> : null}</>}
                  actions={<CopyButton value={variant.query} />} tight>
                  <pre className="code" style={{ border: 0, borderRadius: 0, background: "transparent", whiteSpace: "pre-wrap", overflowWrap: "anywhere", padding: "8px 20px 16px", fontSize: 13 }}>{variant.query}</pre>
                  {variant.description && <div className="small muted" style={{ padding: "12px 20px", borderTop: "1px solid var(--hair)" }}>{variant.description}</div>}
                </Panel>
                {variant.schedule && <Callout tone="accent" icon="clock">Recommended schedule: {variant.schedule}</Callout>}
              </div>
              <div className="stack" style={{ gap: 12 }}>
                {res.mitre && (
                  <Panel title="MITRE ATT&CK">
                    <div className="mono" style={{ color: "var(--critical)", fontWeight: 600 }}>{res.mitre.technique}</div>
                    <div className="strong" style={{ marginTop: 2 }}>{res.mitre.technique_name}</div>
                    <div className="small muted" style={{ marginBottom: 8 }}>{res.mitre.tactic}</div>
                    {safeUrl(res.mitre.url) && <a className="link small" href={safeUrl(res.mitre.url)} target="_blank" rel="noreferrer">View on MITRE <Icon name="external" size={11} /></a>}
                  </Panel>
                )}
                {tables?.length > 0 && <Panel title={`Required ${qt === "kql" ? "tables" : "indexes"}`}>
                  {tables.map(t => <div key={t} className="mono small" style={{ padding: "2px 0" }}>{t}</div>)}
                  {(res.required_connectors || res.required_sourcetypes || []).map(t => <div key={t} className="xs faint" style={{ marginTop: 4 }}>via {t}</div>)}
                </Panel>}
                <Bullets title="Expect false positives from" items={res.false_positives} tone="high" />
                <Bullets title="Tuning tips" items={res.tuning_tips} />
                {res.performance && <div className="small faint" style={{ padding: "0 4px" }}>{res.performance}</div>}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Explainer({ qt }) {
  const [q, setQ] = useState("");
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  async function explain() {
    if (!q.trim()) return;
    setBusy(true); setErr(""); setRes(null);
    try { setRes(await apiJSON("/query-gen/explain", { method: "POST", body: { query: q, query_type: qt } })); } catch (e) { setErr(e.message); }
    setBusy(false);
  }
  return (
    <div className="stack" style={{ gap: 20 }}>
      <Panel>
        <Field label={`Paste a ${qt === "kql" ? "KQL" : "SPL"} query`}>
          <textarea className="textarea mono" rows={9} value={q} onChange={e => setQ(e.target.value)} spellCheck={false}
            placeholder={qt === "kql" ? "A Sentinel analytics rule, hunting query or custom detection…" : "An ES correlation search, dashboard query or custom search…"} />
        </Field>
        <div className="row" style={{ gap: 10 }}>
          <Button variant="primary" size="lg" loading={busy} disabled={!q.trim()} onClick={explain}>Explain this query</Button>
          {res && <Button variant="ghost" onClick={() => { setRes(null); setQ(""); }}>Clear</Button>}
        </div>
      </Panel>
      {err && <Callout tone="error">{err}</Callout>}
      {busy && <Panel><div className="state"><span className="spinner" /><div className="t">Reading the query…</div><div className="d">Breaking down each clause and checking it for improvements.</div></div></Panel>}
      {res && (
        <div className="stack" style={{ gap: 16 }}>
          <Panel>
            <div className="row wrap" style={{ gap: 8, marginBottom: 10 }}>
              {res.severity && <Badge tone={SEV_TONE[res.severity] || "low"} dot>{res.severity}</Badge>}
              {res.mitre?.technique && (safeUrl(res.mitre.url) ? <a className="badge violet" href={safeUrl(res.mitre.url)} target="_blank" rel="noreferrer">{res.mitre.technique}</a> : <Badge tone="violet">{res.mitre.technique}</Badge>)}
              {res.estimated_fidelity && <Badge tone="low" outline>Fidelity: {res.estimated_fidelity}</Badge>}
            </div>
            <div className="strong" style={{ fontSize: 16, lineHeight: 1.45 }}>{res.summary}</div>
            <div className="muted" style={{ marginTop: 8, lineHeight: 1.7 }}>{res.threat_description}</div>
          </Panel>
          {res.line_by_line?.length > 0 && (
            <Panel title="Line by line" tight>
              {res.line_by_line.map((l, i) => (
                <div key={i} className="explain-row"><code>{l.code}</code><div>{l.explanation}</div></div>
              ))}
            </Panel>
          )}
          <div className="grid g3">
            <Bullets title="What it catches" items={res.what_it_catches} tone="success" />
            <Bullets title="What it misses" items={res.what_it_misses} tone="high" />
            <Bullets title="False positives" items={res.false_positives} tone="critical" />
          </div>
          {res.improvements?.length > 0 && (
            <Panel title="Suggested improvements">
              <div className="stack" style={{ gap: 10 }}>
                {res.improvements.map((imp, i) => <div key={i} className="callout"><div><div className="strong" style={{ color: "var(--high)" }}>{imp.issue}</div><div className="small" style={{ marginTop: 4 }}><b style={{ color: "var(--success)" }}>Fix: </b>{imp.fix}</div></div></div>)}
              </div>
            </Panel>
          )}
        </div>
      )}
    </div>
  );
}

export default function QueryBuilder() {
  const [mode, setMode] = useState("builder");
  const [qt, setQt] = useState("kql");
  return (
    <div className="page">
      <PageHeader title="Query builder" sub="Turn a description into KQL or SPL detections, or paste a query and have it explained line by line."
        actions={<>
          <Segmented value={mode} onChange={setMode} options={[["builder", "Build"], ["explainer", "Explain"]]} />
          <Segmented value={qt} onChange={setQt} options={[["kql", "KQL · Sentinel"], ["spl", "SPL · Splunk"]]} />
        </>} />
      {mode === "builder" ? <Builder key={qt} qt={qt} /> : <Explainer key={qt} qt={qt} />}
    </div>
  );
}
