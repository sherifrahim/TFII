import React, { useState } from "react";
import { apiJSON, api } from "../../lib/api";
import { navigate, enc } from "../../lib/router";
import { useSession } from "../../lib/session";
import { timeAgo, detectionTemplates, typeGroup } from "../../lib/format";
import { safeUrl } from "../../lib/safe";
import { geoFacts } from "../../lib/geo";
import DnsPanel from "./DnsPanel";
import MailPanel from "./MailPanel";
import {
  Panel, Button, IconButton, Badge, SevBadge, TypeBadge, Field, Callout, EmptyState, CopyButton, useToast, actionable, rowAction,
} from "../../components/ui";
import InvestigationPicker from "../../components/InvestigationPicker";
import CveLookup from "../CveLookup";
import AiPanel from "../../components/AiPanel";

// ── Indicator ───────────────────────────────────────────────────────────────
export function IndicatorOverview({ env, canEdit, reload }) {
  const { ioc, geo, related, cves } = env.overview;
  const hd = env.entity;
  const enr = ioc.enrichment || {};
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [desc, setDesc] = useState(ioc.description || "");
  const [tags, setTags] = useState((ioc.tags || []).join(", "));

  async function save() {
    try {
      await apiJSON(`/v2/iocs/${enc(ioc.id)}`, { method: "PATCH", body: { description: desc, tags: tags.split(",").map(t => t.trim()).filter(Boolean) } });
      setEditing(false); reload(true); toast("Saved", "ok");
    } catch (e) { toast(e.message, "error"); }
  }

  const vt = enr.virustotal || {}, ab = enr.abuseipdb || {}, uh = enr.urlhaus || {};
  const answered = d => d && !d.skipped && Object.keys(d).length;
  const sources = [
    { name: "VirusTotal", d: vt, rows: [["Detections", vt.total !== undefined ? `${vt.malicious ?? 0} / ${vt.total}` : null], ["Score", vt.vt_score !== undefined ? `${vt.vt_score}%` : null], ["AS owner", vt.as_owner], ["Reputation", vt.reputation]] },
    { name: "AbuseIPDB", d: ab, rows: [["Abuse score", ab.abuse_score !== undefined ? `${ab.abuse_score} / 100` : null], ["Reports", ab.total_reports], ["ISP", ab.isp], ["Usage", ab.usage_type]] },
    { name: "URLhaus", d: uh, rows: [["Listed", uh.found === undefined ? null : uh.found ? "Yes" : "No"], ["Threat", uh.threat], ["Status", uh.url_status]] },
  ].filter(s => answered(s.d));
  const relGroups = [
    ["Same campaign", related.campaign, ioc.campaign_name],
    ["Same malware family", related.malware, hd.malware_family],
    ["Same /24 subnet", related.subnet],
    ["Shared tags", related.tags],
  ].filter(([, rows]) => rows && rows.length);

  return (
    <div className="grid g-main-side">
      <div className="stack">
        <AiPanel title="AI triage" cta="Assess" hint="Why it has this score, whether it looks like a false positive, and what to do next."
          path="/v2/ai/triage" body={{ ioc: ioc.id }} />
        <Panel title="Context" actions={canEdit && !editing && <Button size="xs" variant="ghost" icon="edit" onClick={() => setEditing(true)}>Edit</Button>}>
          {editing ? (
            <>
              <Field label="Description"><textarea className="textarea" rows={4} value={desc} onChange={e => setDesc(e.target.value)} /></Field>
              <Field label="Tags" hint="Comma-separated"><input className="input" value={tags} onChange={e => setTags(e.target.value)} /></Field>
              <div className="row" style={{ gap: 8 }}><Button size="sm" variant="primary" onClick={save}>Save</Button><Button size="sm" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button></div>
            </>
          ) : (
            <>
              <div className="small" style={{ color: ioc.description ? "var(--text-2)" : "var(--text-4)", lineHeight: 1.6, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{ioc.description || "No description."}</div>
              {(ioc.tags || []).length > 0 && (
                <div className="row wrap" style={{ gap: 4, marginTop: 12 }}>
                  {ioc.tags.map(t => <a key={t} className="tag link" href={`#/iocs?tag=${enc(t)}&status=all`}>{t}</a>)}
                </div>
              )}
              {(ioc.mitre_techniques || []).length > 0 && (
                <div className="row wrap" style={{ gap: 4, marginTop: 10 }}>
                  {ioc.mitre_techniques.map(t => <a key={t} className="badge violet" href={`https://attack.mitre.org/techniques/${t.split(" ")[0].replace(".", "/")}/`} target="_blank" rel="noreferrer">{t}</a>)}
                </div>
              )}
              {hd.status === "false_positive" && <Callout tone="warn" style={{ marginTop: 12 }}>Marked as false positive{ioc.fp_reason ? `: ${ioc.fp_reason}` : ""}. Excluded from STIX/TAXII exports.</Callout>}
            </>
          )}
        </Panel>

        <Panel title="Enrichment" sub={enr.enriched_at ? `updated ${timeAgo(enr.enriched_at)}` : undefined}>
          {sources.length === 0 ? (
            <div className="small faint">No enrichment source has answered for this indicator{enr.source ? ` (ingested from ${enr.source})` : ""}. Use Re-enrich to query VirusTotal, AbuseIPDB and URLhaus.</div>
          ) : (
            <div className="grid g3">
              {sources.map(s => (
                <div key={s.name} style={{ background: "var(--elevated)", borderRadius: 6, padding: "10px 12px" }}>
                  <div className="row between" style={{ marginBottom: 6 }}>
                    <span className="strong small">{s.name}</span>
                    {safeUrl(s.d.link) && <a className="link xs" href={safeUrl(s.d.link)} target="_blank" rel="noreferrer">Open ↗</a>}
                  </div>
                  {s.d.error ? <div className="xs" style={{ color: "var(--critical)" }}>{s.d.error}</div> : (
                    <dl className="kv" style={{ gridTemplateColumns: "90px 1fr", gap: "4px 8px", margin: 0 }}>
                      {s.rows.filter(([, v]) => v !== null && v !== undefined && v !== "").map(([k, v]) => <React.Fragment key={k}><dt className="xs">{k}</dt><dd className="xs" style={{ overflowWrap: "anywhere" }}>{String(v)}</dd></React.Fragment>)}
                    </dl>
                  )}
                </div>
              ))}
            </div>
          )}
          {Object.keys(geo || {}).length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>Network & geo</div>
              <dl className="kv">{Object.entries(geo).map(([k, v]) => <React.Fragment key={k}><dt style={{ textTransform: "capitalize" }}>{k.replace(/_/g, " ")}</dt><dd style={{ overflowWrap: "anywhere" }}>{String(v)}</dd></React.Fragment>)}</dl>
            </div>
          )}
        </Panel>

        {ioc.type === "Email" && <MailPanel address={ioc.value} mail={enr.mail} />}
        <DnsPanel value={ioc.value} type={ioc.type} />

        {relGroups.length > 0 && (
          <Panel title="Related indicators" sub="shared campaign, family, subnet or tag" tight>
            {relGroups.map(([label, rows, meta]) => (
              <div key={label}>
                <div className="eyebrow" style={{ padding: "10px 16px 4px" }}>{label}{meta ? ` · ${meta}` : ""} <span className="faint">({rows.length}{rows.length >= 25 ? "+" : ""})</span></div>
                {rows.slice(0, 6).map(r => (
                  <div key={r.id} className="list-row clickable" {...actionable(() => navigate(`/observable/${enc(r.id)}`))}>
                    <TypeBadge type={r.type} /><span className="mono trunc" style={{ flex: 1 }}>{r.value_defanged || r.value}</span>
                    <span className="faint xs">conf {r.confidence}</span><span className="faint xs">{timeAgo(r.created_at)}</span>
                  </div>
                ))}
              </div>
            ))}
          </Panel>
        )}
      </div>

      <div className="stack">
        <Panel title="Intelligence links" tight>
          <LinkRow label="Campaign" value={ioc.campaign_name} to={ioc.campaign_id && `/campaigns/${enc(ioc.campaign_id)}`} />
          <LinkRow label="Threat actor" value={ioc.threat_actor} to={ioc.threat_actor && `/actors/${enc(ioc.threat_actor)}`} />
          <LinkRow label="Malware" value={hd.malware_family} to={hd.malware_family && `/malware/${enc(hd.malware_family)}`} />
        </Panel>
        {cves.length > 0 && (
          <Panel title="Linked vulnerabilities" sub="CVEs whose description names this indicator" tight>
            {cves.map(c => (
              <div key={c.cve_id} className="list-row clickable" {...actionable(() => navigate(`/cve/${enc(c.cve_id)}`))}>
                <span className="mono">{c.cve_id}</span>{c.kev_listed && <Badge tone="critical">KEV</Badge>}
                <span className="spacer" /><SevBadge severity={c.severity} score={c.cvss_score} />
              </div>
            ))}
          </Panel>
        )}
      </div>
    </div>
  );
}

function LinkRow({ label, value, to }) {
  const props = to && value ? actionable(() => navigate(to)) : {};
  return (
    <div className={`list-row ${to && value ? "clickable" : ""}`} {...props}>
      <span className="faint" style={{ width: 110 }}>{label}</span>
      <span className="trunc" style={{ flex: 1, color: value ? "var(--text)" : "var(--text-4)" }}>{value || "—"}</span>
    </div>
  );
}

// ── Analyst notes (indicators) ──────────────────────────────────────────────
export function NotesPanel({ env, reload }) {
  const { me } = useSession();
  const toast = useToast();
  const [note, setNote] = useState("");
  const ioc = env.overview.ioc, notes = env.overview.notes;
  async function add() {
    if (!note.trim()) return;
    try { await apiJSON(`/iocs/${enc(ioc.id)}/notes`, { method: "POST", body: { note } }); setNote(""); reload(true); }
    catch (e) { toast(e.message, "error"); }
  }
  async function del(id) {
    const r = await api(`/iocs/${enc(ioc.id)}/notes/${id}`, { method: "DELETE" });
    if (r.ok) reload(true); else toast("Could not delete note", "error");
  }
  return (
    <Panel title="Analyst notes" tight>
      <div style={{ padding: "8px 16px 12px" }}>
        <textarea className="textarea" rows={3} style={{ width: "100%" }} placeholder="Add an observation… (Ctrl+Enter to save)" value={note} aria-label="New note"
          onChange={e => setNote(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) add(); }} />
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 6 }}><Button size="sm" variant="primary" disabled={!note.trim()} onClick={add}>Add note</Button></div>
      </div>
      {notes.map(n => (
        <div key={n.id} style={{ padding: "10px 16px", borderTop: "1px solid var(--border)" }}>
          <div className="row between"><span className="small strong">{n.username}</span>
            <span className="row" style={{ gap: 4 }}><span className="faint xs">{timeAgo(n.created_at)}</span>
              {(me?.role === "admin" || n.user_id === me?.id) && <IconButton icon="trash" size="sm" title="Delete note" onClick={() => del(n.id)} />}</span></div>
          <div className="small" style={{ whiteSpace: "pre-wrap", marginTop: 4, overflowWrap: "anywhere" }}>{n.note}</div>
        </div>
      ))}
    </Panel>
  );
}

// ── Detections ──────────────────────────────────────────────────────────────
export function Detection({ ioc }) {
  const templates = detectionTemplates(ioc.type, ioc.value);
  const [picker, setPicker] = useState(null);
  return (
    <div className="stack">
      <Callout>Hunting queries generated from this indicator. They are starting points to run in your SIEM/EDR — not a statement of existing coverage. Save the ones you deploy to an investigation to track them.</Callout>
      {(ioc.mitre_techniques || []).length > 0 && (
        <Panel title="Mapped ATT&CK techniques" sub="set by analysts on this indicator">
          <div className="row wrap" style={{ gap: 6 }}>
            {ioc.mitre_techniques.map(t => <a key={t} className="badge violet" href={`https://attack.mitre.org/techniques/${t.split(" ")[0].replace(".", "/")}/`} target="_blank" rel="noreferrer">{t}</a>)}
          </div>
        </Panel>
      )}
      {templates.length === 0 && <EmptyState icon="code" title="No templates for this indicator type" desc="Use the Query Builder to generate a detection for this context." action={<Button size="sm" onClick={() => navigate("/query")}>Open Query Builder</Button>} />}
      {templates.map(t => (
        <Panel key={t.name} title={t.name} actions={<>
          <CopyButton value={t.body} />
          <Button size="xs" icon="briefcase" onClick={() => setPicker(t)}>Save to investigation</Button>
        </>}>
          <pre className="code" style={{ overflowWrap: "anywhere", whiteSpace: "pre-wrap" }}>{t.body}</pre>
        </Panel>
      ))}
      {picker && <InvestigationPicker title="Save detection to investigation" onClose={() => setPicker(null)}
        onPick={inv => apiJSON(`/v2/investigations/${enc(inv.id)}/items`, { method: "POST", body: { item_type: "detection", value: `${picker.name}: ${ioc.value}`, label: picker.name, data: { language: picker.lang, rule: picker.body, indicator: ioc.value } } })} />}
    </div>
  );
}
export const hasDetections = type => typeGroup(type) !== "other";

// ── Indicator TFII does not track ───────────────────────────────────────────
export function ObservableOverview({ env }) {
  const hd = env.entity;
  const [lookup, setLookup] = useState(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  async function run() {
    setBusy(true);
    try { const d = await apiJSON("/iocs/bulk-lookup", { method: "POST", body: { input: hd.value } }); setLookup(d.results?.[0] || null); }
    catch (e) { toast(e.message, "error"); }
    setBusy(false);
  }
  const tone = { malicious: "critical", suspicious: "high", clean: "success" };
  return (
    <div className="stack">
      <Callout>This value isn't in the TFII indicator database. Look up its reputation, then track it as an IOC to enrich it, relate it and share it via STIX/TAXII. Anything TFII does know about it (URLs hosted on it, investigations that mention it) appears in the other tabs.</Callout>
      <Panel title="Reputation" actions={<Button size="sm" icon="search" loading={busy} onClick={run}>Look up</Button>}>
        {!lookup ? <div className="small faint">Not looked up yet. This queries VirusTotal, AbuseIPDB and URLhaus with your keys.</div> : (
          <>
            <div className="row" style={{ gap: 8, marginBottom: 8 }}>
              <Badge tone={tone[lookup.verdict] || "low"} dot>{lookup.verdict}</Badge>
            </div>
            {geoFacts(lookup.geo).length > 0 && (
              <div className="stack" style={{ gap: 4, marginBottom: 8 }}>
                {geoFacts(lookup.geo).map(f => (
                  <div key={f.label} className="small" title={f.title}>
                    <span className="faint">{f.label}: </span>
                    <span style={{ color: f.tone === "warn" ? "var(--high)" : f.tone === "muted" ? "var(--text-3)" : "var(--text)" }}>{f.value}</span>
                  </div>
                ))}
                {lookup.geo?.org && <div className="small faint">Owner: {lookup.geo.org}{lookup.geo.asn ? ` (${lookup.geo.asn})` : ""}{lookup.geo.resolved_ip ? ` · resolves to ${lookup.geo.resolved_ip}` : ""}</div>}
                {lookup.geo?.note && <div className="small faint" style={{ maxWidth: 560 }}>{lookup.geo.note}</div>}
              </div>
            )}
            <div className="small muted" style={{ overflowWrap: "anywhere" }}>{lookup.reason}</div>
          </>
        )}
      </Panel>
      {hd.type === "Email" && <MailPanel address={hd.value} mail={lookup?.enrichment?.mail} />}
      <DnsPanel value={hd.value} type={hd.type} />
    </div>
  );
}

// ── CVE ─────────────────────────────────────────────────────────────────────
const Epss = ({ v }) => v === null || v === undefined ? <span className="faint">—</span>
  : <span className="num" style={{ color: v * 100 >= 50 ? "var(--critical)" : v * 100 >= 10 ? "var(--high)" : "var(--text-3)" }}>{(v * 100).toFixed(v * 100 < 1 ? 2 : 1)}%</span>;

export function CveOverview({ env }) {
  const hd = env.entity, o = env.overview;
  const [lookup, setLookup] = useState(!hd.tracked);
  if (!o) {
    return (
      <div className="stack">
        <Callout>{hd.ref} is not tracked against any monitored software, so TFII holds no record of its own. Multi-source intelligence below is fetched live from public sources.</Callout>
        <MultiSource cveId={hd.ref} />
      </div>
    );
  }
  const links = ls => ls.length === 0 ? null : ls.map(r => <a key={r.url} className="list-row clickable" href={r.url} target="_blank" rel="noreferrer"><span className="trunc link small">{r.url}</span></a>);
  const rem = o.remediation;
  return (
    <div className="grid g-main-side">
      <div className="stack">
        <Panel title="Description">
          <div className="small" style={{ color: "var(--text-2)", lineHeight: 1.65, overflowWrap: "anywhere" }}>{o.description || "No description published."}</div>
          <dl className="kv" style={{ marginTop: 14 }}>
            <dt>CVSS</dt><dd><span className="num">{o.cvss.score ?? "—"}</span> <span className="mono faint xs" style={{ overflowWrap: "anywhere" }}>{o.cvss.vector}</span></dd>
            <dt>EPSS</dt><dd><Epss v={o.epss.score} />{o.epss.percentile != null && <span className="faint"> · percentile {(o.epss.percentile * 100).toFixed(0)}</span>}</dd>
            <dt>Weakness</dt><dd>{o.cwe || "—"}</dd>
            <dt>Published</dt><dd>{o.published || "—"}</dd>
            <dt>Last modified</dt><dd>{o.modified || "—"}</dd>
            <dt>Exploitation</dt><dd>{o.kev.listed ? <span><Badge tone="critical" dot>CISA KEV</Badge> <span className="faint xs">confirmed exploited in the wild{o.kev.date ? `, listed ${o.kev.date}` : ""}</span></span> : <span className="faint">Not in the CISA KEV catalog — no exploitation evidence in TFII's sources</span>}</dd>
          </dl>
        </Panel>

        <Panel title="Affected software" sub="software you monitor that NVD lists for this CVE" tight>
          <div className="tbl-wrap" tabIndex={0}><table className="tbl compact">
            <thead><tr><th>Software</th><th>Affected versions</th><th>Monitored version</th><th>Patch</th></tr></thead>
            <tbody>{o.software.map((s, k) => (
              <tr key={k} className="clickable" {...(s.asset_id ? rowAction(() => navigate(`/software/${enc(s.asset_id)}`)) : {})}>
                <td className="primary">{s.name}<div className="faint xs">{s.vendor}</div></td>
                <td className="wrapcell cellmono" style={{ maxWidth: 320, overflowWrap: "anywhere" }}>{s.affected_versions || <span className="faint">ranges not published</span>}</td>
                <td className="muted">{s.monitored_version || "—"}</td>
                <td>{s.patch_available ? <span className="row" style={{ gap: 4 }}><Badge tone="success" dot>Patched</Badge>{safeUrl(s.patch_url) && <a className="link xs" href={safeUrl(s.patch_url)} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}>fix ↗</a>}</span> : <Badge tone="high" outline>No patch</Badge>}</td>
              </tr>))}</tbody>
          </table></div>
        </Panel>

        {(rem.patches.length > 0 || rem.advisories.length > 0 || rem.mitigations.length > 0) && (
          <Panel title="Remediation" sub={`${rem.patched_on} of ${rem.software_count} monitored software have a patch`} tight>
            {rem.patches.length > 0 && <><div className="eyebrow" style={{ padding: "10px 16px 2px" }}>Patches</div>{links(rem.patches)}</>}
            {rem.mitigations.length > 0 && <><div className="eyebrow" style={{ padding: "10px 16px 2px" }}>Mitigations</div>{links(rem.mitigations)}</>}
            {rem.advisories.length > 0 && <><div className="eyebrow" style={{ padding: "10px 16px 2px" }}>Vendor advisories</div>{links(rem.advisories)}</>}
          </Panel>
        )}
        {o.references.length > 0 && <Panel title="References" sub={`${o.references.length}`} tight>{links(o.references.slice(0, 15))}</Panel>}
      </div>
      <div className="stack">
        {o.linked_iocs.length > 0 && (
          <Panel title="Linked indicators" sub="named in the CVE description" tight>
            {o.linked_iocs.map(i => (
              <div key={i.id} className="list-row clickable" {...actionable(() => navigate(`/observable/${enc(i.id)}`))}>
                <TypeBadge type={i.type} /><span className="mono trunc" style={{ flex: 1 }}>{i.value_defanged || i.value}</span>
              </div>
            ))}
          </Panel>
        )}
        <Panel title="Multi-source intelligence" sub="NVD · CVE.org · OSV · EPSS · CISA KEV · PoCs">
          {lookup ? <MultiSource cveId={hd.ref} bare /> : (
            <><div className="small faint" style={{ marginBottom: 8 }}>Queries several public services live, so it only runs on request.</div>
              <Button size="sm" icon="search" onClick={() => setLookup(true)}>Run multi-source lookup</Button></>
          )}
        </Panel>
      </div>
    </div>
  );
}

function MultiSource({ cveId, bare }) {
  const body = <CveLookup initialId={cveId} key={cveId} />;
  return bare ? body : <Panel title="Multi-source intelligence" sub="NVD · CVE.org · OSV · EPSS · CISA KEV · public PoCs">{body}</Panel>;
}
export { MultiSource };
