import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import Icon from "./Icon";
import { Badge, Button, Callout, Modal } from "./ui";

// Every provider TFII can use, grouped by what it is for. Keys are optional; each one unlocks more detail.
export const KEY_SERVICES = [
  { group: "Reputation", id: "virustotal", name: "VirusTotal", url: "https://www.virustotal.com/gui/my-apikey", desc: "File, domain, IP and URL reputation from 70+ engines", placeholder: "Your VirusTotal API key", icon: "shield" },
  { group: "Reputation", id: "abuseipdb", name: "AbuseIPDB", url: "https://www.abuseipdb.com/account/api", desc: "How often an IP address has been reported for abuse", placeholder: "Your AbuseIPDB key", icon: "alert" },
  { group: "Reputation", id: "urlhaus", name: "abuse.ch", url: "https://auth.abuse.ch/", desc: "URLhaus, ThreatFox and MalwareBazaar. One free Auth-Key covers all three", placeholder: "Your abuse.ch Auth-Key", icon: "bug" },
  { group: "Reputation", id: "otx", name: "AlienVault OTX", url: "https://otx.alienvault.com/settings", desc: "Community threat pulses with adversary and malware context", placeholder: "Your OTX key", icon: "radar" },
  { group: "Email", id: "ipqs", name: "IPQualityScore", url: "https://www.ipqualityscore.com/create-account", desc: "Email address risk: fraud score, disposable, recent abuse (on request)", placeholder: "Your IPQualityScore key", icon: "mail" },
  { group: "Email", id: "mxtoolbox", name: "MxToolbox", url: "https://mxtoolbox.com/user/api", desc: "Deep mail-domain tests: MX, SPF, DMARC, MTA-STS, BIMI (on request)", placeholder: "Your MxToolbox API key", icon: "server" },
  { group: "AI", id: "groq", name: "Groq", url: "https://console.groq.com/keys", desc: "Fast AI for summaries, triage, query building and explanations", placeholder: "gsk_…", icon: "sparkle" },
  { group: "AI", id: "codecraft", name: "CodeCraft", url: "https://www.codecraftapi.com/", desc: "An OpenAI-compatible gateway; used for the same AI features if you have no Groq key", placeholder: "cc_…", icon: "zap" },
  { group: "Other", id: "shodan", name: "Shodan", url: "https://account.shodan.io/", desc: "Open ports and services for a host", placeholder: "Your Shodan key", icon: "globe" },
  { group: "Other", id: "nvd", name: "NVD", url: "https://nvd.nist.gov/developers/request-an-api-key", desc: "A higher request limit for CVE data", placeholder: "Your NVD key", icon: "shieldAlert" },
];

export function useKeys() {
  const [rows, setRows] = useState(null);
  const [quota, setQuota] = useState(null);
  const load = useCallback(() => {
    api("/users/me/api-keys").then(r => (r.ok ? r.json() : null)).then(d => { if (d) { setRows(Object.fromEntries(d.map(k => [k.service, k]))); window.dispatchEvent(new CustomEvent("tfii:keys-changed")); } }).catch(() => {});
    api("/users/me/quota").then(r => (r.ok ? r.json() : null)).then(q => { if (q) setQuota(q); }).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);
  return { rows, quota, reload: load };
}

function KeyRow({ svc, st, onChanged }) {
  const [val, setVal] = useState("");
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState("");
  const [check, setCheck] = useState(null);
  const own = !!st?.has_key;
  const platform = !own && st?.source === "platform";
  const showInput = !own || editing;

  async function save() {
    const k = val.trim();
    if (!k) return;
    setBusy("save");
    const r = await api(`/users/me/api-keys/${svc.id}`, { method: "POST", body: JSON.stringify({ api_key: k }) });
    if (r.ok) { setVal(""); setEditing(false); setCheck(null); onChanged(); }
    else { const d = await r.json().catch(() => ({})); setCheck({ status: "unexpected", message: typeof d.detail === "string" ? d.detail : "Could not save the key." }); }
    setBusy("");
  }
  // Ask the provider whether the key works: the pasted one if there is one, otherwise the saved one.
  async function test() {
    const pasted = val.trim();
    setBusy("test"); setCheck(null);
    try {
      const r = await api(`/users/me/api-keys/${svc.id}/test`, { method: "POST", body: JSON.stringify(pasted ? { api_key: pasted } : {}) });
      const d = await r.json().catch(() => ({}));
      setCheck(r.ok ? { status: d.status, message: d.message, tested: d.tested } : { status: "unexpected", message: typeof d.detail === "string" ? d.detail : "The check could not be run.", tested: pasted ? "pasted" : "saved" });
    } catch { setCheck({ status: "unreachable", message: "Could not reach the server.", tested: pasted ? "pasted" : "saved" }); }
    setBusy("");
  }
  async function remove() {
    if (!window.confirm(`Remove your saved ${svc.name} key?`)) return;
    const r = await api(`/users/me/api-keys/${svc.id}`, { method: "DELETE" });
    if (r.ok) { setCheck(null); onChanged(); }
  }

  return (
    <div className={`key-row ${own ? "has" : ""}`} data-testid={`key-row-${svc.id}`}>
      <div className="key-ico"><Icon name={svc.icon} size={16} /></div>
      <div className="key-main">
        <div className="row wrap" style={{ gap: 8 }}>
          <span className="strong">{svc.name}</span>
          {own ? <Badge tone="success" dot><span data-testid={`key-status-${svc.id}`}>Your key{st.masked ? ` · ${st.masked}` : ""}</span></Badge>
            : platform ? <Badge tone="accent" outline><span data-testid={`key-status-${svc.id}`}>Shared key{st.quota_total ? ` · ${st.quota_remaining}/${st.quota_total} free today` : ""}</span></Badge>
            : <Badge tone="low" outline><span data-testid={`key-status-${svc.id}`}>Not set</span></Badge>}
        </div>
        <div className="small faint" style={{ marginTop: 2 }}>{svc.desc}{own && st.updated_at ? ` · updated ${String(st.updated_at).slice(0, 10)}` : ""}</div>
        {showInput && (
          <div className="row" style={{ gap: 8, marginTop: 10 }}>
            <input type="password" autoComplete="off" className="input mono" style={{ flex: 1 }} value={val} aria-label={`${svc.name} API key`}
              placeholder={own ? "Paste the new key to replace it" : svc.placeholder}
              onChange={e => { setVal(e.target.value); setCheck(null); }} onKeyDown={e => { if (e.key === "Enter") save(); }} />
            <Button variant="primary" size="sm" loading={busy === "save"} disabled={!val.trim()} onClick={save}>Save</Button>
            <Button size="sm" loading={busy === "test"} disabled={!val.trim()} onClick={test} data-testid={`key-test-${svc.id}`} data-tip="Check with the provider that this key works, without saving it">Test</Button>
            {editing && <Button size="sm" variant="ghost" onClick={() => { setEditing(false); setVal(""); setCheck(null); }}>Cancel</Button>}
          </div>
        )}
        {check && !busy && (
          <div role="status" data-testid={`key-check-${svc.id}`} className="small" style={{ marginTop: 8, fontWeight: 550, color: check.status === "valid" ? "var(--success)" : check.status === "invalid" ? "var(--critical)" : "var(--high)" }}>
            {check.status === "valid" ? "✓ Key works" : check.status === "invalid" ? "✕ Key rejected" : "! Could not confirm"}
            <span className="faint" style={{ fontWeight: 400 }}> — {check.message}{check.tested === "pasted" ? " (not saved yet)" : ""}</span>
          </div>
        )}
      </div>
      <div className="key-actions">
        {own && !editing && <>
          <Button size="sm" variant="ghost" loading={busy === "test"} onClick={test} data-testid={`key-test-${svc.id}`}>Test</Button>
          <Button size="sm" variant="ghost" onClick={() => setEditing(true)}>Replace</Button>
          <Button size="sm" variant="ghost" onClick={remove} style={{ color: "var(--critical)" }}>Remove</Button>
        </>}
        {!own && <a className="btn sm ghost" href={svc.url} target="_blank" rel="noreferrer">Get a key <Icon name="external" size={12} /></a>}
      </div>
    </div>
  );
}

export function ApiKeysPanel() {
  const { rows, quota, reload } = useKeys();
  const low = quota && Object.values(quota).some(q => !q.unlimited && q.quota_remaining <= 3);
  const groups = useMemo(() => [...new Set(KEY_SERVICES.map(s => s.group))], []);
  return (
    <div className="stack" style={{ gap: 22 }}>
      <div className="small muted" style={{ maxWidth: 640 }}>
        Your own keys are used for your lookups instead of the shared daily allowance (10 free checks per service per day). They are encrypted and only your account can use them. Every key is optional.
      </div>
      {low && <Callout tone="warn">You're running low on free daily checks. Add your own keys to keep going without limits.</Callout>}
      {rows === null && <div className="state"><span className="spinner" /></div>}
      {rows && groups.map(g => (
        <section key={g}>
          <div className="eyebrow" style={{ marginBottom: 10 }}>{g}</div>
          <div className="stack" style={{ gap: 10 }}>
            {KEY_SERVICES.filter(s => s.group === g).map(s => <KeyRow key={s.id} svc={s} st={rows[s.id]} onChanged={reload} />)}
          </div>
        </section>
      ))}
    </div>
  );
}

// First-run and "API keys" account-menu dialog.
export function ApiKeysModal({ onClose }) {
  return (
    <Modal title="Add your API keys" onClose={onClose} wide footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      <ApiKeysPanel />
    </Modal>
  );
}
