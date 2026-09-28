import React, { useState } from "react";
import { Modal, Button, SearchInput, Loading, ErrorState, useToast } from "./ui";
import { useApi, apiJSON } from "../lib/api";
import { timeAgo } from "../lib/format";
import { navigate, enc } from "../lib/router";
import { SEV_COLOR } from "../design/tokens";

// Pick (or create) an investigation, then hand it to `onPick`. `onPick` returns
// a promise; the modal closes and toasts when it resolves.
export default function InvestigationPicker({ title = "Add to investigation", onPick, onClose }) {
  const { data, error, loading, reload } = useApi("/v2/investigations?status=open,active,monitoring");
  const [q, setQ] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(null);
  const toast = useToast();

  async function pick(inv) {
    setBusy(inv.id);
    try {
      await onPick(inv);
      toast(<span>Added to <a className="link" href={`#/investigations/${enc(inv.id)}`}>{inv.key} {inv.name}</a></span>, "ok");
      onClose();
    } catch (e) {
      toast(e.message, "error");
    }
    setBusy(null);
  }
  async function create() {
    if (!name.trim()) return;
    setBusy("new");
    try {
      const inv = await apiJSON("/v2/investigations", { method: "POST", body: { name: name.trim() } });
      await pick(inv);
    } catch (e) { toast(e.message, "error"); setBusy(null); }
  }

  const list = (data?.investigations || []).filter(i => !q || i.name.toLowerCase().includes(q.toLowerCase()) || i.key.toLowerCase().includes(q.toLowerCase()));
  return (
    <Modal title={title} onClose={onClose}
      footer={<Button variant="ghost" onClick={() => { onClose(); navigate("/workspace"); }}>Open Workspace</Button>}>
      <div className="row" style={{ gap: 8, marginBottom: 12 }}>
        <input className="input" style={{ flex: 1 }} placeholder="New investigation name…" value={name}
          onChange={e => setName(e.target.value)} onKeyDown={e => e.key === "Enter" && create()} />
        <Button variant="primary" onClick={create} disabled={!name.trim()} loading={busy === "new"}>Create & add</Button>
      </div>
      <SearchInput value={q} onChange={setQ} placeholder="Filter open investigations" style={{ marginBottom: 8 }} />
      {loading && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && list.length === 0 && <div className="faint small" style={{ padding: 12 }}>No open investigations.</div>}
      <div style={{ maxHeight: 320, overflow: "auto" }}>
        {list.map(inv => (
          <div key={inv.id} className="list-row clickable" style={{ padding: "0 8px" }} onClick={() => !busy && pick(inv)}>
            <span className="sev-dot" style={{ background: SEV_COLOR[inv.severity] }} />
            <span className="mono faint xs">{inv.key}</span>
            <span className="trunc" style={{ flex: 1, color: "var(--text)" }}>{inv.name}</span>
            <span className="faint xs">{inv.iocs} IOCs · {timeAgo(inv.updated_at)}</span>
            {busy === inv.id && <span className="spinner" />}
          </div>
        ))}
      </div>
    </Modal>
  );
}
