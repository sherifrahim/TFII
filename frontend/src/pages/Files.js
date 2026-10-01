import React, { useCallback, useEffect, useRef, useState } from "react";
import { API_BASE } from "../config";
import { api, apiJSON, getToken } from "../lib/api";
import Icon from "../components/Icon";
import { Badge, Button, Callout, CopyButton, EmptyState, ErrorState, IconButton, Menu, PageHeader, Panel, SkeletonRows, Switch, useToast } from "../components/ui";

export function fmtBytes(n) {
  if (n === 0 || n == null) return "0 B";
  const u = ["B", "KB", "MB", "GB"]; let i = 0; let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}

const EXT_ICON = { pdf: "fileText", txt: "fileText", md: "fileText", csv: "list", json: "code", js: "code", py: "code", zip: "package", gz: "package", pcap: "activity", png: "eye", jpg: "eye", jpeg: "eye" };
const iconFor = name => EXT_ICON[String(name).split(".").pop().toLowerCase()] || "note";

function FileRow({ f, onPatch, onDelete, onDownload }) {
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(f.filename);
  const link = f.share_token ? `${API_BASE}/f/${f.share_token}` : null;
  function save() { setRenaming(false); if (name.trim() && name !== f.filename) onPatch(f.id, { filename: name.trim() }); }
  return (
    <div className="file-row">
      <div className="file-ico"><Icon name={iconFor(f.filename)} size={17} /></div>
      <div style={{ minWidth: 0 }}>
        {renaming
          ? <div className="row" style={{ gap: 8 }}><input className="input" style={{ flex: 1 }} autoFocus value={name} onChange={e => setName(e.target.value)} aria-label="File name"
              onKeyDown={e => { if (e.key === "Enter") save(); if (e.key === "Escape") setRenaming(false); }} /><Button size="sm" variant="primary" onClick={save}>Save</Button><Button size="sm" variant="ghost" onClick={() => setRenaming(false)}>Cancel</Button></div>
          : <div className="strong" style={{ overflowWrap: "anywhere" }}>{f.filename}</div>}
        <div className="xs faint" style={{ marginTop: 2 }}>{fmtBytes(f.size_bytes)}{f.share_token ? ` · ${f.download_count || 0} download${f.download_count === 1 ? "" : "s"} via link` : ""}</div>
        {link && <div className="row" style={{ gap: 6, marginTop: 8 }}><code className="mono-soft trunc" style={{ background: "rgba(255,255,255,.04)", padding: "4px 9px", borderRadius: 7, flex: 1, maxWidth: 520 }}>{link}</code><CopyButton value={link} /></div>}
      </div>
      <div className="row" style={{ gap: 10 }}>
        <Switch checked={!!f.share_token} onChange={v => onPatch(f.id, { shared: v })} label={f.share_token ? "Shared" : "Private"} />
        <IconButton icon="download" title="Download" onClick={() => onDownload(f)} />
        <Menu trigger={t => <IconButton icon="more" title="More" onClick={t} />} items={[
          { label: "Rename", icon: "edit", onClick: () => { setName(f.filename); setRenaming(true); } },
          "sep",
          { label: "Delete", icon: "trash", danger: true, onClick: () => onDelete(f) },
        ]} />
      </div>
    </div>
  );
}

export default function FilesPage() {
  const toast = useToast();
  const [files, setFiles] = useState(null);
  const [usage, setUsage] = useState({ used: 0, quota: 0, maxFile: 0 });
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState("");
  const [drag, setDrag] = useState(false);
  const input = useRef(null);

  const load = useCallback(async () => {
    try {
      const d = await apiJSON("/files");
      setFiles(d.files || []); setUsage({ used: d.used_bytes || 0, quota: d.quota_bytes || 0, maxFile: d.max_file_bytes || 0 }); setErr(null);
    } catch (e) { setErr(e); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function upload(list) {
    for (const f of [...(list || [])]) {
      if (usage.maxFile && f.size > usage.maxFile) { toast(`"${f.name}" is ${fmtBytes(f.size)}, over the ${fmtBytes(usage.maxFile)} limit.`, "error"); continue; }
      setBusy(`Uploading ${f.name}…`);
      try {
        const fd = new FormData(); fd.append("file", f);
        const r = await api("/files/upload", { method: "POST", body: fd });
        if (!r.ok) { const d = await r.json().catch(() => ({})); toast(d.detail || `Upload of "${f.name}" failed`, "error"); }
      } catch (e) { toast(String(e.message || e), "error"); }
    }
    setBusy(""); load();
  }
  async function patch(id, body) {
    try { await apiJSON(`/files/${id}`, { method: "PATCH", body }); load(); } catch (e) { toast(e.message, "error"); }
  }
  async function remove(f) {
    if (!window.confirm(`Delete "${f.filename}"? This removes the file from disk and cannot be undone.`)) return;
    try { await apiJSON(`/files/${f.id}`, { method: "DELETE" }); toast("File deleted", "ok"); load(); } catch (e) { toast(e.message, "error"); }
  }
  // The download needs an Authorization header, which a plain link cannot send: fetch it and hand the browser a blob.
  async function download(f) {
    try {
      const r = await fetch(`${API_BASE}/files/${f.id}/download`, { headers: { Authorization: `Bearer ${getToken()}` } });
      if (!r.ok) { toast(`Download failed (${r.status})`, "error"); return; }
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement("a"); a.href = url; a.download = f.filename; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } catch (e) { toast(String(e.message || e), "error"); }
  }

  const pct = usage.quota ? Math.min(100, (usage.used / usage.quota) * 100) : 0;
  return (
    <div className="page narrow">
      <PageHeader title="Files" sub="A private file store with share links. Files are always served as downloads, never rendered in the browser." />
      <div className="stack" style={{ gap: 18 }}>
        <div className={`dropzone ${drag ? "drag" : ""}`} role="button" tabIndex={0} onClick={() => input.current?.click()} onKeyDown={e => (e.key === "Enter" || e.key === " ") && input.current?.click()}
          onDragOver={e => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={e => { e.preventDefault(); setDrag(false); upload(e.dataTransfer.files); }}>
          <input ref={input} type="file" multiple style={{ display: "none" }} onChange={e => { upload(e.target.files); e.target.value = ""; }} />
          <div className="file-ico" style={{ width: 46, height: 46, borderRadius: 14 }}><Icon name="upload" size={20} /></div>
          <div className="strong">{busy || "Drop files here, or click to choose"}</div>
          <div className="small faint">Up to {fmtBytes(usage.maxFile)} per file · {fmtBytes(usage.used)} of {fmtBytes(usage.quota)} used</div>
          <div className="meter" style={{ width: 280, margin: "6px auto 0" }}><i style={{ width: `${pct}%`, background: pct > 85 ? "var(--critical)" : pct > 60 ? "var(--high)" : "var(--grad)" }} /></div>
        </div>
        <Callout tone="info">Share links are unguessable and can be switched off. Turning sharing off and on again creates a new link, so an old one stays dead.</Callout>
        {err && <ErrorState error={err} onRetry={load} />}
        {files === null && !err && <Panel><SkeletonRows rows={3} cols={3} /></Panel>}
        {files && files.length === 0 && <EmptyState icon="folder" title="No files yet" desc="Upload a file to keep it here and share it with a link when you need to." />}
        {files && files.length > 0 && (
          <Panel title={`${files.length} file${files.length === 1 ? "" : "s"}`} actions={<Badge tone={files.some(f => f.share_token) ? "high" : "low"} outline>{files.filter(f => f.share_token).length} shared</Badge>} tight>
            {files.map(f => <FileRow key={f.id} f={f} onPatch={patch} onDelete={remove} onDownload={download} />)}
          </Panel>
        )}
      </div>
    </div>
  );
}
