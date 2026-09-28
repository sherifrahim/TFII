import { useCallback, useEffect, useRef, useState } from "react";
import { API_BASE } from "../config";

export const TOKEN_KEY = "tf_token";

export function getToken() {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}

// Same contract as the legacy api(): returns the raw Response, and a 401 drops
// the session. Kept so legacy components and new pages behave identically.
export async function api(path, opts = {}, token = getToken()) {
  const headers = { ...(opts.body instanceof FormData ? {} : { "Content-Type": "application/json" }), ...(opts.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(`${API_BASE}${path}`, { ...opts, headers });
  if (r.status === 401) {
    try { localStorage.removeItem(TOKEN_KEY); } catch {}
    window.location.reload();
  }
  return r;
}

export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

// JSON helper that throws a readable error instead of returning a Response.
export async function apiJSON(path, opts = {}) {
  let r;
  try {
    r = await api(path, {
      ...opts,
      body: opts.body && !(opts.body instanceof FormData) && typeof opts.body !== "string"
        ? JSON.stringify(opts.body) : opts.body,
    });
  } catch (e) {
    throw new ApiError("Cannot reach the TFII server.", 0);
  }
  let data = null;
  try { data = await r.json(); } catch { /* empty body */ }
  if (!r.ok) {
    const detail = data && (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data));
    throw new ApiError(detail || `Request failed (HTTP ${r.status})`, r.status);
  }
  return data;
}

// Data-fetching hook: {data, error, loading, reload}. Stale responses from an
// earlier `path` are discarded so fast filter changes never flash old rows.
export function useApi(path, deps = []) {
  const [state, setState] = useState({ data: null, error: null, loading: !!path });
  const seq = useRef(0);
  const load = useCallback(async (silent = false) => {
    if (!path) { setState({ data: null, error: null, loading: false }); return; }
    const mine = ++seq.current;
    if (!silent) setState(s => ({ ...s, loading: true, error: null }));
    try {
      const data = await apiJSON(path);
      if (mine === seq.current) setState({ data, error: null, loading: false });
    } catch (e) {
      if (mine === seq.current) setState(s => ({ ...s, error: e, loading: false }));
    }
  }, [path]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [load, ...deps]); // eslint-disable-line react-hooks/exhaustive-deps
  return { ...state, reload: load, setData: d => setState(s => ({ ...s, data: typeof d === "function" ? d(s.data) : d })) };
}

export function qs(params) {
  const p = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "" || v === false) return;
    p.set(k, v);
  });
  const s = p.toString();
  return s ? `?${s}` : "";
}

export async function downloadJSON(path, filename) {
  const data = await apiJSON(path);
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}
