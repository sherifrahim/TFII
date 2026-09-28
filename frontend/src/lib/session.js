import { createContext, useContext } from "react";

export const SessionContext = createContext({ me: null, token: null, caps: [], can: () => false, logout: () => {} });
export function useSession() { return useContext(SessionContext); }

// Recently opened entities and searches, for the command palette.
const RECENT_KEY = "tf_recent_entities";
const SEARCH_KEY = "tf_recent_searches";

function read(key) { try { return JSON.parse(localStorage.getItem(key) || "[]"); } catch { return []; } }
function write(key, v) { try { localStorage.setItem(key, JSON.stringify(v)); } catch {} }

export function pushRecentEntity(e) {
  if (!e || !e.ref) return;
  const list = read(RECENT_KEY).filter(x => !(x.kind === e.kind && x.ref === e.ref));
  write(RECENT_KEY, [{ ...e, at: Date.now() }, ...list].slice(0, 8));
}
export function recentEntities() { return read(RECENT_KEY); }

export function pushRecentSearch(q) {
  q = (q || "").trim();
  if (!q) return;
  write(SEARCH_KEY, [q, ...read(SEARCH_KEY).filter(x => x !== q)].slice(0, 6));
}
export function recentSearches() { return read(SEARCH_KEY); }
