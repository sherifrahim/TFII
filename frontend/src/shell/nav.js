// Global information architecture. `match` decides which item is highlighted
// for a given route; `cap` gates visibility or locks the item for explorers.
export const NAV = [
  { sec: "Command Center", items: [
    { id: "home", label: "Command Center", icon: "command", to: "/", match: p => p === "/", data: true },
  ] },
  { sec: "Intelligence", items: [
    { id: "iocs", label: "IOC Intelligence", icon: "crosshair", to: "/iocs", match: p => /^\/(iocs|ioc|observable)(\/|$)/.test(p), data: true },
    { id: "cve", label: "CVE Intelligence", icon: "shieldAlert", to: "/cve", match: p => /^\/(cve|software)(\/|$)/.test(p) },
    { id: "actors", label: "Threat Actors", icon: "skull", to: "/actors", match: p => /^\/(actors|malware)(\/|$)/.test(p) },
    { id: "campaigns", label: "Campaigns", icon: "flag", to: "/campaigns", match: p => /^\/campaigns(\/|$)/.test(p), data: true },
    { id: "intel", label: "Intel Wall", icon: "rss", to: "/intel", match: p => p.startsWith("/intel") },
  ] },
  { sec: "Investigate", items: [
    { id: "search", label: "Global Search", icon: "search", to: "/search", match: p => p.startsWith("/search") },
    { id: "explorer", label: "Entity Explorer", icon: "graph", to: "/explorer", match: p => p.startsWith("/explorer"), data: true },
    { id: "osint", label: "OSINT Toolkit", icon: "radar", to: "/osint", match: p => p.startsWith("/osint") },
    { id: "query", label: "Query Builder", icon: "code", to: "/query", match: p => p.startsWith("/query") },
    { id: "geo", label: "Geo Intelligence", icon: "globe", to: "/geo", match: p => p.startsWith("/geo"), data: true },
  ] },
  { sec: "Operations", items: [
    { id: "workspace", label: "Workspace", icon: "briefcase", to: "/workspace", match: p => /^\/(workspace|investigations)(\/|$)/.test(p), data: true },
    { id: "advisories", label: "Advisories", icon: "megaphone", to: "/advisories", match: p => p.startsWith("/advisories"), data: true },
    { id: "reports", label: "Reports", icon: "fileText", to: "/reports", match: p => p.startsWith("/reports") },
  ] },
  { sec: "Platform", items: [
    { id: "health", label: "Health", icon: "activity", to: "/platform/health", match: p => p === "/platform/health", cap: "admin.panel" },
    { id: "connectors", label: "Connectors", icon: "plug", to: "/platform/connectors", match: p => p === "/platform/connectors", cap: "admin.panel" },
    { id: "usage", label: "API Usage", icon: "barChart", to: "/platform/api-usage", match: p => p === "/platform/api-usage", cap: "admin.panel" },
    { id: "users", label: "Users", icon: "users", to: "/platform/users", match: p => p === "/platform/users", cap: "admin.users" },
    { id: "files", label: "Files", icon: "folder", to: "/platform/files", match: p => p === "/platform/files", root: true },
    { id: "settings", label: "Settings", icon: "settings", to: "/platform/settings", match: p => p === "/platform/settings" },
  ] },
];

export function flatNav() {
  return NAV.flatMap(s => s.items.map(i => ({ ...i, sec: s.sec })));
}

export function activeNav(path) {
  return flatNav().find(i => i.match(path));
}
