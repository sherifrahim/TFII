// Deploy scripts substitute the literal placeholder below with the real domain
// (see .github/workflows/deploy.yml and docker/frontend.Dockerfile). If a build
// ever ships without that substitution, fall back to the page's own origin —
// the API is served from the same host as /ui/, so this is always correct in
// production and turns a blank app into a working one. The check is split in
// two so the deploy-time sed cannot rewrite the sentinel itself.
const RAW_API_BASE = "https://YOUR_DOMAIN";
const PLACEHOLDER = ["YOUR", "DOMAIN"].join("_");

export const API_BASE =
  RAW_API_BASE.includes(PLACEHOLDER) && typeof window !== "undefined"
    ? window.location.origin
    : RAW_API_BASE;
