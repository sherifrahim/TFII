import React, { Suspense, lazy } from "react";

// The legacy component bundle is ~400 KB of source that only a few screens use
// (multi-source CVE lookup, software registry, first-run key dialog). Loading it
// on demand keeps it out of the initial download.
const chunk = name => lazy(() => import("./LegacyComponents").then(m => ({ default: m[name] })));
const fallback = <div className="state"><span className="spinner" /></div>;
const wrap = C => function LazyLegacy(props) { return <Suspense fallback={fallback}><C {...props} /></Suspense>; };

export const ApiKeyModal = wrap(chunk("ApiKeyModal"));
export const DemoLockedPage = wrap(chunk("DemoLockedPage"));
export const AssetManager = wrap(chunk("AssetManager"));
export const CVELookup = wrap(chunk("CVELookup"));
export const CVEReportModal = wrap(chunk("CVEReportModal"));
export const LegacyNotes = wrap(chunk("WorkspacePage"));
export const CVEDetail = wrap(chunk("CVEDetail"));
