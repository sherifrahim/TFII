import React from "react";
import { navigate } from "../lib/router";
import { getToken } from "../lib/api";
import { PageHeader, Button } from "../components/ui";
import Icon from "../components/Icon";
import { LEGACY_C } from "../design/tokens";
import {
  OSINTTool, URLDecoder, SafeLinkExtractor, UserAgentParser, RedirectTracer, DiffChecker, BulkLookup, PublicSearch,
} from "../legacy/LegacyComponents";

// Each tool keeps its original, working implementation; the toolkit gives them
// a proper launcher and a consistent frame.
export const TOOLS = [
  { id: "lookup", name: "IOC Lookup", icon: "radar", desc: "DNS, WHOIS/RDAP, Shodan, HaveIBeenPwned and MX for a single target in one tabbed view.", inputs: ["Domain", "IP", "Email"], C: OSINTTool },
  { id: "bulk", name: "Bulk IOC Lookup", icon: "layers", desc: "Paste or upload up to 60 mixed indicators. Classifies, geolocates and scores each against VirusTotal, AbuseIPDB and URLhaus, then adds the ones you pick to the feed.", inputs: ["IP", "Domain", "URL", "Hash", "Email", "File"], C: BulkLookup },
  { id: "urldecode", name: "URL Decoder", icon: "code", desc: "Decode percent-encoding, Base64 and nested encodings to reveal where a link really points.", inputs: ["URL", "Encoded text"], C: URLDecoder },
  { id: "safelinks", name: "Safe Link Extractor", icon: "unlink", desc: "Unwrap Microsoft Safe Links, Proofpoint URL Defense and other rewriters back to the original destination.", inputs: ["Rewritten URL"], C: SafeLinkExtractor },
  { id: "ua", name: "User Agent Parser", icon: "userAgent", desc: "Break a User-Agent string into browser, engine, OS and device — and flag tooling and anomalies.", inputs: ["User-Agent"], C: UserAgentParser },
  { id: "trace", name: "Redirect Tracer", icon: "arrowRight", desc: "Follow a URL's redirect chain hop by hop from the server, with status codes, headers and cookies — without opening it in your browser.", inputs: ["URL"], C: RedirectTracer },
  { id: "diff", name: "Diff Checker", icon: "diff", desc: "Compare two blobs — configs, scripts, IOC lists — line or word level, with an optional AI explanation of what changed.", inputs: ["Text", "Config", "Script"], C: DiffChecker },
  { id: "public", name: "Public Lookup", icon: "globe", desc: "The unauthenticated public lookup view, as external users see it.", inputs: ["Any indicator"], C: PublicSearch },
];

export default function OsintToolkit({ tool }) {
  const t = TOOLS.find(x => x.id === tool);
  if (t) {
    const Comp = t.C;
    return (
      <div className="page">
        <div className="page-head">
          <div className="row" style={{ gap: 12 }}>
            <div className="tool-ico"><Icon name={t.icon} size={18} /></div>
            <div><h1 className="page-title">{t.name}</h1><div className="page-sub">{t.desc}</div></div>
          </div>
          <div className="page-actions">
            <select className="select" value={t.id} onChange={e => navigate(`/osint/${e.target.value}`)} aria-label="Switch tool">
              {TOOLS.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}
            </select>
            <Button size="sm" icon="grid" onClick={() => navigate("/osint")}>All tools</Button>
          </div>
        </div>
        <div className="legacy-host"><Comp token={getToken()} C={LEGACY_C} /></div>
      </div>
    );
  }
  return (
    <div className="page">
      <PageHeader title="OSINT Toolkit" sub="Analyst utilities for enrichment, link analysis and triage." />
      <div className="grid g4">
        {TOOLS.map(x => (
          <div key={x.id} className="tool-card" role="link" tabIndex={0} onClick={() => navigate(`/osint/${x.id}`)} onKeyDown={e => e.key === "Enter" && navigate(`/osint/${x.id}`)}>
            <div className="tool-ico"><Icon name={x.icon} size={18} /></div>
            <div className="tool-name">{x.name}</div>
            <div className="tool-desc">{x.desc}</div>
            <div className="row wrap" style={{ gap: 4 }}>{x.inputs.map(i => <span key={i} className="tag">{i}</span>)}</div>
            <div className="tool-open">Open tool <Icon name="arrowRight" size={13} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}
