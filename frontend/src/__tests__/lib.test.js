/* eslint-disable no-script-url -- the tests feed hostile javascript: URLs on purpose */
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { safeUrl, installLinkGuard } from "../lib/safe";
import { geoFacts, regionName } from "../lib/geo";
import { runningBundle, servedBundle, isStale } from "../lib/update";
import { dnsHost, DnsResult, HistoryList } from "../pages/entity/DnsPanel";
import { MailSignals, ExposureResult, RiskResult, DeepResult, mailForAi } from "../pages/entity/MailPanel";
import { previewTokens, csvCell, resultsToCsv, digestRows } from "../pages/BulkLookup";
import { aiToMarkdown, AiAnswer } from "../components/AiPanel";
import { filtersSummary } from "../pages/Iocs";
import { Section } from "../pages/Report";
import { readReportItems, reportToMarkdown } from "../lib/report";
import { entityPath, canonicalKind, KINDS } from "../lib/entity";
import { entityRoute } from "../lib/router";
import { detectType, refang, defang, confBand } from "../lib/format";
import { StatusBadge, Badge } from "../components/ui";
import { hitRoute, HitBadges } from "../components/SearchHit";

describe("safeUrl — only plain http(s) may become a link", () => {
  test.each([
    ["https://example.com/a?b=1", true], ["http://example.com", true],
    ["javascript:alert(1)", false], ["JaVaScRiPt:alert(1)", false], ["data:text/html,x", false],
    ["//evil.example", false], ["", false], [null, false], [undefined, false], ["https://a b.com", false],
    ["https://x.com/\u0001", false], ["ftp://x.com", false],
  ])("%s → %s", (u, ok) => expect(!!safeUrl(u)).toBe(ok));
});

describe("link guard — blocks hostile links but not the page's own downloads", () => {
  let off;
  beforeEach(() => { off = installLinkGuard(); });
  afterEach(() => { off(); document.body.innerHTML = ""; });

  // Was the click stopped by the guard?  A blocked click never reaches the later bubbling listener (the guard
  // stops propagation); an allowed one does, and that listener cancels it so jsdom does not try to navigate.
  function blocked(href, download) {
    const a = document.createElement("a");
    a.setAttribute("href", href);
    if (download) a.setAttribute("download", "x.csv");
    document.body.appendChild(a);
    let reached = false, prevented = false;
    const spy = e => { reached = true; prevented = e.defaultPrevented; e.preventDefault(); };
    document.addEventListener("click", spy);
    a.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    document.removeEventListener("click", spy);
    return !reached || prevented;
  }
  const own = () => `blob:${window.location.origin}/0f8fad5b-d9cb-469f-a165-70867728950e`;

  test("the CSV/report/attachment downloads still work", () => {
    expect(blocked(own(), true)).toBe(false);
  });
  test("hostile or unrelated links are still refused", () => {
    expect(blocked("javascript:alert(1)", false)).toBe(true);
    expect(blocked("javascript:alert(1)", true)).toBe(true);
    expect(blocked("data:text/html,<script>alert(1)</script>", true)).toBe(true);
    expect(blocked(own(), false)).toBe(true);                                   // a blob link that navigates, not downloads
    expect(blocked("blob:https://evil.example/abc", true)).toBe(true);          // someone else's blob
    expect(blocked("https://example.com/", false)).toBe(false);                 // ordinary links unchanged
    expect(blocked("#/iocs", false)).toBe(false);
  });
});

describe("location facts are labelled for what they are", () => {
  const by = f => Object.fromEntries(f.map(x => [x.label, x]));
  test("a .mu domain hosted in Italy: hosting is not presented as origin, the registry is separate", () => {
    const f = by(geoFacts({ kind: "hosting", country: "Italy", countries: [{ code: "IT", name: "Italy" }], cctld_country_code: "MU", note: "n" }));
    expect(f["Hosted in"].value).toBe("Italy");
    expect(f["TLD registry"].value).toBe("Mauritius (.mu)");
    expect(f["TLD registry"].tone).toBe("muted");
    expect(f["IP location"]).toBeUndefined();
  });
  test("behind a CDN the edge country is shown but labelled as the CDN's node, not the site's location", () => {
    const f = by(geoFacts({ kind: "cdn_edge", cdn: "Cloudflare", country: null, edge_country: "Italy", cctld_country_code: "MU" }));
    expect(Object.keys(f)).toEqual(["Behind CDN", "CDN edge node", "TLD registry"]);
    expect(f["CDN edge node"]).toMatchObject({ value: "Italy", tone: "muted" });
    expect(f["Behind CDN"].value).toMatch(/Cloudflare.*hidden/);
    expect(f["Hosted in"]).toBeUndefined();
    expect(f["IP location"]).toBeUndefined();
  });
  test("registration facts: registrar, age and registrant country", () => {
    const f = by(geoFacts({ kind: "unknown", registration: { registrar: "Namecheap, Inc.", created: "2026-09-26", country: "MU" } }));
    expect(f["Registered"].value).toContain("Namecheap, Inc.");
    expect(f["Registered"].value).toContain("2026-09-26");
    expect(f["Registrant country"].value).toBe("Mauritius");
    expect(geoFacts({ kind: "hosting", country: "Italy", registration: {} }).map(x => x.label)).toEqual(["Hosted in"]);
  });
  test("an IP is an IP location, and a disagreement between sources is flagged", () => {
    const f = by(geoFacts({ kind: "ip", country: "Italy", agreement: "differ", other_sources: { AbuseIPDB: "DE" } }));
    expect(f["IP location"].value).toBe("Italy");
    expect(f["Disagrees with"]).toMatchObject({ value: "AbuseIPDB: Germany", tone: "warn" });
  });
  test("nothing to show, and .uk, are handled", () => {
    expect(geoFacts(null)).toEqual([]);
    expect(geoFacts({ kind: "hosting", country: "Italy", cctld_country_code: "GB" }).find(x => x.label === "TLD registry").value).toBe("United Kingdom (.uk)");
    expect(regionName("")).toBe("");
  });
});

describe("stale tab detection", () => {
  const html = '<script defer="defer" src="/ui/static/js/main.7678bbfb.js"></script>';
  test("finds the bundle a page is running and the one the server serves", () => {
    expect(runningBundle(["/ui/static/js/main.aaaa1111.js"])).toBe("main.aaaa1111.js");
    expect(runningBundle([{ getAttribute: () => "/ui/static/js/main.aaaa1111.js" }, { getAttribute: () => null }])).toBe("main.aaaa1111.js");
    expect(runningBundle(["/other.js", null, undefined])).toBeNull();
    expect(servedBundle(html)).toBe("main.7678bbfb.js");
    expect(servedBundle("<html></html>")).toBeNull();
    // Vite names bundles with URL-safe base64 hashes, which can contain "-" and "_"
    expect(servedBundle('<script type="module" src="/ui/static/js/main.CzfmmHWo.js"></script>')).toBe("main.CzfmmHWo.js");
    expect(runningBundle(["/ui/static/js/main.B-x_9Qa2.js"])).toBe("main.B-x_9Qa2.js");
  });
  test("only a different bundle counts as stale; unknowns never do", () => {
    expect(isStale("main.aaaa1111.js", "main.7678bbfb.js")).toBe(true);
    expect(isStale("main.7678bbfb.js", "main.7678bbfb.js")).toBe(false);
    expect(isStale(null, "main.7678bbfb.js")).toBe(false);
    expect(isStale("main.aaaa1111.js", null)).toBe(false);
  });
});

describe("DNS panel", () => {
  test("only domains and URLs with a real host are looked up", () => {
    expect(dnsHost("Shop.Example.com.", "Domain")).toBe("shop.example.com");
    expect(dnsHost("hxxp://Evil.example.mu/login?a=1", "URL")).toBe("evil.example.mu");
    expect(dnsHost("http://1.2.3.4/x", "URL")).toBe("");
    expect(dnsHost("http://[2001:db8::1]/x", "URL")).toBe("");
    expect(dnsHost("1.2.3.4", "IPv4")).toBe("");
    expect(dnsHost("not a url", "URL")).toBe("");
    expect(dnsHost("", "Domain")).toBe("");
    expect(dnsHost("Alice@Mail.Example.com", "Email")).toBe("mail.example.com");
    expect(dnsHost("a@b@example.com", "Email")).toBe("");
    expect(dnsHost("no-at-sign", "Email")).toBe("");
    expect(dnsHost("a@1.2.3.4", "Email")).toBe("");
  });
  test("renders the records, the observations and the mail authentication", () => {
    const d = {
      addresses: [{ ip: "140.82.121.4", geo: { org: "Github Inc.", asn: "AS36459", city: "San Francisco", country: "United States" } }, { ip: "1.1.1.1", geo: null }],
      cname: [], ns: ["dns1.p08.nsone.net"], mx: [{ priority: 0, host: "mail.example.com" }], txt: ["v=spf1 -all"],
      soa: { host: "ns1.example.com.", admin: "hostmaster.example.com.", serial: 7 }, caa: [{ tag: "issue", value: "digicert.com" }],
      spf: { record: "v=spf1 -all" }, dmarc: { record: "v=DMARC1; p=none", policy: "none" },
      signals: [{ level: "warn", text: "No CAA record" }, { level: "ok", text: "fine" }],
    };
    const html = renderToStaticMarkup(<DnsResult d={d} />);
    for (const t of ["140.82.121.4", "Github Inc.", "AS36459", "San Francisco, United States", "no network data", "dns1.p08.nsone.net", "mail.example.com",
      "v=spf1 -all", "p=none", "digicert.com", "hostmaster.example.com.", "No CAA record", "Check", "Good"]) expect(html).toContain(t);
  });
  test("past addresses say which are not a CDN, and what to conclude when all are", () => {
    const some = renderToStaticMarkup(<HistoryList h={{ total: 2, not_cdn: 1, addresses: [
      { ip: "104.16.1.1", cdn: "Cloudflare", org: "Cloudflare, Inc.", asn: "AS13335", country: "United States", last_seen: "2026-09-20" },
      { ip: "93.184.216.34", cdn: null, org: "Example Hosting", asn: "AS64500", country: "Germany", last_seen: "2023-11-14" }] }} />);
    for (const t of ["1 of 2 past addresses", "not a CDN", "CDN: Cloudflare", "Example Hosting", "Germany", "last seen 2023-11-14", "best clue"]) expect(some).toContain(t);
    const none = renderToStaticMarkup(<HistoryList h={{ total: 1, not_cdn: 0, addresses: [{ ip: "104.16.1.1", cdn: "Cloudflare" }] }} />);
    expect(none).toContain("no earlier origin on record");
    expect(renderToStaticMarkup(<HistoryList h={{ total: 0, not_cdn: 0, addresses: [] }} />)).toContain("no earlier addresses");
  });
  test("missing records read as 'not published', not as errors", () => {
    const html = renderToStaticMarkup(<DnsResult d={{ addresses: [], cname: ["alias.example.com."], ns: [], mx: [], txt: [], soa: null, caa: [], spf: null, dmarc: null, signals: [] }} />);
    expect(html).toContain("CNAME → alias.example.com.");
    expect(html).toContain("No MX records");
    expect(html.match(/not published/g).length).toBe(2);
  });
});

describe("entity routing", () => {
  test("every kind has a page except sources", () => {
    for (const k of ["indicator", "cve", "malware", "actor", "campaign", "software", "investigation"]) expect(entityPath(k, "x")).toBeTruthy();
    expect(entityPath("source", "x")).toBeNull();
  });
  test("legacy kind names map to canonical kinds", () => {
    expect(canonicalKind("ioc")).toBe("indicator");
    expect(canonicalKind("observable")).toBe("indicator");
    expect(canonicalKind("asset")).toBe("software");
  });
  test("refs are URL-encoded so indicator values with slashes and colons survive", () => {
    expect(entityPath("indicator", "http://evil.example/a?b=c")).toBe("/observable/http%3A%2F%2Fevil.example%2Fa%3Fb%3Dc");
    expect(entityPath("indicator", "2001:db8::1")).toBe("/observable/2001%3Adb8%3A%3A1");
  });
  test("investigation context is carried as ?inv=", () => {
    expect(entityPath("cve", "CVE-2099-0001", "inv-1")).toBe("/cve/CVE-2099-0001?inv=inv-1");
    expect(entityRoute("ioc", "indicator--1", "inv-1")).toBe("/observable/indicator--1?inv=inv-1");
    expect(entityRoute("software", "asset--1")).toBe("/software/asset--1");
  });
  test("unknown kinds fall back to home rather than a broken link", () => expect(entityRoute("spaceship", "x")).toBe("/"));
  test("every linkable kind is described for the UI", () => {
    for (const k of Object.keys(KINDS)) { expect(KINDS[k].label).toBeTruthy(); expect(KINDS[k].icon).toBeTruthy(); }
  });
});

describe("indicator helpers", () => {
  test("refang / defang round trip", () => {
    expect(refang("hxxp://evil[.]example/x")).toBe("http://evil.example/x");
    expect(defang("http://evil.example/x", "URL")).toMatch(/hxxp/);
  });
  test.each([["1.2.3.4", "IPv4"], ["evil.example", "Domain"], ["http://evil.example/x", "URL"], ["CVE-2024-1234", "CVE"], ["a".repeat(64), "SHA256"], ["a".repeat(32), "MD5"]])(
    "detectType(%s) = %s", (v, t) => expect(detectType(v)).toBe(t));
  test("confidence bands match the backend severity bands", () => {
    expect(confBand(95)).toBe("critical"); expect(confBand(80)).toBe("high"); expect(confBand(60)).toBe("medium"); expect(confBand(10)).toBe("low");
  });
});

describe("status vocabulary", () => {
  test.each(["active", "suspicious", "confirmed", "unknown", "expired", "false_positive", "untracked", "known_exploited"])("%s renders a label", s => {
    expect(renderToStaticMarkup(<StatusBadge status={s} />)).toMatch(/badge/);
  });
  test("unknown statuses are shown, not hidden", () => expect(renderToStaticMarkup(<StatusBadge status="on_hold" />)).toMatch(/on hold/));
  test("text is rendered escaped — stored markup never becomes HTML", () => {
    expect(renderToStaticMarkup(<Badge>{"<img src=x onerror=alert(1)>"}</Badge>)).not.toMatch(/<img/);
  });
});

describe("search hits", () => {
  test("hits route to their entity page", () => {
    expect(hitRoute({ kind: "cve", ref: "CVE-2099-0001" })[0]).toBe("/cve/CVE-2099-0001");
    expect(hitRoute({ kind: "software", ref: "asset--1" })[0]).toBe("/software/asset--1");
    expect(hitRoute({ kind: "indicator", ref: "evil.example" })[0]).toBe("/observable/evil.example");
  });
  test("notes route into their investigation", () => {
    expect(hitRoute({ kind: "note", ref: "n1", investigation_id: "inv-1" })).toEqual(["/investigations/inv-1", { tab: "notes" }]);
    expect(hitRoute({ kind: "note", ref: "n1" })[0]).toBe("/workspace");
  });
  test("a kind the UI has never heard of does not crash the result list", () => {
    expect(hitRoute({ kind: "certificate", ref: "x" })[0]).toBe("/");
    expect(renderToStaticMarkup(<HitBadges h={{ kind: "certificate" }} />)).toBe("");
  });
});

describe("mail address panel", () => {
  test("shows the domain's mail setup and what was noticed, as facts", () => {
    const mail = { domain: "new-shop.example", provider_kind: null, registration: { registrar: "R", created: "2026-09-25" },
      posture: { checked: true, mx: [{ priority: 10, host: "mx.new-shop.example" }], spf: null, dmarc: { policy: "none", record: "v=DMARC1; p=none" } },
      signals: [{ level: "warn", text: "No SPF record", code: "no_spf" }, { level: "info", text: "DMARC policy is 'none'", code: "dmarc_none" }] };
    const html = renderToStaticMarkup(<MailSignals mail={mail} />);
    for (const t of ["new-shop.example", "No SPF record", "Check", "Note", "10 mx.new-shop.example", "p=none", "not published", "R"]) expect(html).toContain(t);
    expect(renderToStaticMarkup(<MailSignals mail={null} />)).toBe("");
  });
  test("a clean breach answer is not proof of safety, and a hit lists the breaches", () => {
    expect(renderToStaticMarkup(<ExposureResult r={{ found: false, count: 0, breaches: [] }} />)).toContain("not proof");
    const html = renderToStaticMarkup(<ExposureResult r={{ found: true, count: 2, breaches: ["Adobe", "LinkedIn"] }} />);
    for (const t of ["2", "breaches", "Adobe", "LinkedIn"]) expect(html).toContain(t);
    expect(renderToStaticMarkup(<ExposureResult r={{ found: true, count: 1, breaches: ["Adobe"] }} />)).toContain("1</strong> known breach include");
  });
  test("an address risk answer shows the score as an estimate and only the facts it has", () => {
    const html = renderToStaticMarkup(<RiskResult r={{ fraud_score: 88, valid: true, disposable: false, recent_abuse: true, leaked: null, spam_trap: "none", first_seen: "2 days ago" }} />);
    for (const t of ["fraud score 88 / 100", "not proof", "Recent abuse", "yes", "Disposable", "no", "2 days ago"]) expect(html).toContain(t);
    expect(html).not.toContain("In a data leak");
    expect(html).not.toContain("Spam trap");
    expect(renderToStaticMarkup(<RiskResult r={{ fraud_score: null }} />)).toContain("no score");
  });
  test("deep analysis lists what failed and warned per test, and says what the plan could not run", () => {
    const r = { summary: { failed: 1, warnings: 1, passed: 3 }, errors: { blacklist: { kind: "forbidden", message: "Not included in this MxToolbox plan" } }, checks: {
      spf: { failed: [{ name: "SPF Record Published", info: "No SPF record found" }], warnings: [], passed: [{ name: "a" }], timeouts: [] },
      dmarc: { failed: [], warnings: [{ name: "DMARC Policy Not Enabled", info: "p=none" }], passed: [{ name: "b" }, { name: "c" }], timeouts: [] },
      mx: { failed: [], warnings: [], passed: [], timeouts: [] } } };
    const html = renderToStaticMarkup(<DeepResult r={r} />);
    for (const t of ["1 failed", "1 warnings", "3 passed", "SPF Record Published", "No SPF record found", "DMARC Policy Not Enabled", "Nothing to report", "Blocklists", "Not included in this MxToolbox plan"]) expect(html).toContain(t);
  });
});

describe("bulk lookup helpers", () => {
  test("live counts describe what was pasted, defanged or not, once per value", () => {
    const p = previewTokens("8.8.8.8\nevil[.]com, evil[.]com\nhxxp://bad[.]site/x\n  d41d8cd98f00b204e9800998ecf8427e\ntest[at]phish.net");
    expect(p.total).toBe(5);
    expect(p.counts).toEqual({ IP: 1, domain: 1, URL: 1, hash: 1, email: 1 });
    expect(previewTokens("").total).toBe(0);
  });
  test("CSV cells are quoted and spreadsheet formulas are defused", () => {
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("=HYPERLINK(\"http://x\")")).toMatch(/^"?'=/);
    expect(csvCell("plain")).toBe("plain");
    const csv = resultsToCsv([{ input: "evil[.]com", refanged: "evil.com", type: "Domain", verdict: "malicious", score: 88, reason: "r", geo: { kind: "hosting", country: "Italy", cctld_country_code: "MU", org: "Aruba" }, already_tracked: true }]);
    const lines = csv.split("\r\n");
    expect(lines[0].startsWith("input,refanged,type,verdict")).toBe(true);
    expect(lines[1]).toContain("Italy,hosting,Mauritius,Aruba");
    expect(lines[1].endsWith("yes")).toBe(true);
  });
});

describe("detailed report", () => {
  test("each kind of section renders its values as text", () => {
    const kv = renderToStaticMarkup(<Section s={{ title: "Detections", type: "kv", rows: [["Malicious", "14"]] }} />);
    expect(kv).toContain("Detections"); expect(kv).toContain("Malicious"); expect(kv).toContain("14");
    const tb = renderToStaticMarkup(<Section s={{ title: "Engines", type: "table", cols: ["Engine", "Result"], rows: [["BadAV", "<script>x</script>"]] }} />);
    expect(tb).toContain("BadAV"); expect(tb).not.toContain("<script>"); expect(tb).toContain("&lt;script&gt;");     // provider text is never markup
    expect(renderToStaticMarkup(<Section s={{ title: "Tags", type: "tags", items: ["dga", "phishing"] }} />)).toContain("phishing");
    expect(renderToStaticMarkup(<Section s={{ title: "WHOIS", type: "text", text: "Domain Name: X" }} />)).toContain("Domain Name: X");
  });
  test("the report is opened from the URL or from a parked list, never more than 25", () => {
    expect(readReportItems({ items: JSON.stringify(["a.example", "1.2.3.4"]) })).toEqual(["a.example", "1.2.3.4"]);
    expect(readReportItems({ items: "not json" })).toEqual([]);
    expect(readReportItems({})).toEqual([]);
    expect(readReportItems({ items: JSON.stringify(Array.from({ length: 40 }, (_, i) => `h${i}.example`)) })).toHaveLength(25);
  });
  test("Markdown carries what was scanned, what was not, and the section data", () => {
    const md = reportToMarkdown([{ value: "evil.example", defanged: "evil[.]example", type: "Domain", verdict: "malicious", score: 88, reason: "why",
      providers: [{ id: "virustotal", name: "VirusTotal", status: "ok", headline: "14 of 90 engines flagged it", message: "", sections: [{ title: "Detections", type: "kv", rows: [["Malicious", "14"]] }, { title: "Engines", type: "table", cols: ["Engine", "Result"], rows: [["BadAV", "a|b"]] }] },
        { id: "abuseipdb", name: "AbuseIPDB", status: "skipped", message: "No API key available for this provider", headline: "", sections: [] }], tfii: [] }]);
    for (const t of ["# TFII detailed report", "## evil[.]example", "Verdict: Malicious (88)", "VirusTotal: 14 of 90 engines flagged it", "AbuseIPDB: not scanned", "### VirusTotal: Detections", "**Malicious:** 14", "| Engine | Result |", "a\\|b"]) expect(md).toContain(t);
  });
});

describe("AI assistants", () => {
  const answer = { provider: "Groq", result: { headline: "Two providers flag it", summary: "VirusTotal and AbuseIPDB agree.", points: ["14/90 engines"], next_steps: ["Block it"], caveats: ["URLhaus did not scan"] } };

  test("an answer is shown as plain text, labelled as AI-generated, never as markup", () => {
    const hostile = { provider: "Groq", result: { headline: "<img src=x onerror=alert(1)>", summary: "<script>alert(1)</script>", points: [], next_steps: [], caveats: [] } };
    const html = renderToStaticMarkup(<AiAnswer title="AI summary" answer={hostile} />);
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
    const shown = renderToStaticMarkup(<AiAnswer title="AI summary" answer={answer} />);
    expect(shown).toContain("AI-generated by Groq");
    expect(shown).toContain("Next steps");
    expect(shown).toContain("Caveats");
  });

  test("the Markdown copy carries the sections and the AI-generated note", () => {
    const md = aiToMarkdown("AI summary", answer.result);
    expect(md).toContain("## AI summary");
    expect(md).toContain("- 14/90 engines");
    expect(md).toContain("### Next steps");
    expect(md).toContain("AI-generated");
    expect(aiToMarkdown("x", null)).toBe("");
  });

  test("the bulk digest gets one compact line per result, capped, with no raw provider data", () => {
    const many = Array.from({ length: 200 }, (_, i) => ({ defanged: `h${i}[.]example`, type: "Domain", verdict: "malicious", score: 90.4, reason: "x".repeat(900), enrichment: { secret: "nope" }, geo: { country: "Germany", org: "Host GmbH" } }));
    const rows = digestRows(many);
    expect(rows).toHaveLength(150);
    expect(rows[0]).toEqual({ value: "h0[.]example", type: "Domain", verdict: "malicious", score: 90, reason: "x".repeat(400), country: "Germany", owner: "Host GmbH" });
    expect(JSON.stringify(rows)).not.toContain("nope");
  });

  test("the mail explanation is given the domain checks, not raw records", () => {
    const out = mailForAi({ domain: "x.example", provider_kind: "free", verdict: "unknown", signals: [{ level: "warn", text: "No DMARC", extra: 1 }],
      posture: { spf: { record: "v=spf1 -all", parts: [1, 2, 3] }, dmarc: null, mx: [{ host: "mx1.x.example", priority: 10 }] }, registration: { created: "2026-09-01" } });
    expect(out).toEqual({ domain: "x.example", provider_kind: "free", verdict: "unknown", registration: { created: "2026-09-01" },
      signals: [{ level: "warn", text: "No DMARC" }], spf: "v=spf1 -all", dmarc: undefined, mail_servers: ["mx1.x.example"] });
    expect(mailForAi(null)).toEqual({});
  });

  test("the filters the AI chose are listed in words so the analyst can see what was applied", () => {
    expect(filtersSummary({ type: "ip", severity: "high", since_days: 7, bogus: "x" })).toBe("type: ip · severity: high · first seen (days): 7");
    expect(filtersSummary({})).toBe("");
  });
});
