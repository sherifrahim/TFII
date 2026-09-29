/* eslint-disable no-script-url -- the tests feed hostile javascript: URLs on purpose */
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { safeUrl, installLinkGuard } from "../lib/safe";
import { geoFacts, regionName } from "../lib/geo";
import { runningBundle, servedBundle, isStale } from "../lib/update";
import { dnsHost, DnsResult, HistoryList } from "../pages/entity/DnsPanel";
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
