/* eslint-disable no-script-url -- the tests feed hostile javascript: URLs on purpose */
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { safeUrl } from "../lib/safe";
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
