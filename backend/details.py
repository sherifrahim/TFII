"""Detailed provider results for one indicator, as plain display sections.

Each provider's answer holds far more than the verdict TFII shows in a table row. These pure functions turn the raw
answers into a small, uniform structure the "Detailed report" screen can render without knowing any provider:

    {"title": str, "type": "kv",     "rows": [[label, value], ...]}
    {"title": str, "type": "table",  "cols": [str, ...], "rows": [[cell, ...], ...]}
    {"title": str, "type": "tags",   "items": [str, ...]}
    {"title": str, "type": "text",   "text": str}

Everything is bounded (rows, string lengths): provider text is attacker-influenced (comments, page titles, file
names) and is only ever displayed as text. Nothing here makes a request.
"""
from datetime import datetime, timezone
from typing import Any, List, Optional

MAX_ROWS = 60


def _s(v: Any, n: int = 300) -> str:
    return "" if v is None else str(v)[:n]


def _ts(v: Any) -> Optional[str]:
    """Unix seconds -> 'YYYY-MM-DD HH:MM UTC'."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
        return None
    try:
        return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return None


def kv(title: str, rows) -> Optional[dict]:
    rows = [[k, _s(v)] for k, v in rows if v not in (None, "", [], {})]
    return {"title": title, "type": "kv", "rows": rows} if rows else None


def table(title: str, cols: List[str], rows: List[list]) -> Optional[dict]:
    rows = [[_s(c) for c in r] for r in rows[:MAX_ROWS]]
    return {"title": title, "type": "table", "cols": cols, "rows": rows} if rows else None


def tags(title: str, items) -> Optional[dict]:
    items = [_s(i, 80) for i in (items or []) if i][:MAX_ROWS]
    return {"title": title, "type": "tags", "items": items} if items else None


def text(title: str, value: Any, n: int = 1500) -> Optional[dict]:
    t = _s(value, n).strip()
    return {"title": title, "type": "text", "text": t} if t else None


def _clean(sections) -> List[dict]:
    return [s for s in sections if s]


# ── VirusTotal ────────────────────────────────────────────────────────────────
def _engine_rows(results: dict) -> List[list]:
    rows = []
    for name, r in (results or {}).items():
        if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious"):
            rows.append([r.get("engine_name") or name, r["category"], r.get("result") or r.get("method") or ""])
    rows.sort(key=lambda x: (x[1] != "malicious", x[0].lower()))
    return rows


def _cert(c: Any) -> Optional[dict]:
    if not isinstance(c, dict):
        return None
    issuer, subject, valid = c.get("issuer") or {}, c.get("subject") or {}, c.get("validity") or {}
    return kv("HTTPS certificate", [
        ("Subject", subject.get("CN")), ("Issuer", issuer.get("O") or issuer.get("CN")),
        ("Valid from", valid.get("not_before")), ("Valid until", valid.get("not_after")),
        ("SHA-256", c.get("thumbprint_sha256")), ("Serial", c.get("serial_number")),
    ])


def vt_sections(kind: str, attrs: dict) -> List[dict]:
    """kind: ip | domain | url | file | analysis (the first scan of a newly submitted URL)."""
    a = attrs if isinstance(attrs, dict) else {}
    stats = a.get("last_analysis_stats") or a.get("stats") or {}
    votes = a.get("total_votes") or {}
    out = [kv("Detections", [
        ("Malicious", stats.get("malicious")), ("Suspicious", stats.get("suspicious")), ("Harmless", stats.get("harmless")),
        ("Undetected", stats.get("undetected")), ("Timed out", stats.get("timeout")),
        ("Community votes", f"{votes.get('malicious', 0)} malicious / {votes.get('harmless', 0)} harmless" if votes else None),
        ("Reputation", a.get("reputation")), ("Last analysed", _ts(a.get("last_analysis_date") or a.get("date"))),
    ])]
    flagged = _engine_rows(a.get("last_analysis_results") or a.get("results") or {})
    out.append(table(f"Engines that flagged it ({len(flagged)})", ["Engine", "Verdict", "Result"], flagged))
    cats = a.get("categories")
    if isinstance(cats, dict) and cats:
        out.append(table("Categories", ["Vendor", "Category"], sorted([[k, v] for k, v in cats.items()])))
    elif isinstance(cats, list):
        out.append(tags("Categories", cats))
    out.append(tags("Tags", a.get("tags")))
    out.append(tags("Threat names", a.get("threat_names")))

    if kind == "ip":
        out.append(kv("Network", [("Owner", a.get("as_owner")), ("ASN", a.get("asn")), ("Network", a.get("network")), ("Country", a.get("country")),
                                  ("Continent", a.get("continent")), ("Registry", a.get("regional_internet_registry")), ("JARM", a.get("jarm"))]))
        out.append(_cert(a.get("last_https_certificate")))
        out.append(text("WHOIS", a.get("whois")))
    elif kind == "domain":
        ranks = a.get("popularity_ranks") or {}
        out.append(kv("Registration", [("Registrar", a.get("registrar")), ("Created", _ts(a.get("creation_date"))), ("Updated", _ts(a.get("last_update_date"))),
                                       ("TLD", a.get("tld")), ("Country", a.get("country"))]))
        if ranks:
            out.append(table("Popularity ranks", ["List", "Rank"], sorted([[k, (v or {}).get("rank", "")] for k, v in ranks.items()])))
        recs = [[r.get("type"), r.get("value"), r.get("ttl")] for r in (a.get("last_dns_records") or []) if isinstance(r, dict)]
        out.append(table(f"DNS records VirusTotal last saw ({len(recs)})", ["Type", "Value", "TTL"], recs))
        out.append(_cert(a.get("last_https_certificate")))
        out.append(text("WHOIS", a.get("whois")))
    elif kind == "url":
        out.append(kv("Page", [("Final URL", a.get("last_final_url")), ("Title", a.get("title")), ("HTTP status", a.get("last_http_response_code")),
                               ("Size (bytes)", a.get("last_http_response_content_length")), ("First submitted", _ts(a.get("first_submission_date"))),
                               ("Last submitted", _ts(a.get("last_submission_date"))), ("Times submitted", a.get("times_submitted"))]))
        chain = a.get("redirection_chain")
        if isinstance(chain, list) and len(chain) > 1:
            out.append(table("Redirection chain", ["Hop", "URL"], [[i + 1, u] for i, u in enumerate(chain)]))
        trackers = a.get("trackers")
        if isinstance(trackers, dict) and trackers:
            out.append(tags("Trackers", sorted(trackers)))
    elif kind == "file":
        pc = a.get("popular_threat_classification") or {}
        out.append(kv("File", [("Name", a.get("meaningful_name")), ("Type", a.get("type_description")), ("Size (bytes)", a.get("size")),
                               ("MD5", a.get("md5")), ("SHA-1", a.get("sha1")), ("SHA-256", a.get("sha256")), ("Magic", a.get("magic")),
                               ("ssdeep", a.get("ssdeep")), ("TLSH", a.get("tlsh")), ("First submitted", _ts(a.get("first_submission_date"))),
                               ("Last submitted", _ts(a.get("last_submission_date"))), ("Times submitted", a.get("times_submitted"))]))
        out.append(kv("Threat classification", [("Suggested label", pc.get("suggested_threat_label")),
                                                ("Categories", ", ".join(f"{x.get('value')} ({x.get('count')})" for x in (pc.get("popular_threat_category") or [])[:6])),
                                                ("Family names", ", ".join(f"{x.get('value')} ({x.get('count')})" for x in (pc.get("popular_threat_name") or [])[:6]))]))
        out.append(tags("Other names", a.get("names")))
        sb = a.get("sandbox_verdicts") or {}
        out.append(table("Sandbox verdicts", ["Sandbox", "Verdict", "Classification"],
                         [[k, (v or {}).get("category"), ", ".join((v or {}).get("malware_classification") or (v or {}).get("malware_names") or [])] for k, v in sb.items()]))
        yara = [[y.get("rule_name"), y.get("ruleset_name"), y.get("source")] for y in (a.get("crowdsourced_yara_results") or []) if isinstance(y, dict)]
        out.append(table(f"Crowdsourced YARA matches ({len(yara)})", ["Rule", "Ruleset", "Source"], yara))
        sig = a.get("signature_info") or {}
        out.append(kv("Signature", [("Verified", sig.get("verified")), ("Signers", sig.get("signers")), ("Product", sig.get("product")), ("Description", sig.get("description"))]))
    return _clean(out)


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
ABUSE_CATEGORIES = {
    1: "DNS compromise", 2: "DNS poisoning", 3: "Fraud orders", 4: "DDoS attack", 5: "FTP brute force", 6: "Ping of death", 7: "Phishing",
    8: "Fraud VoIP", 9: "Open proxy", 10: "Web spam", 11: "Email spam", 12: "Blog spam", 13: "VPN IP", 14: "Port scan", 15: "Hacking",
    16: "SQL injection", 17: "Spoofing", 18: "Brute force", 19: "Bad web bot", 20: "Exploited host", 21: "Web app attack", 22: "SSH", 23: "IoT targeted",
}


def abuse_sections(data: dict) -> List[dict]:
    d = data if isinstance(data, dict) else {}
    out = [kv("Reputation", [
        ("Abuse confidence", f"{d.get('abuseConfidenceScore')}%" if d.get("abuseConfidenceScore") is not None else None),
        ("Total reports (90 days)", d.get("totalReports")), ("Distinct reporters", d.get("numDistinctUsers")), ("Last reported", d.get("lastReportedAt")),
        ("Whitelisted", d.get("isWhitelisted")), ("Tor exit node", d.get("isTor")),
    ]), kv("Network", [("ISP", d.get("isp")), ("Usage type", d.get("usageType")), ("Domain", d.get("domain")), ("Country", d.get("countryName") or d.get("countryCode")),
                       ("Hostnames", ", ".join(d.get("hostnames") or []))])]
    reports = [r for r in (d.get("reports") or []) if isinstance(r, dict)]
    if reports:
        counts: dict = {}
        for r in reports:
            for c in r.get("categories") or []:
                counts[c] = counts.get(c, 0) + 1
        out.append(table("What it was reported for", ["Category", "Reports"],
                         [[ABUSE_CATEGORIES.get(c, f"Category {c}"), n] for c, n in sorted(counts.items(), key=lambda x: -x[1])]))
        out.append(table(f"Recent reports ({len(reports)})", ["Reported", "Categories", "Comment", "From"],
                         [[r.get("reportedAt"), ", ".join(ABUSE_CATEGORIES.get(c, str(c)) for c in (r.get("categories") or [])), _s(r.get("comment"), 220),
                           r.get("reporterCountryCode")] for r in reports[:12]]))
    return _clean(out)


# ── URLhaus ───────────────────────────────────────────────────────────────────
def urlhaus_sections(kind: str, data: dict) -> List[dict]:
    d = data if isinstance(data, dict) else {}
    bl = d.get("blacklists") or {}
    out = [kv("Listing", [
        ("Host", d.get("host")), ("Status", d.get("url_status")), ("Threat", d.get("threat")), ("First seen", d.get("firstseen") or d.get("date_added")),
        ("URLs on this host", d.get("url_count")), ("Reporter", d.get("reporter")), ("Takedown (seconds)", d.get("takedown_time_seconds")),
        ("Spamhaus DBL", bl.get("spamhaus_dbl")), ("SURBL", bl.get("surbl")),
    ]), tags("Tags", d.get("tags"))]
    urls = [u for u in (d.get("urls") or []) if isinstance(u, dict)]
    out.append(table(f"URLs seen on this host ({len(urls)})", ["Added", "Status", "Threat", "URL"],
                     [[u.get("date_added"), u.get("url_status"), u.get("threat"), _s(u.get("url"), 200)] for u in urls[:25]]))
    payloads = [p for p in (d.get("payloads") or []) if isinstance(p, dict)]
    out.append(table(f"Payloads served ({len(payloads)})", ["First seen", "File", "Type", "Signature", "SHA-256"],
                     [[p.get("firstseen"), p.get("filename"), p.get("file_type"), p.get("signature"), p.get("response_sha256")] for p in payloads[:20]]))
    return _clean(out)


# ── TFII's own analysis ───────────────────────────────────────────────────────
def geo_sections(geo: Optional[dict]) -> List[dict]:
    if not geo:
        return []
    names = ", ".join(c.get("name") or c.get("code") or "" for c in (geo.get("countries") or []))
    reg = geo.get("registration") or {}
    return _clean([kv("Location", [
        ("Kind", geo.get("kind")), ("Country", geo.get("country") or names), ("CDN edge node", geo.get("edge_country")), ("Behind CDN", geo.get("cdn")),
        ("Owner", geo.get("org")), ("ASN", geo.get("asn")), ("Cloud provider", geo.get("cloud_provider")), ("Resolves to", ", ".join(geo.get("resolved_ips") or [])),
        ("TLD registry country", geo.get("cctld_country_code")), ("Registrar", reg.get("registrar")), ("Registered", reg.get("created")),
        ("Registrant country", reg.get("country")), ("Cross-check", geo.get("agreement")), ("Note", geo.get("note")),
    ])])


def mail_sections(mail: Optional[dict]) -> List[dict]:
    if not mail:
        return []
    p = mail.get("posture") or {}
    reg = mail.get("registration") or {}
    spf, dmarc = p.get("spf") or {}, p.get("dmarc") or {}
    out = [kv("Address", [("Domain", mail.get("domain")), ("Provider kind", mail.get("provider_kind") or "company or other domain"),
                          ("Registrar", reg.get("registrar")), ("Registered", reg.get("created"))])]
    if p.get("checked"):
        out.append(table("Mail servers", ["Priority", "Host"], [[m.get("priority"), m.get("host")] for m in (p.get("mx") or [])]))
        out.append(kv("Email authentication", [("SPF", spf.get("record")), ("SPF final rule", spf.get("all")), ("DMARC", dmarc.get("record")), ("DMARC policy", dmarc.get("policy"))]))
    out.append(table("Observations", ["Level", "Observation"], [[s.get("level"), s.get("text")] for s in (mail.get("signals") or [])]))
    return _clean(out)


# ── assembling one indicator's report ─────────────────────────────────────────
PROVIDERS = (("virustotal", "VirusTotal"), ("abuseipdb", "AbuseIPDB"), ("urlhaus", "URLhaus"))


def _headline(pid: str, d: dict) -> str:
    if pid == "virustotal":
        if d.get("malicious") is not None:
            return f"{d.get('malicious', 0)} of {d.get('total', 0)} engines flagged it"
        return "Not previously scanned" if d.get("found") is False else ""
    if pid == "abuseipdb":
        return f"{d.get('abuse_score', 0)}% abuse confidence, {d.get('total_reports', 0)} reports"
    if pid == "urlhaus":
        return f"Listed: {d.get('threat') or 'malware distribution'}" if d.get("found") else "Not listed"
    return ""


def build_providers(enrichment: dict, detail: dict) -> List[dict]:
    """One entry per provider that was asked. status: ok | not_found | error | skipped."""
    out = []
    for pid, name in PROVIDERS:
        d = (enrichment or {}).get(pid)
        if not isinstance(d, dict) or not d:
            continue
        det = (detail or {}).get(pid) or {}
        if d.get("skipped"):
            status, msg = "skipped", "No API key available for this provider"
        elif d.get("error"):
            status, msg = "error", _s(d["error"], 200)
        elif d.get("found") is False:
            status, msg = "not_found", _s(d.get("note")) or "The provider has no record of this indicator"
        else:
            status, msg = "ok", _s(d.get("note"))
        out.append({"id": pid, "name": name, "status": status, "message": msg, "headline": _headline(pid, d) if status in ("ok", "not_found") else "",
                    "link": d.get("link") or None, "sections": det.get("sections") or []})
    return out


def build_report_item(value: str, ioc_type: str, row: dict, detail: dict) -> dict:
    """The stored / served report for one looked-up indicator. `row` is the bulk-lookup result for it."""
    enr = row.get("enrichment") or {}
    providers = build_providers(enr, detail)
    tfii = _clean([*geo_sections(row.get("geo")), *mail_sections(enr.get("mail"))])
    asked = [p for p in providers if p["status"] in ("ok", "not_found")]
    return {
        "value": value, "type": ioc_type, "defanged": row.get("defanged") or value, "verdict": row.get("verdict"), "score": row.get("score"),
        "reason": row.get("reason"), "already_tracked": bool(row.get("already_tracked")), "existing_id": row.get("existing_id"),
        "providers": providers, "tfii": tfii,
        # Provider detail is only captured when a provider is actually called; a cached summary has none.
        "has_detail": any(p["sections"] for p in asked) or not asked,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
