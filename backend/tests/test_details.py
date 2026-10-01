"""Detailed report: what every provider said about an indicator, as display sections, remembered per user."""
import asyncio

import httpx
import pytest

import details

REAL_ASYNC_CLIENT = httpx.AsyncClient


def titles(sections):
    return [s["title"] for s in sections]


def test_virustotal_domain_sections():
    attrs = {"last_analysis_stats": {"malicious": 2, "harmless": 60, "undetected": 20}, "reputation": -4, "registrar": "Namecheap", "creation_date": 1790000000,
             "tld": "example", "categories": {"Forcepoint": "phishing"}, "tags": ["dga"], "popularity_ranks": {"Tranco": {"rank": 99999}},
             "last_dns_records": [{"type": "A", "value": "93.184.216.34", "ttl": 300}], "whois": "Domain Name: X" * 5,
             "last_analysis_results": {"Bad": {"category": "malicious", "engine_name": "BadAV", "result": "phishing"},
                                       "Fine": {"category": "harmless", "engine_name": "FineAV", "result": "clean"},
                                       "Maybe": {"category": "suspicious", "engine_name": "MaybeAV", "result": "suspicious"}}}
    s = details.vt_sections("domain", attrs)
    t = titles(s)
    assert "Detections" in t and "Engines that flagged it (2)" in t and "Registration" in t and "Popularity ranks" in t and "WHOIS" in t
    eng = next(x for x in s if x["title"].startswith("Engines"))
    assert eng["rows"] == [["BadAV", "malicious", "phishing"], ["MaybeAV", "suspicious", "suspicious"]]       # malicious first, harmless left out
    det = next(x for x in s if x["title"] == "Detections")
    assert ["Malicious", "2"] in det["rows"] and ["Reputation", "-4"] in det["rows"]
    reg = next(x for x in s if x["title"] == "Registration")
    assert ["Registrar", "Namecheap"] in reg["rows"] and any(r[0] == "Created" and r[1].startswith("2026-09") for r in reg["rows"])


def test_virustotal_file_and_url_and_ip_sections_use_what_exists():
    f = details.vt_sections("file", {"last_analysis_stats": {"malicious": 40}, "meaningful_name": "evil.exe", "sha256": "ab" * 32, "size": 1234,
                                     "popular_threat_classification": {"suggested_threat_label": "trojan.emotet", "popular_threat_name": [{"value": "emotet", "count": 30}]},
                                     "sandbox_verdicts": {"Zenbox": {"category": "malicious", "malware_classification": ["TROJAN"]}},
                                     "crowdsourced_yara_results": [{"rule_name": "Emotet_X", "ruleset_name": "r", "source": "s"}]})
    assert {"File", "Threat classification", "Sandbox verdicts", "Crowdsourced YARA matches (1)"} <= set(titles(f))
    u = details.vt_sections("url", {"last_analysis_stats": {"malicious": 1}, "last_final_url": "https://x.example/a", "title": "Login", "last_http_response_code": 200,
                                    "redirection_chain": ["http://a.example", "https://x.example/a"]})
    assert "Page" in titles(u) and "Redirection chain" in titles(u)
    ip = details.vt_sections("ip", {"last_analysis_stats": {}, "as_owner": "Example Hosting", "asn": 64500, "country": "DE"})
    assert ["Owner", "Example Hosting"] in next(x for x in ip if x["title"] == "Network")["rows"]
    assert details.vt_sections("ip", None)[0:0] == [] and isinstance(details.vt_sections("domain", {}), list)


def test_abuseipdb_sections_name_the_categories():
    d = {"abuseConfidenceScore": 100, "totalReports": 5, "numDistinctUsers": 3, "isp": "Bad ISP", "usageType": "Data Center", "isTor": False,
         "reports": [{"reportedAt": "2026-09-30T10:00:00+00:00", "comment": "ssh brute force " + "x" * 400, "categories": [18, 22], "reporterCountryCode": "US"},
                     {"reportedAt": "2026-09-29T10:00:00+00:00", "comment": "scan", "categories": [14, 18]}]}
    s = details.abuse_sections(d)
    cat = next(x for x in s if x["title"] == "What it was reported for")
    assert cat["rows"][0] == ["Brute force", "2"] and ["Port scan", "1"] in cat["rows"]
    recent = next(x for x in s if x["title"].startswith("Recent reports"))
    assert len(recent["rows"][0][2]) <= 220 and recent["rows"][0][1] == "Brute force, SSH"
    assert ["Tor exit node", "False"] in next(x for x in s if x["title"] == "Reputation")["rows"]


def test_urlhaus_sections_for_host_and_url():
    host = details.urlhaus_sections("host", {"host": "evil.example", "url_count": 2, "firstseen": "2026-09-01", "blacklists": {"spamhaus_dbl": "listed", "surbl": "not listed"},
                                             "urls": [{"url": "http://evil.example/a.exe", "url_status": "online", "threat": "malware_download", "date_added": "2026-09-02"}]})
    assert "URLs seen on this host (1)" in titles(host)
    url = details.urlhaus_sections("url", {"url_status": "offline", "threat": "malware_download", "tags": ["emotet"], "payloads": [
        {"firstseen": "2026-09-02", "filename": "a.exe", "file_type": "exe", "signature": "Emotet", "response_sha256": "ab" * 32}]})
    assert "Payloads served (1)" in titles(url) and "Tags" in titles(url)


def test_text_from_providers_is_bounded():
    big = "A" * 100000
    s = details.vt_sections("domain", {"whois": big, "title": big, "last_dns_records": [{"type": "TXT", "value": big, "ttl": 1}] * 500})
    for sec in s:
        for row in sec.get("rows", []):
            assert all(len(str(c)) <= 1500 for c in row)
        assert len(sec.get("rows", [])) <= details.MAX_ROWS
        assert len(sec.get("text", "")) <= 1500


def test_report_item_lists_who_scanned_who_did_not_and_who_failed():
    row = {"verdict": "malicious", "score": 90, "reason": "r", "defanged": "evil[.]example",
           "enrichment": {"virustotal": {"malicious": 5, "total": 90, "link": "https://vt"}, "urlhaus": {"found": False},
                          "abuseipdb": {"skipped": True}},
           "geo": {"kind": "hosting", "country": "Germany", "org": "Example Hosting"}}
    item = details.build_report_item("evil.example", "Domain", row, {"virustotal": {"sections": [{"title": "Detections", "type": "kv", "rows": [["Malicious", "5"]]}]}})
    by = {p["id"]: p for p in item["providers"]}
    assert by["virustotal"]["status"] == "ok" and by["virustotal"]["headline"] == "5 of 90 engines flagged it" and by["virustotal"]["sections"]
    assert by["urlhaus"]["status"] == "not_found" and by["abuseipdb"]["status"] == "skipped"
    assert item["tfii"][0]["title"] == "Location" and item["has_detail"] is True
    cached_only = details.build_report_item("evil.example", "Domain", row, {})
    assert cached_only["has_detail"] is False            # a cached summary carries no provider detail: the screen offers a refresh


# ── real provider functions attach their detail ──────────────────────────────
def test_provider_functions_return_detail_and_enrich_strips_it(monkeypatch):
    import main

    def handler(req):
        if "virustotal.com" in req.url.host:
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "harmless": 70}, "registrar": "R", "creation_date": 1790000000}}})
        return httpx.Response(200, json={"query_status": "no_results"})
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **kw: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler)))
    raw = asyncio.run(main.vt_domain("evil.example", None, "k" * 20, None))
    assert raw["malicious"] == 3 and raw["_detail"]["sections"]

    async def go():
        sink = {}
        tok = main._DETAIL_SINK.set(sink)
        try:
            res = await main.enrich("Domain", "evil.example", 50, None, force=True)
        finally:
            main._DETAIL_SINK.reset(tok)
        return res, sink
    monkeypatch.setattr(main, "PLATFORM_KEYS", {**main.PLATFORM_KEYS, "virustotal": "k" * 20, "urlhaus": "k" * 20})
    res, sink = asyncio.run(go())
    assert "_detail" not in res["virustotal"] and "virustotal" in sink and sink["virustotal"]["sections"]


# ── through the API ──────────────────────────────────────────────────────────
@pytest.fixture
def stack(client, analyst, monkeypatch):
    import main
    calls = []

    async def fake_vt(domain, conn=None, key=None, user_id=None):
        calls.append(domain)
        return {"source": "VirusTotal", "malicious": 4, "total": 90, "link": "https://vt/x",
                "_detail": {"sections": [{"title": "Detections", "type": "kv", "rows": [["Malicious", "4"]]}]}}

    async def fake_uh(domain, conn=None, key=None, user_id=None): return {"source": "URLhaus", "found": False}

    async def fake_posture(domain, client=None): return {"checked": False}

    async def no_geo(ips): return {}

    async def no_ips(host, client=None, limit=4): return []
    monkeypatch.setattr(main, "vt_domain", fake_vt)
    monkeypatch.setattr(main, "urlhaus_host_lookup", fake_uh)
    monkeypatch.setattr(main.mailintel, "mail_posture", fake_posture)
    monkeypatch.setattr(main, "geo_org_lookup_batch", no_geo)
    monkeypatch.setattr(main.geoloc, "resolve_ips", no_ips)
    client.post("/users/me/api-keys/virustotal", json={"api_key": "vt-analyst-key-0123456789"}, headers=analyst)
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "uh-analyst-key-0123456789"}, headers=analyst)
    yield calls
    client.delete("/users/me/api-keys/virustotal", headers=analyst)
    client.delete("/users/me/api-keys/urlhaus", headers=analyst)


def test_bulk_lookup_remembers_details_and_the_report_serves_them_without_new_lookups(client, analyst, stack):
    r = client.post("/iocs/bulk-lookup", json={"input": "evil[.]example\nother.example"}, headers=analyst)
    assert r.status_code == 200, r.text
    row = r.json()["results"][0]
    assert "_detail" not in str(row["enrichment"])                                  # the list response stays small
    assert sorted(stack) == ["evil.example", "other.example"]
    rep = client.post("/iocs/detail-report", json={"items": ["evil[.]example"]}, headers=analyst)
    assert rep.status_code == 200, rep.text
    item = rep.json()["items"][0]
    assert item["value"] == "evil.example" and item["cached"] is True and sorted(stack) == ["evil.example", "other.example"]   # no new provider call
    vt = next(p for p in item["providers"] if p["id"] == "virustotal")
    assert vt["status"] == "ok" and vt["sections"][0]["title"] == "Detections" and vt["headline"].startswith("4 of 90")
    again = client.post("/iocs/detail-report", json={"items": ["evil.example"], "refresh": True}, headers=analyst).json()["items"][0]
    assert again["cached"] is False and stack.count("evil.example") == 2


def test_an_indicator_never_looked_up_is_fetched_by_the_report(client, analyst, stack):
    item = client.post("/iocs/detail-report", json={"items": ["new.example"]}, headers=analyst).json()["items"][0]
    assert item["cached"] is False and stack == ["new.example"] and item["providers"][0]["status"] == "ok"


def test_the_report_is_per_user_and_bounded(client, analyst, admin, stack):
    client.post("/iocs/bulk-lookup", json={"input": "mine.example"}, headers=analyst)
    before = len(stack)
    other = client.post("/iocs/detail-report", json={"items": ["mine.example"]}, headers=admin).json()["items"][0]
    assert other["cached"] is False and len(stack) == before + 1                 # another user's lookup is not shown to them
    assert client.post("/iocs/detail-report", json={"items": []}, headers=analyst).status_code == 400
    assert client.post("/iocs/detail-report", json={"items": [f"d{i}.example" for i in range(26)]}, headers=analyst).status_code == 400
    many = client.post("/iocs/detail-report", json={"items": [f"n{i}.example" for i in range(14)]}, headers=analyst).json()["items"]
    assert sum(1 for i in many if not i["has_detail"]) == 4 and "at most 10" in many[-1]["reason"]
    assert client.post("/iocs/detail-report", json={"items": ["a.example"]}).status_code in (401, 403)
