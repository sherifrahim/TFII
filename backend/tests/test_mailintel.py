"""Email indicators are judged through their domain, never by a free-mail domain's good name."""
import asyncio
from datetime import datetime, timezone

import httpx
import pytest

import mailintel

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
REAL_ASYNC_CLIENT = httpx.AsyncClient


@pytest.mark.parametrize("raw,expected", [
    ("Alice@Example.COM", ("Alice", "example.com")), ("a+tag@sub.example.co.uk.", ("a+tag", "sub.example.co.uk")),
    ("üser@bücher.example", ("üser", "xn--bcher-kva.example")),
    ("no-at-sign.example.com", None), ("two@@example.com", None), ("a@b@example.com", None), ("@example.com", None),
    ("a@localhost", None), ("a@1.2.3.4", None), ("a b@example.com", None), ("a@exa mple.com", None), ("", None),
    (("x" * 65) + "@example.com", None),
])
def test_split_email(raw, expected):
    assert mailintel.split_email(raw) == expected


def test_provider_kinds_and_role_names():
    assert mailintel.provider_kind("gmail.com") == "free" and mailintel.provider_kind("mailinator.com") == "disposable"
    assert mailintel.provider_kind("corp.example") is None
    assert mailintel.role_name("Support") == "support" and mailintel.role_name("billing+x") == "billing" and mailintel.role_name("jane") is None


def _doh(mx=None, txt=None, dmarc=None, status=0):
    def handler(req):
        name, rtype = req.url.params["name"], req.url.params["type"]
        if status == 3:
            return httpx.Response(200, json={"Status": 3})
        if rtype == "MX":
            ans = [{"type": 15, "data": d} for d in (mx or [])]
        elif name.startswith("_dmarc."):
            ans = [{"type": 16, "data": d} for d in (dmarc or [])]
        else:
            ans = [{"type": 16, "data": d} for d in (txt or [])]
        return httpx.Response(200, json={"Status": 0, "Answer": ans})
    return handler


def _posture(handler, domain="corp.example"):
    async def go():
        async with REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler)) as c:
            return await mailintel.mail_posture(domain, c)
    return asyncio.run(go())


def test_posture_reads_mx_spf_and_dmarc():
    p = _posture(_doh(mx=["20 mx2.corp.example.", "10 mx1.corp.example."], txt=['"v=spf1 include:_spf.corp.example " "-all"', '"google-site-verification=abc"'],
                      dmarc=['"v=DMARC1; p=reject; rua=mailto:d@corp.example"']))
    assert p["checked"] and p["exists"]
    assert [m["host"] for m in p["mx"]] == ["mx1.corp.example", "mx2.corp.example"]
    assert p["spf"]["all"] == "fail" and p["spf"]["includes"] == ["_spf.corp.example"] and p["dmarc"]["policy"] == "reject"


def test_a_domain_that_does_not_exist_is_reported_and_a_dead_resolver_claims_nothing():
    assert _posture(_doh(status=3))["exists"] is False
    def down(req): raise httpx.ConnectError("down")
    assert _posture(down) == {"checked": False}


def codes(sigs):
    return {s["code"] for s in sigs}


def test_signals_for_a_free_mailbox_do_not_judge_the_domain():
    s = mailintel.signals("jane", "gmail.com", "free", None)
    assert codes(s) == {"free_mail"}
    assert codes(mailintel.signals("support", "gmail.com", "free", None)) == {"free_mail", "role_name"}


def test_signals_flag_spoofable_and_brand_new_domains():
    p = {"checked": True, "exists": True, "mx": [], "null_mx": False, "spf": None, "dmarc": None}
    s = mailintel.signals("billing", "new-shop.example", None, p, {"created": "2026-09-25"}, now=NOW)
    assert {"role_name", "new_domain", "no_mx", "no_spf", "no_dmarc"} <= codes(s)
    old = mailintel.signals("jane", "corp.example", None, {**p, "mx": [{"priority": 10, "host": "mx"}], "spf": {"all": "fail", "duplicates": False},
                                                          "dmarc": {"policy": "reject"}}, {"created": "2015-01-01"}, now=NOW)
    assert codes(old) == {"dmarc_enforced"}
    assert "nxdomain" in codes(mailintel.signals("a", "gone.example", None, {"checked": True, "exists": False}))


def test_registration_age():
    assert mailintel.registration_age_days({"created": "2026-09-21"}, NOW) == 10
    assert mailintel.registration_age_days({"created": "bad"}, NOW) is None and mailintel.registration_age_days(None, NOW) is None
    assert mailintel.registration_age_days({"created": "2027-01-01"}, NOW) is None          # future dates say nothing


def _mail(kind=None, sigs=(), domain="corp.example", **kw):
    return {"domain": domain, "provider_kind": kind, "signals": [{"level": "warn", "text": c, "code": c} for c in sigs], **kw}


def test_verdicts():
    v = mailintel.verdict
    assert v(_mail("free", ["free_mail"], "gmail.com"), {})["verdict"] == "unknown"                   # a good domain never clears a mailbox
    assert v(_mail(), {"virustotal": {"malicious": 5, "total": 90}})["verdict"] == "malicious"
    assert v(_mail(), {"virustotal": {"malicious": 1, "total": 90}})["verdict"] == "suspicious"
    assert v(_mail(), {"urlhaus": {"found": True}})["verdict"] == "malicious"
    assert v(_mail("disposable", ["disposable"], "mailinator.com"), {})["verdict"] == "suspicious"
    assert v(_mail(None, ["new_domain"]), {"virustotal": {"malicious": 0, "total": 90}})["verdict"] == "suspicious"
    assert v(_mail(None, ["no_spf"]), {"virustotal": {"malicious": 0, "total": 90}})["verdict"] == "clean"   # missing SPF is a finding, not a verdict
    assert v(_mail(), {"virustotal": {"skipped": True}, "urlhaus": {"skipped": True}})["verdict"] == "unknown"
    assert v(_mail(otx_address={"found": True, "pulse_count": 2}), {})["verdict"] == "suspicious"


# ── through the API ──────────────────────────────────────────────────────────
@pytest.fixture
def stack(client, analyst, monkeypatch):
    import main
    calls = {"vt": [], "uh": [], "mx": []}

    async def fake_vt(domain, conn=None, key=None, user_id=None):
        calls["vt"].append(domain)
        return {"source": "VirusTotal", "malicious": 4 if domain == "evil.example" else 0, "total": 90,
                "registration": {"registrar": "R", "created": "2026-09-28"} if domain == "evil.example" else {"registrar": "R", "created": "2012-01-01"}}

    async def fake_uh(domain, conn=None, key=None, user_id=None):
        calls["uh"].append(domain)
        return {"source": "URLhaus", "found": False}

    async def fake_posture(domain, client=None):
        calls["mx"].append(domain)
        return {"checked": True, "exists": True, "mx": [{"priority": 10, "host": "mx." + domain}], "null_mx": False,
                "spf": {"all": "fail", "duplicates": False, "includes": [], "ip_mechanisms": 0}, "dmarc": {"policy": "reject"}}

    async def no_geo(ips): return {}
    monkeypatch.setattr(main, "vt_domain", fake_vt)
    monkeypatch.setattr(main, "urlhaus_host_lookup", fake_uh)
    monkeypatch.setattr(main.mailintel, "mail_posture", fake_posture)
    monkeypatch.setattr(main, "geo_org_lookup_batch", no_geo)
    client.post("/users/me/api-keys/virustotal", json={"api_key": "vt-analyst-key-0123456789"}, headers=analyst)
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "uh-analyst-key-0123456789"}, headers=analyst)
    yield calls
    client.delete("/users/me/api-keys/virustotal", headers=analyst)
    client.delete("/users/me/api-keys/urlhaus", headers=analyst)


def test_bulk_lookup_judges_addresses_by_their_domain_and_asks_once_per_domain(client, analyst, stack):
    body = {"input": "ceo@evil.example\nhr@evil[.]example\nalice@gmail.com\nbob@mailinator.com\nplain@corp.example"}
    r = client.post("/iocs/bulk-lookup", json=body, headers=analyst)
    assert r.status_code == 200, r.text
    rows = {x["refanged"]: x for x in r.json()["results"]}
    assert all(x["type"] == "Email" for x in rows.values())
    evil = rows["ceo@evil.example"]
    assert evil["verdict"] == "malicious" and "evil.example" in evil["reason"]
    assert "new_domain" in {s["code"] for s in evil["enrichment"]["mail"]["signals"]} and evil["geo"] is None
    assert rows["alice@gmail.com"]["verdict"] == "unknown" and "virustotal" not in rows["alice@gmail.com"]["enrichment"]
    assert rows["bob@mailinator.com"]["verdict"] == "suspicious"
    assert rows["plain@corp.example"]["verdict"] == "clean"
    # evil.example appears twice but is asked once; free and disposable domains cost no reputation lookups
    assert sorted(stack["vt"]) == ["corp.example", "evil.example"] and sorted(stack["uh"]) == ["corp.example", "evil.example"]
    assert sorted(set(stack["mx"])) == ["corp.example", "evil.example", "mailinator.com"] and "gmail.com" not in stack["mx"]


def test_an_invalid_address_is_not_sent_anywhere(client, analyst, stack):
    r = client.post("/iocs/bulk-lookup", json={"input": "a@b@c.example"}, headers=analyst)
    assert r.status_code == 200
    assert stack["vt"] == [] and stack["mx"] == []


# ── breach exposure (XposedOrNot) ────────────────────────────────────────────
def test_exposure_parsing():
    r = mailintel.parse_exposure(200, {"breaches": [["Tesco", "KiwiFarms", "Tesco"]], "email": "a@b.example", "status": "success"})
    assert r["found"] and r["count"] == 2 and r["breaches"] == ["Tesco", "KiwiFarms"]
    assert mailintel.parse_exposure(200, {"Error": "Not found", "email": None})["found"] is False
    assert mailintel.parse_exposure(404, None)["found"] is False
    with pytest.raises(mailintel.MailApiError) as e:
        mailintel.parse_exposure(429, {})
    assert e.value.kind == "rate_limited"
    with pytest.raises(mailintel.MailApiError):
        mailintel.parse_exposure(500, {})


def test_budget_keeps_under_the_providers_limits():
    b = mailintel.Budget(hourly=3, daily=5)
    assert [b.take() for _ in range(4)] == [True, True, True, False]


@pytest.fixture
def xon(client, analyst, monkeypatch):
    import entity_api
    mailintel._EXPOSURE_CACHE.clear()
    monkeypatch.setattr(mailintel, "BUDGET", mailintel.Budget(hourly=2, daily=10))
    monkeypatch.setattr(entity_api, "EXPOSURE_LIMIT", entity_api.dnsintel.UserLimiter(limit=50))
    seen = []

    def handler(req):
        seen.append(str(req.url))
        if "gone@" in str(req.url):
            return httpx.Response(200, json={"Error": "Not found", "email": None})
        return httpx.Response(200, json={"breaches": [["Adobe", "LinkedIn"]], "status": "success"})
    monkeypatch.setattr(mailintel.httpx, "AsyncClient", lambda **kw: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler)))
    return seen


def test_exposure_endpoint_asks_once_then_remembers_and_respects_the_shared_budget(client, analyst, xon):
    r = client.get("/v2/mail/exposure", params={"address": "Victim@Example.com"}, headers=analyst)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["found"] and j["breaches"] == ["Adobe", "LinkedIn"] and j["cached"] is False
    assert xon == ["https://api.xposedornot.com/v1/check-email/victim@example.com"]
    again = client.get("/v2/mail/exposure", params={"address": "victim@example.com"}, headers=analyst).json()
    assert again["cached"] is True and len(xon) == 1
    assert client.get("/v2/mail/exposure", params={"address": "gone@example.com"}, headers=analyst).json()["found"] is False
    busy = client.get("/v2/mail/exposure", params={"address": "third@example.com"}, headers=analyst)     # hourly budget (2) is spent
    assert busy.status_code == 429 and "limit" in busy.json()["detail"]
    stale = client.get("/v2/mail/exposure", params={"address": "victim@example.com", "refresh": "true"}, headers=analyst).json()
    assert stale["stale"] is True and stale["found"]                          # a saved answer beats an error


def test_exposure_rejects_bad_input_and_needs_a_login(client, analyst, xon):
    assert client.get("/v2/mail/exposure", params={"address": "not-an-email"}, headers=analyst).status_code == 400
    assert client.get("/v2/mail/exposure", params={"address": "a@example.com"}).status_code in (401, 403)
    assert xon == []


# ── address risk (IPQualityScore) ────────────────────────────────────────────
IPQS_OK = {"success": True, "message": "Success.", "valid": True, "disposable": False, "fraud_score": 88, "recent_abuse": True, "leaked": True,
           "honeypot": False, "spam_trap_score": "low", "suspect": True, "deliverability": "high", "dns_valid": True, "catch_all": False,
           "first_seen": {"human": "2 days ago", "timestamp": 1, "iso": "x"}, "domain_age": {"human": "3 weeks ago"}, "request_id": "r1"}


def test_risk_parsing_keeps_the_useful_fields_only():
    r = mailintel.parse_risk(200, IPQS_OK)
    assert r["fraud_score"] == 88 and r["recent_abuse"] is True and r["first_seen"] == "2 days ago" and r["domain_age"] == "3 weeks ago"
    assert "request_id" not in r and "message" not in r


@pytest.mark.parametrize("status,body,kind", [
    (429, {}, "rate_limited"), (500, {}, "unavailable"), (200, None, "unavailable"),
    (200, {"success": False, "message": "You have insufficient credits to make this query."}, "rate_limited"),
    (200, {"success": False, "message": "Invalid or unauthorized key."}, "invalid"),
    (200, {"success": False, "message": "weird"}, "unavailable"),
])
def test_risk_provider_problems(status, body, kind):
    with pytest.raises(mailintel.MailApiError) as e:
        mailintel.parse_risk(status, body)
    assert e.value.kind == kind


@pytest.fixture
def ipqs(client, analyst, monkeypatch):
    import entity_api
    mailintel._RISK_CACHE.clear()
    monkeypatch.setattr(entity_api, "RISK_LIMIT", entity_api.dnsintel.UserLimiter(limit=50))
    seen = []

    def handler(req):
        seen.append(req.url.path)
        return httpx.Response(200, json=IPQS_OK)
    monkeypatch.setattr(mailintel.httpx, "AsyncClient", lambda **kw: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler)))
    yield seen
    client.delete("/users/me/api-keys/ipqs", headers=analyst)


def test_risk_needs_the_callers_own_key_and_then_remembers_the_answer(client, analyst, ipqs):
    r = client.get("/v2/mail/risk", params={"address": "x@example.com"}, headers=analyst)
    assert r.status_code in (400, 429) and "IPQualityScore" in r.json()["detail"] and ipqs == []
    assert client.post("/users/me/api-keys/ipqs", json={"api_key": "ipqs-analyst-key-0123456789"}, headers=analyst).status_code in (200, 201)
    ok = client.get("/v2/mail/risk", params={"address": "X@Example.com"}, headers=analyst)
    assert ok.status_code == 200, ok.text
    assert ok.json()["fraud_score"] == 88 and ok.json()["cached"] is False
    assert ipqs == ["/api/json/email/ipqs-analyst-key-0123456789/x@example.com"]
    assert client.get("/v2/mail/risk", params={"address": "x@example.com"}, headers=analyst).json()["cached"] is True and len(ipqs) == 1
    assert client.get("/v2/mail/risk", params={"address": "bad"}, headers=analyst).status_code == 400
    assert client.get("/v2/mail/risk", params={"address": "x@example.com"}).status_code in (401, 403)


# ── deep analysis (MxToolbox) ────────────────────────────────────────────────
def _mxt_item(name, info="", url="https://mxtoolbox.com/x"):
    return {"ID": 1, "Name": name, "Info": info, "Url": url}


def _mxt_handler(seen, fail=None, bodies=None):
    def handler(req):
        cmd = req.url.path.rstrip("/").rsplit("/", 1)[1]
        seen.append((cmd, req.url.params["argument"], req.headers.get("authorization")))
        if fail and cmd in fail:
            return httpx.Response(fail[cmd])
        body = (bodies or {}).get(cmd) or {"Failed": [], "Warnings": [], "Passed": [_mxt_item(cmd + " ok")], "Timeouts": []}
        return httpx.Response(200, json=body)
    return handler


def _report(handler, domain="corp.example", **kw):
    async def go():
        async with REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler)) as c:
            return await mailintel.mxtoolbox_report(domain, "mxt-key-0123456789", client=c, **kw)
    mailintel._MXT_CACHE.clear()
    return asyncio.run(go())


def test_report_runs_the_dns_tests_and_summarises_them():
    seen = []
    bodies = {"spf": {"Failed": [_mxt_item("SPF Record Published", "No SPF record found")], "Warnings": [_mxt_item("SPF Included Lookups", "9 of 10")],
                      "Passed": [], "Timeouts": []}}
    r = _report(_mxt_handler(seen, bodies=bodies))
    assert [c for c, _a, _k in seen] == list(mailintel.MXT_DNS_COMMANDS) or sorted(c for c, _a, _k in seen) == sorted(mailintel.MXT_DNS_COMMANDS)
    assert all(a == "corp.example" and k == "mxt-key-0123456789" for _c, a, k in seen)
    assert r["summary"] == {"failed": 1, "warnings": 1, "passed": 5} and r["errors"] == {} and r["deep"] is False
    assert r["checks"]["spf"]["failed"][0]["name"] == "SPF Record Published"


def test_network_tests_are_opt_in_and_a_plan_without_them_is_reported_not_fatal(monkeypatch):
    async def posture(domain, client=None): return {"checked": True, "exists": True, "mx": [{"priority": 10, "host": "mx1.corp.example"}]}
    monkeypatch.setattr(mailintel, "mail_posture", posture)
    seen = []
    r = _report(_mxt_handler(seen, fail={"blacklist": 403, "smtp": 403}), deep=True, selector="google")
    assert {"blacklist", "smtp", "dkim"} <= {c for c, _a, _k in seen}
    assert ("smtp", "mx1.corp.example") in [(c, a) for c, a, _k in seen] and ("dkim", "corp.example:google") in [(c, a) for c, a, _k in seen]
    assert r["errors"]["blacklist"]["kind"] == "forbidden" and "plan" in r["errors"]["smtp"]["message"] and "spf" in r["checks"]
    plain = []
    _report(_mxt_handler(plain))
    assert not {"blacklist", "smtp", "dkim"} & {c for c, _a, _k in plain}


def test_a_rejected_key_or_total_refusal_is_an_error_and_input_is_checked():
    with pytest.raises(mailintel.MailApiError) as e:
        _report(_mxt_handler([], fail={c: 401 for c in mailintel.MXT_DNS_COMMANDS}))
    assert e.value.kind == "invalid"
    with pytest.raises(mailintel.MailApiError) as e:
        _report(_mxt_handler([], fail={c: 429 for c in mailintel.MXT_DNS_COMMANDS}))
    assert e.value.kind == "rate_limited" and "00:00 UTC" in str(e.value)
    for bad in ("1.2.3.4", "not a domain", ""):
        with pytest.raises(mailintel.MailApiError):
            _report(_mxt_handler([]), domain=bad)
    with pytest.raises(mailintel.MailApiError):
        _report(_mxt_handler([]), selector="bad selector!")


def test_the_report_is_cached_to_save_the_daily_allowance():
    seen = []
    handler = _mxt_handler(seen)

    async def twice():
        async with REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler)) as c:
            a = await mailintel.mxtoolbox_report("corp.example", "k" * 20, client=c)
            b = await mailintel.mxtoolbox_report("corp.example", "k" * 20, client=c)
            return a, b
    mailintel._MXT_CACHE.clear()
    a, b = asyncio.run(twice())
    assert a["cached"] is False and b["cached"] is True and len(seen) == len(mailintel.MXT_DNS_COMMANDS)


@pytest.fixture
def mxt(client, analyst, monkeypatch):
    import entity_api
    mailintel._MXT_CACHE.clear()
    monkeypatch.setattr(entity_api, "DEEP_LIMIT", entity_api.dnsintel.UserLimiter(limit=50))
    seen = []
    monkeypatch.setattr(mailintel.httpx, "AsyncClient", lambda **kw: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(_mxt_handler(seen))))
    yield seen
    client.delete("/users/me/api-keys/mxtoolbox", headers=analyst)


def test_deep_endpoint_needs_a_key_and_a_real_mail_domain(client, analyst, mxt):
    r = client.get("/v2/mail/deep", params={"address": "x@corp.example"}, headers=analyst)
    assert r.status_code in (400, 429) and "MxToolbox" in r.json()["detail"] and mxt == []
    assert client.post("/users/me/api-keys/mxtoolbox", json={"api_key": "mxt-analyst-key-0123456789"}, headers=analyst).status_code in (200, 201)
    ok = client.get("/v2/mail/deep", params={"address": "X@Corp.Example"}, headers=analyst)
    assert ok.status_code == 200, ok.text
    assert ok.json()["domain"] == "corp.example" and ok.json()["summary"]["passed"] == 6 and mxt[0][2] == "mxt-analyst-key-0123456789"
    assert client.get("/v2/mail/deep", params={"domain": "corp.example"}, headers=analyst).json()["cached"] is True
    free = client.get("/v2/mail/deep", params={"address": "me@gmail.com"}, headers=analyst)
    assert free.status_code == 400 and "free mailbox" in free.json()["detail"]
    assert client.get("/v2/mail/deep", params={"address": "bad"}, headers=analyst).status_code == 400
    assert client.get("/v2/mail/deep", params={"domain": "corp.example"}).status_code in (401, 403)
