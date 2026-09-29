"""NSLookup.io DNS enrichment: parsing real response shapes, pacing, caching, and the endpoint."""
import asyncio

import httpx
import pytest

import dnsintel as D


def _q(rtype, answers, rcode="NOERROR"):
    return {"query": {"domain": "example.com.", "recordType": rtype}, "response": {"rCode": rcode, "answer": answers}}


def _ans(rtype, raw, **fields):
    return {"record": {"recordType": rtype, "raw": raw, "name": "example.com.", "ttl": 58, **fields}, "cnameChain": [], "ipInfo": fields.pop("_ipinfo", None)}


def common(a=None, mx=None, txt=None, ns=None):
    a = a if a is not None else [{"record": {"recordType": "A", "raw": "140.82.121.4", "name": "example.com.", "ttl": 58, "ipv4": "140.82.121.4"}, "cnameChain": [],
                                  "ipInfo": {"country": "United States", "regionName": "California", "city": "San Francisco", "lat": 37.7, "lon": -122.4,
                                             "org": "Github Inc.", "as": "AS36459", "asname": "Github Inc."}}]
    mx = mx if mx is not None else [_ans("MX", "0 mail.example.com.", priority=0, target="mail.example.com.")]
    txt = txt if txt is not None else []
    ns = ns if ns is not None else [_ans("NS", "dns1.p08.nsone.net.", target="dns1.p08.nsone.net.")]
    return {"punycodeDomain": "example.com.", "unicodeDomain": "example.com.", "records": {
        "a": _q("A", a), "aaaa": _q("AAAA", []), "ns": _q("NS", ns), "mx": _q("MX", mx), "txt": _q("TXT", txt), "cname": _q("CNAME", []),
        "soa": _q("SOA", [_ans("SOA", "ns1. host. 1 7200 900 1209600 86400", host="ns1.example.com.", admin="hostmaster.example.com.",
                               serial=1, refresh=7200, retry=900, expire=1209600, minimum=86400)])}}


def txt_ans(text):
    return {"record": {"recordType": "TXT", "raw": f'"{text}"', "name": "example.com.", "ttl": 9, "strings": [text]}, "cnameChain": [], "ipInfo": None}


def other(rtype, answers):
    return {"punycodeDomain": "x.", "unicodeDomain": "x.", "queryResult": _q(rtype, answers)}


CAA = other("CAA", [{"record": {"recordType": "CAA", "raw": '0 issue "digicert.com"', "flags": 0, "tag": "issue", "value": "digicert.com"}, "cnameChain": [], "ipInfo": None}])


def test_common_records_are_read_from_the_real_response_shape():
    d = D.parse_records(common(txt=[txt_ans("v=spf1 include:_spf.google.com ~all")]), CAA, other("TXT", [txt_ans("v=DMARC1; p=reject; rua=mailto:a@example.com")]))
    assert d["domain"] == "example.com."
    assert d["addresses"] == [{"ip": "140.82.121.4", "geo": {"country": "United States", "region": "California", "city": "San Francisco",
                                                             "org": "Github Inc.", "asn": "AS36459", "asname": "Github Inc."}}]
    assert d["ns"] == ["dns1.p08.nsone.net"] and d["mx"] == [{"priority": 0, "host": "mail.example.com"}]
    assert d["soa"]["serial"] == 1 and d["soa"]["admin"] == "hostmaster.example.com."
    assert d["caa"] == [{"flags": 0, "tag": "issue", "value": "digicert.com"}]
    assert d["spf"]["all"] == "softfail" and d["spf"]["includes"] == ["_spf.google.com"]
    assert d["dmarc"]["policy"] == "reject" and d["dmarc"]["rua"] == ["mailto:a@example.com"]


@pytest.mark.parametrize("record,expect", [
    ("v=spf1 -all", "fail"), ("v=spf1 ip4:1.2.3.4 ~all", "softfail"), ("v=spf1 include:x.example ?all", "neutral"),
    ("v=spf1 +all", "pass"), ("v=spf1 all", "pass"), ("v=spf1 include:x.example", "none"),
])
def test_spf_final_rule(record, expect):
    assert D.parse_spf([record])["all"] == expect


def test_spf_ignores_other_txt_and_flags_duplicates():
    assert D.parse_spf(["google-site-verification=abc"]) is None
    assert D.parse_spf(["v=spf1 -all", "v=spf1 ~all"])["duplicates"] is True
    assert D.parse_spf(["v=spf1 ip4:1.1.1.1 ip6:::1 -all"])["ip_mechanisms"] == 2


def test_dmarc_tags():
    assert D.parse_dmarc(["v=DMARC1; p=none; sp=reject; pct=50"]) == {"record": "v=DMARC1; p=none; sp=reject; pct=50", "policy": "none",
                                                                       "subdomain_policy": "reject", "pct": "50", "rua": []}
    assert D.parse_dmarc(["something else"]) is None


def texts(d):
    return " | ".join(s["text"] for s in d["signals"])


def test_signals_describe_the_published_records_without_over_claiming():
    weak = D.summarize(common(txt=[]), None, None)
    assert "No SPF record" in texts(weak) and "No DMARC record" in texts(weak) and "No CAA record" in texts(weak)
    assert {s["level"] for s in weak["signals"]} >= {"warn", "info"}
    good = D.summarize(common(txt=[txt_ans("v=spf1 -all include:_spf.example.com")]), CAA, other("TXT", [txt_ans("v=DMARC1; p=quarantine")]))
    assert "DMARC policy is 'quarantine'" in texts(good) and "No SPF" not in texts(good) and "No CAA" not in texts(good)
    permissive = D.summarize(common(txt=[txt_ans("v=spf1 +all")]), CAA, None)
    assert "permissive" in texts(permissive)
    parked = D.summarize(common(mx=[], txt=[txt_ans("v=spf1 -all")]), CAA, None)
    assert "send and receive no mail" in texts(parked) and "No DMARC" not in texts(parked)
    gone = D.summarize(common(a=[], mx=[]), None, None)
    assert "does not resolve" in texts(gone)


def test_ttls_are_not_reported():
    d = D.summarize(common(), CAA, None)
    assert "ttl" not in str(d).lower()                         # resolver TTLs are remaining cache time, not zone values


def test_many_networks_are_noted():
    a = [{"record": {"recordType": "A", "raw": f"1.1.1.{i}", "ipv4": f"1.1.1.{i}"}, "cnameChain": [], "ipInfo": {"as": f"AS{i}", "country": "X"}} for i in range(1, 5)]
    assert "4 different networks" in texts(D.summarize(common(a=a), CAA, None))


# ── pacing ───────────────────────────────────────────────────────────────────
def test_the_throttle_spaces_requests_and_refuses_to_queue_for_long():
    t = D.Throttle(per_minute=6, max_wait=5)                     # one slot every 10 seconds

    async def go():
        await t.wait()                                            # first goes straight away
        with pytest.raises(D.DnsApiError) as e:
            await t.wait()                                        # next slot is 10 s away: more than max_wait
        return e.value.kind
    assert asyncio.run(go()) == "busy"


def test_user_limiter_is_per_user():
    u = D.UserLimiter(limit=2)
    assert [u.allow("a"), u.allow("a"), u.allow("a"), u.allow("b")] == [True, True, False, True]


def test_api_errors_are_classified_and_reset_headers_are_honoured():
    def run(handler, throttle=None):
        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
                return await D._get(c, "/api/v1/records", {"domain": "example.com"}, throttle or D.Throttle(per_minute=6000))
        return asyncio.run(go())
    for status, kind in ((429, "rate_limited"), (422, "invalid"), (503, "unavailable")):
        with pytest.raises(D.DnsApiError) as e:
            run(lambda req, s=status: httpx.Response(s))
        assert e.value.kind == kind
    def boom(req): raise httpx.ConnectError("down")
    with pytest.raises(D.DnsApiError) as e:
        run(boom)
    assert e.value.kind == "unavailable"
    t = D.Throttle(per_minute=6000)
    run(lambda req: httpx.Response(200, json={"ok": 1}, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "40"}), t)
    assert t._next - __import__("time").monotonic() > 30           # the next request waits for the API's window to reset


def test_lookup_keeps_the_answer_when_the_extras_are_rate_limited():
    calls = []

    def handler(req):
        calls.append(dict(req.url.params))
        if req.url.path.endswith("/records/other"):
            return httpx.Response(429)
        return httpx.Response(200, json=common())

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await D.lookup("example.com", c, D.Throttle(per_minute=6000))
    d = asyncio.run(go())
    assert d["addresses"] and d["caa"] == [] and d["dmarc"] is None and d["source"] == "nslookup.io"
    # after the 429 the client backs off: it does not send the DMARC request into a limited API
    assert [c.get("domain") for c in calls] == ["example.com", "example.com"]


# ── endpoint ─────────────────────────────────────────────────────────────────
@pytest.fixture
def fake(monkeypatch):
    calls = []

    async def lookup(domain, client=None, throttle=None):
        calls.append(domain)
        return D.summarize(common(txt=[txt_ans("v=spf1 -all")]), CAA, None)
    monkeypatch.setattr(D, "lookup", lookup)
    monkeypatch.setattr(D, "USER_LIMIT", D.UserLimiter(limit=50))
    return calls


def test_endpoint_looks_up_caches_and_normalises(client, analyst, db, fake):
    r = client.get("/v2/dns", params={"domain": "HTTP://Shop.Example-DNS-Test.com/login?a=1"}, headers=analyst)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["cached"] is False and j["addresses"][0]["ip"] == "140.82.121.4" and j["signals"] and fake == ["shop.example-dns-test.com"]
    again = client.get("/v2/dns", params={"domain": "shop.example-dns-test.com."}, headers=analyst).json()
    assert again["cached"] is True and again["age_minutes"] == 0 and fake == ["shop.example-dns-test.com"]      # no second upstream call
    forced = client.get("/v2/dns", params={"domain": "shop.example-dns-test.com", "refresh": True}, headers=analyst).json()
    assert forced["cached"] is True and len(fake) == 1                    # refresh is ignored inside the cooldown
    db.cursor().execute("UPDATE dns_intel_cache SET fetched_at = NOW() - INTERVAL '30 minutes' WHERE domain = 'shop.example-dns-test.com'")
    assert client.get("/v2/dns", params={"domain": "shop.example-dns-test.com", "refresh": True}, headers=analyst).json()["cached"] is False
    assert len(fake) == 2
    db.cursor().execute("DELETE FROM dns_intel_cache WHERE domain = 'shop.example-dns-test.com'")


def test_endpoint_rejects_things_that_are_not_domains(client, analyst, fake):
    for bad in ("", "1.2.3.4", "not a domain", "-bad-.com", "a" * 300 + ".com"):
        assert client.get("/v2/dns", params={"domain": bad}, headers=analyst).status_code == 400, bad
    assert fake == []


def test_endpoint_requires_login_and_serves_explorers(client, explorer, fake):
    assert client.get("/v2/dns", params={"domain": "example.com"}).status_code in (401, 403)
    assert client.get("/v2/dns", params={"domain": "explorer-dns-test.com"}, headers=explorer).status_code == 200


def test_endpoint_maps_upstream_trouble_and_prefers_a_saved_answer(client, analyst, db, monkeypatch):
    async def down(domain, client=None, throttle=None): raise D.DnsApiError("unavailable", "NSLookup.io could not be reached")
    async def limited(domain, client=None, throttle=None): raise D.DnsApiError("rate_limited", "NSLookup.io is rate limiting requests; try again in a minute")
    monkeypatch.setattr(D, "USER_LIMIT", D.UserLimiter(limit=50))
    monkeypatch.setattr(D, "lookup", down)
    assert client.get("/v2/dns", params={"domain": "upstream-down-test.com"}, headers=analyst).status_code == 502
    monkeypatch.setattr(D, "lookup", limited)
    assert client.get("/v2/dns", params={"domain": "upstream-down-test.com"}, headers=analyst).status_code == 429
    # with a saved (old) answer, the same failure returns it, marked stale
    db.cursor().execute("INSERT INTO dns_intel_cache (domain, data, fetched_at) VALUES ('upstream-down-test.com', %s, NOW() - INTERVAL '2 days')",
                        (__import__("json").dumps(D.summarize(common(), CAA, None)),))
    j = client.get("/v2/dns", params={"domain": "upstream-down-test.com"}, headers=analyst).json()
    assert j["stale"] is True and j["cached"] is True and "rate limiting" in j["warning"]
    db.cursor().execute("DELETE FROM dns_intel_cache WHERE domain = 'upstream-down-test.com'")


def test_endpoint_limits_each_user(client, analyst, monkeypatch, fake):
    monkeypatch.setattr(D, "USER_LIMIT", D.UserLimiter(limit=2))
    codes = [client.get("/v2/dns", params={"domain": f"limit-test-{i}.com"}, headers=analyst).status_code for i in range(4)]
    assert codes == [200, 200, 429, 429]
