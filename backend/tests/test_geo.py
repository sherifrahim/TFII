"""Locations are labelled for what they are: an IP's GeoIP, a domain's hosting, a CDN edge, a registry country."""
import asyncio

import httpx
import pytest

import geo

REAL_ASYNC_CLIENT = httpx.AsyncClient          # captured before any test patches it

IT = {"status": "success", "country": "Italy", "countryCode": "IT", "org": "Aruba S.p.A.", "isp": "Aruba", "as": "AS31034 Aruba S.p.A."}
CF = {"status": "success", "country": "Italy", "countryCode": "IT", "org": "Cloudflare, Inc.", "isp": "Cloudflare", "as": "AS13335 Cloudflare, Inc."}
US = {"status": "success", "country": "United States", "countryCode": "US", "org": "Example Hosting", "isp": "Example", "as": "AS64500 Example"}


def test_cdn_detection_uses_the_owner_not_the_country():
    assert geo.cdn_provider("Cloudflare, Inc.") == "Cloudflare"
    assert geo.cdn_provider(None, "", "AS20940 Akamai International B.V.") == "Akamai"
    assert geo.cdn_provider("Aruba S.p.A.", "Aruba", "AS31034 Aruba S.p.A.") is None


@pytest.mark.parametrize("host,code", [
    ("shop.example.mu", "MU"), ("bank.example.co.uk", "GB"), ("x.example.de", "DE"), ("a.b.example.fr.", "FR"),
    ("evil.io", None), ("evil.tv", None), ("evil.co", None),              # sold worldwide: says nothing about a country
    ("evil.com", None), ("evil.xyz", None), ("localhost", None), ("1.2.3.4", None), ("", None),
])
def test_only_real_country_code_tlds_give_a_registry_country(host, code):
    assert geo.cctld_country_code(host) == code


def _run(coro):
    return asyncio.run(coro)


def test_resolve_ips_returns_every_public_address_once():
    def handler(req):
        t = req.url.params["type"]
        if t == "A":
            return httpx.Response(200, json={"Answer": [{"type": 1, "data": "93.184.216.34"}, {"type": 1, "data": "10.0.0.5"},
                                                         {"type": 5, "data": "alias.example."}, {"type": 1, "data": "93.184.216.34"}]})
        return httpx.Response(200, json={"Answer": [{"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"}]})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await geo.resolve_ips("example.mu", c)
    assert _run(go()) == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]      # private dropped, duplicate dropped


def test_resolve_ips_falls_back_to_the_os_resolver_when_doh_fails(monkeypatch):
    def boom(req): raise httpx.ConnectError("down")
    monkeypatch.setattr(geo.socket, "gethostbyname_ex", lambda h: (h, [], ["93.184.216.34", "192.168.1.1"]))

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as c:
            return await geo.resolve_ips("example.mu", c)
    assert _run(go()) == ["93.184.216.34"]


def test_a_dot_mu_domain_hosted_in_italy_is_labelled_as_hosting_not_origin():
    g = geo.describe_location("Domain", "shop.example.mu", ["93.184.216.34"], {"93.184.216.34": IT})
    assert g["kind"] == "hosting" and g["country_code"] == "IT" and g["country"] == "Italy"
    assert g["cctld_country_code"] == "MU"                                    # shown separately as the registry hint
    assert "not necessarily where the operators are" in g["note"] and g["resolved_ip"] == "93.184.216.34"


def test_behind_a_cdn_no_country_is_claimed():
    g = geo.describe_location("Domain", "shop.example.mu", ["104.16.1.1"], {"104.16.1.1": CF})
    assert g["kind"] == "cdn_edge" and g["cdn"] == "Cloudflare"
    assert g["country"] is None and g["country_code"] is None and g["countries"] == []
    assert g["edge_country"] == "Italy" and "Behind Cloudflare" in g["note"] and g["cctld_country_code"] == "MU"


def test_an_ip_is_the_geoip_of_that_address_and_several_hosting_countries_are_all_reported():
    g = geo.describe_location("IPv4", "93.184.216.34", ["93.184.216.34"], {"93.184.216.34": IT})
    assert g["kind"] == "ip" and g["country"] == "Italy" and g["resolved_ips"] == [] and g["cctld_country_code"] is None
    m = geo.describe_location("Domain", "example.com", ["1.1.1.1", "2.2.2.2"], {"1.1.1.1": IT, "2.2.2.2": US})
    assert [c["code"] for c in m["countries"]] == ["IT", "US"] and "several countries" in m["note"]


def test_unresolvable_names_do_not_invent_a_location():
    assert geo.describe_location("Domain", "gone.example.com", [], {}) is None
    hint = geo.describe_location("Domain", "gone.example.mu", [], {})
    assert hint["kind"] == "unknown" and hint["cctld_country_code"] == "MU" and "country" not in hint


def test_cross_check_compares_geoip_with_abuseipdb_and_virustotal():
    g = geo.describe_location("IPv4", "1.1.1.1", ["1.1.1.1"], {"1.1.1.1": IT})
    same = geo.cross_check(dict(g), {"abuseipdb": {"country": "IT"}, "virustotal": {"country": "IT"}})
    assert same["agreement"] == "agree" and same["other_sources"] == {"AbuseIPDB": "IT", "VirusTotal": "IT"}
    diff = geo.cross_check(dict(g), {"abuseipdb": {"country": "DE"}})
    assert diff["agreement"] == "differ"
    assert "agreement" not in geo.cross_check(dict(g), {"abuseipdb": {"country": "?"}})       # nobody else answered
    dom = geo.describe_location("Domain", "x.example.mu", ["1.1.1.1"], {"1.1.1.1": IT})
    assert "agreement" not in geo.cross_check(dict(dom), {"abuseipdb": {"country": "DE"}})    # only meaningful for a single IP


# ── through the API ──────────────────────────────────────────────────────────
@pytest.fixture
def offline(monkeypatch):
    import main
    table = {}

    async def fake_resolve(host, client=None, limit=4): return ["93.184.216.34"] if host.endswith("example.mu") else []

    async def fake_geo(ips): return {ip: table[ip] for ip in ips if ip in table}

    async def no_enrich(ioc_type, value, base, conn=None, **kw): return {}
    monkeypatch.setattr(main.geoloc, "resolve_ips", fake_resolve)
    monkeypatch.setattr(main, "geo_org_lookup_batch", fake_geo)
    monkeypatch.setattr(main, "enrich", no_enrich)
    return table


def test_bulk_lookup_reports_hosting_and_registry_separately(client, analyst, offline):
    offline["93.184.216.34"] = IT
    r = client.post("/iocs/bulk-lookup", json={"input": "hxxp://shop[.]example[.]mu/login"}, headers=analyst)
    assert r.status_code == 200, r.text
    g = r.json()["results"][0]["geo"]
    assert g["kind"] == "hosting" and g["country_code"] == "IT" and g["cctld_country_code"] == "MU"


def test_bulk_lookup_withholds_the_country_behind_a_cdn(client, analyst, offline):
    offline["93.184.216.34"] = CF
    g = client.post("/iocs/bulk-lookup", json={"input": "shop.example.mu"}, headers=analyst).json()["results"][0]["geo"]
    assert g["kind"] == "cdn_edge" and g["country"] is None and g["edge_country"] == "Italy"


# ── registration and address history ─────────────────────────────────────────
def test_registration_is_read_from_the_virustotal_report():
    whois = "Domain Name: EXAMPLE.MU\nRegistrant Name: REDACTED\nRegistrant Country: mu\nRegistrar: Some Registrar\n"
    reg = geo.vt_registration({"registrar": "Namecheap, Inc.", "creation_date": 1790000000, "whois": whois})
    assert reg == {"registrar": "Namecheap, Inc.", "created": "2026-09-21", "country": "MU"}
    assert geo.vt_registration({"whois": "Registrant Country: REDACTED FOR PRIVACY"}) is None      # not a country code
    assert geo.vt_registration({}) is None and geo.vt_registration(None) is None
    assert geo.vt_registration({"creation_date": 0, "registrar": ""}) is None


def test_registration_is_attached_to_domains_even_when_the_name_did_not_resolve():
    enr = {"virustotal": {"registration": {"registrar": "R", "created": "2026-09-01"}}}
    g = geo.add_registration(None, enr, "Domain")
    assert g["kind"] == "unknown" and g["registration"]["registrar"] == "R"
    base = geo.describe_location("Domain", "x.example.com", ["1.1.1.1"], {"1.1.1.1": IT})
    assert geo.add_registration(base, enr, "Domain")["registration"]["created"] == "2026-09-01" and base.get("registration") is None
    assert geo.add_registration(None, enr, "IPv4") is None                       # registrations are for names, not addresses
    assert geo.add_registration(base, {}, "Domain") == base


@pytest.mark.parametrize("raw,host", [
    ("Shop.Example.com.", "shop.example.com"), ("HTTP://Evil.example.mu/x?y=1", "evil.example.mu"), ("bücher.example", "xn--bcher-kva.example"),
    ("1.2.3.4", None), ("not a domain", None), ("", None), ("http://[2001:db8::1]/", None),
])
def test_lookup_host_takes_a_name_or_a_url(raw, host):
    assert geo.lookup_host(raw) == host


def _vt_history(client, analyst, monkeypatch, items, status=200, org="Example Hosting"):
    import main

    def handler(req):
        assert req.url.path.endswith("/domains/shop.example.com/resolutions") and req.headers["x-apikey"] == "vt-analyst-key-0123456789"
        return httpx.Response(status, json={"data": items})

    async def fake_geo(ips):
        return {ip: ({"status": "success", "country": "Germany", "countryCode": "DE", "org": org if not ip.startswith("104.") else "Cloudflare, Inc.",
                      "isp": "x", "as": "AS1"}) for ip in ips}
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **kw: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(main, "geo_org_lookup_batch", fake_geo)
    client.post("/users/me/api-keys/virustotal", json={"api_key": "vt-analyst-key-0123456789"}, headers=analyst)
    try:
        return client.get("/v2/dns/history", params={"domain": "https://shop.example.com/login"}, headers=analyst)
    finally:
        client.delete("/users/me/api-keys/virustotal", headers=analyst)


def test_address_history_marks_which_past_addresses_are_not_a_cdn(client, analyst, monkeypatch):
    item = lambda ip, d: {"attributes": {"ip_address": ip, "date": d}}  # noqa: E731
    r = _vt_history(client, analyst, monkeypatch, [item("104.16.1.1", 1790000000), item("93.184.216.34", 1700000000), item("93.184.216.34", 1600000000),
                                                    item("10.0.0.1", 1790000001), {"attributes": {}}])
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["domain"] == "shop.example.com" and j["total"] == 2 and j["not_cdn"] == 1           # private + duplicate + empty dropped
    assert [x["ip"] for x in j["addresses"]] == ["104.16.1.1", "93.184.216.34"]                  # newest first
    assert j["addresses"][0]["cdn"] == "Cloudflare" and j["addresses"][1]["cdn"] is None and j["addresses"][1]["country"] == "Germany"
    assert j["addresses"][1]["last_seen"] == "2023-11-14"


def test_address_history_reports_upstream_problems(client, analyst, monkeypatch):
    assert _vt_history(client, analyst, monkeypatch, [], status=429).status_code == 429
    assert _vt_history(client, analyst, monkeypatch, [], status=503).status_code == 502
    assert client.get("/v2/dns/history", params={"domain": "1.2.3.4"}, headers=analyst).status_code == 400
    assert client.get("/v2/dns/history", params={"domain": "example.com"}).status_code in (401, 403)
