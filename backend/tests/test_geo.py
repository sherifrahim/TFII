"""Locations are labelled for what they are: an IP's GeoIP, a domain's hosting, a CDN edge, a registry country."""
import asyncio

import httpx
import pytest

import geo

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
