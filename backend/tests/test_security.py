"""Security baseline: every route is authenticated, hostile input is refused server-side, no SSRF, safe URLs."""
import asyncio

import httpcore
import pytest

import security

# Routes that are intentionally reachable without a token.
PUBLIC = {("GET", "/health"), ("POST", "/auth/login"), ("POST", "/auth/signup"), ("GET", "/public/search")}


def _concrete(path):
    import re
    return re.sub(r"\{[^}]+\}", "x", path)


def test_no_route_answers_without_authentication(client):
    """The sweep that keeps a forgotten Depends() from shipping."""
    offenders = []
    for route in client.app.routes:
        methods = getattr(route, "methods", None)
        if not methods:
            continue
        for m in methods - {"HEAD", "OPTIONS"}:
            path = _concrete(route.path)
            if (m, route.path) in PUBLIC or path.startswith(("/f/", "/static")):
                continue
            r = client.request(m, path)
            if r.status_code not in (401, 403, 404, 405, 422):
                offenders.append((m, route.path, r.status_code))
    assert offenders == [], offenders


def test_public_endpoints_are_rate_limited_or_inert(client):
    assert client.get("/health").status_code == 200
    r = client.get("/public/search", params={"q": "1.2.3.4"})
    assert r.status_code in (200, 400, 422, 429, 503)


def test_api_docs_and_schema_are_not_exposed(client):
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(p).status_code == 404


def test_security_headers_on_every_response(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    r = client.get("/v2/iocs")
    assert r.headers["cache-control"] == "no-store"


def test_cors_is_same_origin_only(client):
    r = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers
    pre = client.options("/v2/iocs", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in pre.headers


def test_errors_do_not_leak_internals(client, analyst):
    r = client.get("/v2/entity", params={"kind": "indicator"}, headers=analyst)     # missing ref
    assert r.status_code == 422
    r = client.get("/definitely/not/a/route")
    assert r.status_code == 404 and "Traceback" not in r.text


def test_login_rejects_bad_credentials_uniformly(client):
    a = client.post("/auth/login", data={"username": "admin", "password": "wrong-password-1"})
    b = client.post("/auth/login", data={"username": "no-such-user", "password": "wrong-password-1"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


@pytest.mark.parametrize("user,pw", [("ab", "longenough-1"), ("bad name!", "longenough-1"), ("okname", "short")])
def test_signup_enforces_policy_server_side(client, user, pw):
    assert client.post("/auth/signup", json={"username": user, "password": pw}).status_code == 400


def test_open_signup_never_grants_more_than_explorer(client):
    r = client.post("/auth/signup", json={"username": "sneaky", "password": "longenough-99", "role": "admin"})
    assert r.status_code == 200
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"}).json()
    assert me["role"] == "explorer"
    assert "data.workspace" not in me["capabilities"] and "admin.panel" not in me["capabilities"]


def test_analyst_cannot_use_admin_endpoints(client, analyst):
    for m, p in [("GET", "/users"), ("POST", "/invites"), ("GET", "/invites")]:
        assert client.request(m, p, headers=analyst, json={"role": "admin"} if m == "POST" else None).status_code == 403, (m, p)


# ── SSRF ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("1.1.1.1", True), ("2606:4700:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("172.16.0.5", False), ("192.168.1.1", False),
    ("169.254.169.254", False), ("0.0.0.0", False), ("100.64.0.1", False), ("::1", False), ("fe80::1", False),
    ("fc00::1", False), ("::ffff:127.0.0.1", False), ("224.0.0.1", False), ("not-an-ip", False),
])
def test_is_public_ip(ip, public):
    assert security.is_public_ip(ip) is public


def test_guarded_backend_refuses_private_and_mixed_answers():
    async def to_private(host, port): return ["10.0.0.5"]
    async def mixed(host, port): return ["93.184.216.34", "127.0.0.1"]
    for resolver in (to_private, mixed):
        be = security.GuardedBackend(resolver=resolver)
        with pytest.raises(httpcore.ConnectError, match="blocked"):
            asyncio.run(be.connect_tcp("rebind.example", 80))


def test_guarded_backend_refuses_unix_sockets():
    with pytest.raises(httpcore.ConnectError):
        asyncio.run(security.GuardedBackend().connect_unix_socket("/var/run/docker.sock"))


@pytest.mark.parametrize("url", ["http://127.0.0.1:9", "http://localhost:9/x", "http://169.254.169.254/latest/meta-data", "http://[::1]:9"])
def test_import_endpoints_cannot_be_pointed_at_internal_hosts(client, admin, url):
    r = client.post("/iocs/import/taxii", json={"server_url": url, "collection_id": "x"}, headers=admin)
    assert r.status_code == 502 and "blocked" in r.json()["detail"].lower()
    r = client.post("/iocs/import/misp", json={"misp_url": url, "misp_key": "k"}, headers=admin)
    assert r.status_code == 502 and "blocked" in r.json()["detail"].lower()


def test_redirect_tracer_cannot_reach_internal_hosts(client, analyst):
    r = client.post("/tools/trace-redirects", json={"url": "http://169.254.169.254/latest/meta-data"}, headers=analyst)
    body = r.text.lower()
    assert r.status_code in (200, 400) and ("blocked" in body or "non-public" in body or "not allowed" in body), r.text[:300]


# ── URL handling ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("u,ok", [
    ("https://example.com/a?b=c", True), ("http://example.com", True),
    ("javascript:alert(1)", False), ("JaVaScRiPt:alert(1)", False), ("data:text/html,<script>", False),
    ("vbscript:x", False), ("//evil.example", False), ("https://exa mple.com", False), ("https://x.com/\x01", False),
    ("", False), (None, False), ("ftp://x.com", False), ("http://" + "a" * 3000, False),
])
def test_safe_http_url(u, ok):
    assert (security.safe_http_url(u) is not None) is ok


@pytest.mark.parametrize("d,ok", [("example.com", True), ("a-b.example.co.uk", True), ("bad_domain.com", False), ("-x.com", False),
                                  ("x" * 64 + ".com", False), ("no_tld", False), ("a..com", False), ("exa mple.com", False), ("", False)])
def test_is_valid_domain(d, ok):
    assert security.is_valid_domain(d) is ok


def test_stored_javascript_reference_urls_are_never_served_as_links(client, analyst, data):
    env = client.get("/v2/entity", params={"kind": "cve", "ref": "CVE-2099-0001"}, headers=analyst).json()
    urls = [r["url"] for r in env["overview"]["references"]]
    assert all(u.startswith("https://") for u in urls)
    assert env["overview"]["software"][0]["patch_url"] in (None, "") or env["overview"]["software"][0]["patch_url"].startswith("http")


# ── injection / hostile values ───────────────────────────────────────────────
HOSTILE = ["' OR '1'='1", "\"; DROP TABLE iocs; --", "%00", "\x00", "<script>alert(1)</script>", "${jndi:ldap://x}", "{{7*7}}", "../../etc/passwd", "a" * 5000]


@pytest.mark.parametrize("value", HOSTILE)
def test_hostile_values_never_500(client, analyst, data, value):
    for path, params in [("/v2/search", {"q": value}), ("/v2/entity", {"kind": "indicator", "ref": value}),
                         ("/v2/iocs", {"q": value}), ("/v2/entity", {"kind": "actor", "ref": value}),
                         ("/v2/entity/timeline", {"kind": "cve", "ref": value}), ("/v2/intel-wall", {"entity_kind": "cve", "entity_ref": value})]:
        try:
            r = client.get(path, params=params, headers=analyst)
        except Exception as e:                      # noqa: BLE001 — httpx refusing to encode is fine
            assert "\x00" in value, e
            continue
        assert r.status_code < 500, (path, value[:20], r.status_code, r.text[:200])


def test_iocs_table_survives_injection_attempts(client, analyst, data):
    client.get("/v2/search", params={"q": "'; DROP TABLE iocs;--"}, headers=analyst)
    assert client.get("/v2/iocs", headers=analyst).json()["total"] > 0


def test_stored_text_is_returned_as_data_not_markup(client, analyst, data):
    body = "<img src=x onerror=alert(1)>"
    r = client.post("/v2/relationships", json={"src_kind": "indicator", "src_ref": "xss1.example", "rel_type": "related_to",
                                                "dst_kind": "indicator", "dst_ref": "xss2.example", "note": body}, headers=analyst)
    assert r.status_code == 201
    r = client.get("/v2/entity", params={"kind": "indicator", "ref": "xss1.example"}, headers=analyst)
    assert r.headers["content-type"].startswith("application/json")
    assert body in r.text            # stored verbatim, JSON-escaped; the UI renders it as text (React), never as HTML


def test_signup_and_login_are_rate_limited(client):
    codes = [client.post("/auth/signup", json={"username": f"spam{i}", "password": "longenough-99"}).status_code for i in range(7)]
    assert 429 in codes and codes[0] == 200
    logins = [client.post("/auth/login", data={"username": "admin", "password": "wrong-password-1"}).status_code for _ in range(12)]
    assert 429 in logins


def test_upstream_failures_are_502_not_500(client, analyst, monkeypatch):
    import httpx
    import main

    class Boom:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): raise httpx.ConnectError("boom https://secret.internal/token=abc")
        async def __aexit__(self, *a): return False

    monkeypatch.setattr(main.httpx, "AsyncClient", Boom)
    r = client.get("/advisory/suggested-cves", headers=analyst)
    assert r.status_code == 502 and "secret" not in r.text and "token" not in r.text
