"""Key check: what each provider's answer means, and that a key is never echoed back."""
import asyncio
import json

import httpx
import pytest

import keycheck


def _check(service, key, handler):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await keycheck.check_key(service, key, c)
    return asyncio.run(go())


@pytest.mark.parametrize("service,status,expect", [
    ("virustotal", 200, "valid"), ("virustotal", 401, "invalid"), ("abuseipdb", 401, "invalid"),
    ("shodan", 401, "invalid"), ("groq", 403, "invalid"), ("otx", 403, "invalid"), ("urlhaus", 401, "invalid"),
    ("nvd", 404, "invalid"),                                         # NVD's way of saying "bad apiKey"
    ("virustotal", 404, "unexpected"),                               # a 404 elsewhere is not a verdict on the key
    ("virustotal", 429, "rate_limited"), ("nvd", 503, "unreachable"), ("groq", 302, "unexpected"),
])
def test_provider_answers_are_interpreted(service, status, expect):
    r = _check(service, "k" * 24, lambda req: httpx.Response(status))
    assert r["status"] == expect
    assert r["ok"] is {"valid": True, "invalid": False}.get(expect)


def test_each_provider_gets_the_key_the_way_it_expects_it():
    seen = {}

    def handler(req):
        seen[req.url.host] = (dict(req.headers), dict(req.url.params))
        return httpx.Response(200)

    for svc in keycheck.PROBES:
        _check(svc, "sekret-key-0123456789", handler)
    assert seen["www.virustotal.com"][0]["x-apikey"] == "sekret-key-0123456789"
    assert seen["api.abuseipdb.com"][0]["key"] == "sekret-key-0123456789"
    assert seen["api.shodan.io"][1]["key"] == "sekret-key-0123456789"
    assert seen["api.groq.com"][0]["authorization"] == "Bearer sekret-key-0123456789"
    assert seen["services.nvd.nist.gov"][0]["apikey"] == "sekret-key-0123456789"
    assert seen["urlhaus-api.abuse.ch"][0]["auth-key"] == "sekret-key-0123456789"
    assert seen["otx.alienvault.com"][0]["x-otx-api-key"] == "sekret-key-0123456789"
    assert all(u.startswith("https://") for u in (p.url for p in keycheck.PROBES.values()))


def test_network_failure_is_unreachable_and_leaks_nothing():
    def boom(req):
        raise httpx.ConnectError("connect failed for " + str(req.url))     # url contains the Shodan key
    r = _check("shodan", "sekret-key-0123456789", boom)
    assert r["status"] == "unreachable" and r["ok"] is None
    assert "sekret-key" not in json.dumps(r)


@pytest.mark.parametrize("key", ["", "   ", "has space", "line\nbreak", "ünïcode-key", "x" * 600])
def test_malformed_keys_are_rejected_without_a_request(key):
    def never(req): raise AssertionError("no request should be made")
    r = _check("virustotal", key, never)
    assert r["status"] == "invalid" and r["ok"] is False


# ── endpoint ─────────────────────────────────────────────────────────────────
@pytest.fixture
def fake_provider(monkeypatch):
    import main
    calls = []

    async def fake(service, key, client=None):
        calls.append((service, key))
        return {"status": "valid" if key.startswith("good") else "invalid", "ok": key.startswith("good"), "message": "m"}
    monkeypatch.setattr(main.keycheck, "check_key", fake)
    return calls


def test_pasted_key_is_tested_without_being_saved(client, analyst, fake_provider):
    r = client.post("/users/me/api-keys/groq/test", json={"api_key": "good-pasted-key-000111"}, headers=analyst)
    assert r.status_code == 200
    assert r.json()["status"] == "valid" and r.json()["tested"] == "pasted" and r.json()["checked_at"]
    assert "good-pasted-key" not in r.text
    assert fake_provider == [("groq", "good-pasted-key-000111")]
    rows = {x["service"]: x for x in client.get("/users/me/api-keys", headers=analyst).json()}
    assert rows["groq"]["has_key"] is False                      # testing does not save


def test_saved_key_is_tested_when_none_is_pasted(client, analyst, analyst2, fake_provider):
    assert client.post("/users/me/api-keys/otx/test", json={}, headers=analyst).status_code == 400   # nothing saved yet
    client.post("/users/me/api-keys/otx", json={"api_key": "bad-saved-key-0011223344"}, headers=analyst)
    r = client.post("/users/me/api-keys/otx/test", headers=analyst)
    assert r.status_code == 200 and r.json()["tested"] == "saved" and r.json()["status"] == "invalid"
    assert fake_provider[-1] == ("otx", "bad-saved-key-0011223344")
    assert "bad-saved-key" not in r.text
    # somebody else's saved key can never be tested through your account
    assert client.post("/users/me/api-keys/otx/test", headers=analyst2).status_code == 400
    client.delete("/users/me/api-keys/otx", headers=analyst)


def test_key_test_requires_login_and_a_known_service(client, analyst, explorer, fake_provider):
    assert client.post("/users/me/api-keys/groq/test", json={"api_key": "x" * 20}).status_code in (401, 403)
    assert client.post("/users/me/api-keys/nope/test", json={"api_key": "x" * 20}, headers=analyst).status_code == 400
    assert client.post("/users/me/api-keys/groq/test", json={"api_key": ["x"]}, headers=analyst).status_code == 400
    assert client.post("/users/me/api-keys/groq/test", json={"api_key": "good" + "x" * 20}, headers=explorer).status_code == 200
