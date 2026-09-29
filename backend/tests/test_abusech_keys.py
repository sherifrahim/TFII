"""abuse.ch connectors: a rejected server key must fall through to a working admin key; other errors must not."""
import asyncio

import pytest


@pytest.fixture
def setup(client, admin, analyst, monkeypatch):
    import main
    calls = []

    async def fake(conn, key, arg):
        calls.append(key)
        if key.startswith("good"):
            return {"ok": True, "added": 3}
        if key.startswith("broken"):
            return {"ok": False, "error": "HTTP 500"}
        return {"ok": False, "error": "HTTP 403"}
    monkeypatch.setattr(main, "run_urlhaus_connector", fake)
    yield main, calls
    client.delete("/users/me/api-keys/urlhaus", headers=admin)
    client.delete("/users/me/api-keys/urlhaus", headers=analyst)


def _run(main):
    conn = main.get_db_direct()
    try:
        return asyncio.run(main._run_abusech("urlhaus", conn, {}))
    finally:
        conn.close()


def test_a_rejected_server_key_falls_through_to_the_admins_saved_key(client, admin, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "stale-env-key-0123456789")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-admin-key-0123456789"}, headers=admin)
    res = _run(main)
    assert res == {"ok": True, "added": 3}
    assert calls == ["stale-env-key-0123456789", "good-admin-key-0123456789"]


def test_only_admin_accounts_keys_are_borrowed_for_platform_feeds(client, analyst, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-analyst-key-0123456789"}, headers=analyst)
    res = _run(main)
    assert res["ok"] is False and "No abuse.ch Auth-Key" in res["error"] and calls == []


def test_all_keys_rejected_says_so_and_a_non_auth_error_does_not_try_other_keys(client, admin, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "stale-env-key-0123456789")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "also-stale-key-0123456789"}, headers=admin)
    res = _run(main)
    assert res["ok"] is False and "rejected every Auth-Key" in res["error"] and "auth.abuse.ch" in res["error"]
    assert len(calls) == 2
    calls.clear()
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "broken-env-key-0123456789")      # upstream trouble, not a bad key
    res = _run(main)
    assert res == {"ok": False, "error": "HTTP 500"} and calls == ["broken-env-key-0123456789"]
