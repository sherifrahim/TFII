"""abuse.ch connectors: a rejected server key falls through to the *triggering* user's own key, nobody else's."""
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


def _user(db, username):
    cur = db.cursor()
    cur.execute("SELECT id, role FROM users WHERE username = %s", (username,))
    i, role = cur.fetchone()
    return {"id": i, "role": role}


def _run(main, user=None):
    conn = main.get_db_direct()
    try:
        return asyncio.run(main._run_abusech("urlhaus", conn, {}, user))
    finally:
        conn.close()


def test_a_rejected_server_key_falls_through_to_the_starters_own_key(client, admin, db, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "stale-env-key-0123456789")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-admin-key-0123456789"}, headers=admin)
    assert _run(main, _user(db, "admin")) == {"ok": True, "added": 3}
    assert calls == ["stale-env-key-0123456789", "good-admin-key-0123456789"]


def test_a_scheduled_run_falls_back_to_a_key_saved_on_an_admin_account(client, admin, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "stale-env-key-0123456789")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-admin-key-0123456789"}, headers=admin)
    assert _run(main) == {"ok": True, "added": 3}                  # no user: server key first, then the admin's
    assert calls == ["stale-env-key-0123456789", "good-admin-key-0123456789"]


def test_a_scheduled_run_never_uses_a_non_admin_users_key(client, analyst, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-analyst-key-0123456789"}, headers=analyst)
    res = _run(main)
    assert res["ok"] is False and "No abuse.ch Auth-Key" in res["error"] and calls == []


def test_the_otx_feed_key_falls_back_the_same_way(client, admin, analyst, monkeypatch):
    import main
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    conn = main.get_db_direct()
    try:
        assert main._feed_key(conn, "otx") == ""
        client.post("/users/me/api-keys/otx", json={"api_key": "analyst-otx-key-0123456789"}, headers=analyst)
        assert main._feed_key(conn, "otx") == ""                    # a non-admin's key is never used
        client.post("/users/me/api-keys/otx", json={"api_key": "admin-otx-key-0123456789"}, headers=admin)
        assert main._feed_key(conn, "otx") == "admin-otx-key-0123456789"
        monkeypatch.setenv("OTX_API_KEY", "server-otx-key-0123456789")
        assert main._feed_key(conn, "otx") == "server-otx-key-0123456789"     # the server key still wins
    finally:
        conn.close()
        client.delete("/users/me/api-keys/otx", headers=admin)
        client.delete("/users/me/api-keys/otx", headers=analyst)


def test_an_admin_started_run_may_fall_back_to_users_keys_but_nobody_else_can(client, analyst, analyst2, db, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-analyst-key-0123456789"}, headers=analyst)
    assert _run(main, _user(db, "admin")) == {"ok": True, "added": 3}          # admin fallback, used server-side
    assert calls == ["good-analyst-key-0123456789"]
    calls.clear()
    res = _run(main, _user(db, "analyst2"))                                     # a non-admin never borrows
    assert res["ok"] is False and "No abuse.ch Auth-Key" in res["error"] and calls == []


def test_all_keys_rejected_says_so_and_a_non_auth_error_does_not_try_other_keys(client, admin, db, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "stale-env-key-0123456789")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "also-stale-key-0123456789"}, headers=admin)
    res = _run(main, _user(db, "admin"))
    assert res["ok"] is False and "rejected every Auth-Key" in res["error"] and "auth.abuse.ch" in res["error"]
    assert len(calls) == 2
    calls.clear()
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "broken-env-key-0123456789")      # upstream trouble, not a bad key
    res = _run(main, _user(db, "admin"))
    assert res == {"ok": False, "error": "HTTP 500"} and calls == ["broken-env-key-0123456789"]
