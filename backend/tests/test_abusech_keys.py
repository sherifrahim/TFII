"""Platform keys: the key saved on an admin account is used first, the .env key second, nobody else's for scheduled runs."""
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
    monkeypatch.setitem(main._ENV_PLATFORM_KEYS, "urlhaus", "")
    monkeypatch.setattr(main, "URLHAUS_AUTH_KEY", "")
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


def test_the_admins_saved_key_is_used_before_the_env_key(client, admin, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setitem(main._ENV_PLATFORM_KEYS, "urlhaus", "stale-env-key-0123456789")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-admin-key-0123456789"}, headers=admin)
    assert _run(main) == {"ok": True, "added": 3}                  # scheduled run: no user
    assert calls == ["good-admin-key-0123456789"]


def test_a_rejected_admin_key_falls_back_to_the_env_key(client, admin, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setitem(main._ENV_PLATFORM_KEYS, "urlhaus", "good-env-key-0123456789")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "stale-admin-key-0123456789"}, headers=admin)
    assert _run(main) == {"ok": True, "added": 3}
    assert calls == ["stale-admin-key-0123456789", "good-env-key-0123456789"]


def test_a_scheduled_run_never_uses_a_non_admin_users_key(client, analyst, setup):
    main, calls = setup
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-analyst-key-0123456789"}, headers=analyst)
    res = _run(main)
    assert res["ok"] is False and "No abuse.ch Auth-Key" in res["error"] and calls == []


def test_an_admin_started_run_may_fall_back_to_users_keys_but_nobody_else_can(client, analyst, analyst2, db, setup):
    main, calls = setup
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "good-analyst-key-0123456789"}, headers=analyst)
    assert _run(main, _user(db, "admin")) == {"ok": True, "added": 3}          # admin fallback, used server-side
    assert calls == ["good-analyst-key-0123456789"]
    calls.clear()
    res = _run(main, _user(db, "analyst2"))                                     # a non-admin never borrows
    assert res["ok"] is False and "No abuse.ch Auth-Key" in res["error"] and calls == []


def test_all_keys_rejected_says_so_and_a_non_auth_error_does_not_try_other_keys(client, admin, db, setup, monkeypatch):
    main, calls = setup
    monkeypatch.setitem(main._ENV_PLATFORM_KEYS, "urlhaus", "stale-env-key-0123456789")
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "also-stale-key-0123456789"}, headers=admin)
    res = _run(main, _user(db, "admin"))
    assert res["ok"] is False and "rejected every Auth-Key" in res["error"] and "auth.abuse.ch" in res["error"]
    assert len(calls) == 2
    calls.clear()
    client.post("/users/me/api-keys/urlhaus", json={"api_key": "broken-admin-key-0123456789"}, headers=admin)   # upstream trouble, not a bad key
    res = _run(main, _user(db, "admin"))
    assert res == {"ok": False, "error": "HTTP 500"} and calls == ["broken-admin-key-0123456789"]


def test_the_otx_feed_key_prefers_an_admin_saved_key(client, admin, analyst, monkeypatch):
    import main
    monkeypatch.setenv("OTX_API_KEY", "server-otx-key-0123456789")
    conn = main.get_db_direct()
    try:
        assert main._feed_key(conn, "otx") == "server-otx-key-0123456789"
        client.post("/users/me/api-keys/otx", json={"api_key": "analyst-otx-key-0123456789"}, headers=analyst)
        assert main._feed_key(conn, "otx") == "server-otx-key-0123456789"       # a non-admin's key is never used
        client.post("/users/me/api-keys/otx", json={"api_key": "admin-otx-key-0123456789"}, headers=admin)
        assert main._feed_key(conn, "otx") == "admin-otx-key-0123456789"        # the admin's saved key wins
    finally:
        conn.close()
        client.delete("/users/me/api-keys/otx", headers=admin)
        client.delete("/users/me/api-keys/otx", headers=analyst)


def test_saving_an_admin_key_repoints_every_platform_call_and_removing_it_restores_env(client, admin, monkeypatch):
    import main
    monkeypatch.setitem(main._ENV_PLATFORM_KEYS, "nvd", "env-nvd-key-0123456789")
    monkeypatch.setattr(main, "NVD_API_KEY", "env-nvd-key-0123456789")
    assert client.post("/users/me/api-keys/nvd", json={"api_key": "admin-nvd-key-0123456789"}, headers=admin).status_code == 200
    try:
        assert main.NVD_API_KEY == "admin-nvd-key-0123456789" and main.PLATFORM_KEYS["nvd"] == "admin-nvd-key-0123456789"
    finally:
        client.delete("/users/me/api-keys/nvd", headers=admin)
    assert main.NVD_API_KEY == "env-nvd-key-0123456789" and main.PLATFORM_KEYS["nvd"] == "env-nvd-key-0123456789"


def test_a_non_admins_key_never_becomes_a_platform_key(client, analyst, monkeypatch):
    import main
    monkeypatch.setitem(main._ENV_PLATFORM_KEYS, "groq", "")
    monkeypatch.setattr(main, "GROQ_API_KEY", "")
    client.post("/users/me/api-keys/groq", json={"api_key": "analyst-groq-key-0123456789"}, headers=analyst)
    try:
        main.refresh_platform_keys()
        assert main.GROQ_API_KEY == "" and main.PLATFORM_KEYS["groq"] == ""
    finally:
        client.delete("/users/me/api-keys/groq", headers=analyst)
