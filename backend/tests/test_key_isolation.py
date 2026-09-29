"""Saved API keys are never shown, listed, tested or returned to anyone but the account that saved them.
(The admin fallback, which uses another user's key server-side without exposing it, is a deliberate exception.)"""
import pytest

SECRET = "iso-secret-key-ABCDEFGH-0123456789"


@pytest.fixture
def analyst_key(client, analyst):
    assert client.post("/users/me/api-keys/virustotal", json={"api_key": SECRET}, headers=analyst).status_code == 200
    yield
    client.delete("/users/me/api-keys/virustotal", headers=analyst)


def test_nobody_else_can_see_or_test_a_saved_key(client, admin, analyst, analyst2, explorer, analyst_key):
    mine = {r["service"]: r for r in client.get("/users/me/api-keys", headers=analyst).json()}
    assert mine["virustotal"]["has_key"] is True
    for who in (admin, analyst2, explorer):
        rows = {r["service"]: r for r in client.get("/users/me/api-keys", headers=who).json()}
        assert rows["virustotal"]["has_key"] is False and rows["virustotal"]["masked"] is None
        assert rows["virustotal"]["source"] != "personal"
        # "test my saved key" finds nothing of the analyst's, even for an admin
        assert client.post("/users/me/api-keys/virustotal/test", headers=who).status_code == 400
        # and nothing else the account can list carries the key
        for path in ("/users/me/api-keys", "/users/me/quota", "/users", "/admin/connectors/catalog"):
            assert SECRET not in client.get(path, headers=who).text


def test_the_owner_only_ever_gets_a_short_hint_back(client, analyst, analyst_key):
    r = client.get("/users/me/api-keys", headers=analyst)
    assert SECRET not in r.text
    hint = {x["service"]: x for x in r.json()}["virustotal"]["masked"]
    assert hint == "••••••••" + SECRET[-4:]
    saved = client.post("/users/me/api-keys/virustotal", json={"api_key": SECRET}, headers=analyst)
    assert SECRET not in saved.text and saved.json()["masked"] == hint


def test_short_keys_reveal_nothing():
    import main
    assert main.mask_key("abcdefghij") == "••••••••" and main.mask_key("") == "••••••••"
    assert main.mask_key(SECRET).startswith("••••••••") and SECRET[:4] not in main.mask_key(SECRET)


def test_only_an_admin_can_fall_back_to_another_users_key(client, db, analyst, analyst_key, monkeypatch):
    import main
    monkeypatch.setitem(main.PLATFORM_KEYS, "virustotal", "")
    cur = db.cursor()

    def who(name):
        cur.execute("SELECT id, role FROM users WHERE username = %s", (name,))
        i, role = cur.fetchone()
        return {"id": i, "role": role}
    conn = main.get_db_direct()
    try:
        assert main.resolve_api_key(conn, "virustotal", who("analyst1")) == (SECRET, True, None)      # the owner
        assert main.resolve_api_key(conn, "virustotal", who("admin")) == (SECRET, False, None)        # admin fallback (server-side)
        assert main.resolve_api_key(conn, "virustotal", who("analyst2"))[0] == ""                     # everyone else: never
    finally:
        conn.close()
