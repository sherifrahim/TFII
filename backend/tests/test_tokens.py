"""Session tokens: a login token is accepted, bad ones are not."""
from datetime import datetime, timedelta, timezone

import jwt


def _make(main, **claims):
    payload = {"exp": datetime.now(timezone.utc) + timedelta(minutes=5), **claims}
    return jwt.encode(payload, main.SECRET_KEY, algorithm=main.ALGORITHM)


def _me(client, token):
    return client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})


def test_login_token_works_and_has_a_string_subject(client, admin):
    import main
    tok = admin["Authorization"].split()[1]
    assert isinstance(jwt.decode(tok, main.SECRET_KEY, algorithms=[main.ALGORITHM])["sub"], str)
    assert _me(client, tok).status_code == 200


def test_expired_wrong_key_and_none_algorithm_tokens_are_rejected(client, admin):
    import main
    uid = jwt.decode(admin["Authorization"].split()[1], main.SECRET_KEY, algorithms=[main.ALGORITHM])["sub"]
    expired = jwt.encode({"sub": uid, "exp": datetime.now(timezone.utc) - timedelta(minutes=1)}, main.SECRET_KEY, algorithm=main.ALGORITHM)
    forged = jwt.encode({"sub": uid, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, "x" * 32, algorithm=main.ALGORITHM)
    unsigned = jwt.encode({"sub": uid}, None, algorithm="none")
    for bad in (expired, forged, unsigned, "not-a-token"):
        assert _me(client, bad).status_code == 401
