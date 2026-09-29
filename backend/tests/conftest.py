"""
Test harness: a throwaway PostgreSQL database per test session, the real app
(startup runs the real migrations), and users created through the app's own
flows. Nothing here touches a development or production database.

Connection settings come from the same variables the app reads
(DB_HOST / DB_USER / DB_PASS). The role needs CREATEDB; without a reachable
server the whole suite is skipped rather than failed.
"""
import os
import secrets
import sys
import uuid
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ADMIN_PW = "Adm-" + secrets.token_hex(8)
TEST_DB = "tfii_test_" + secrets.token_hex(4)


def _admin_conn(dbname="postgres"):
    import psycopg2
    return psycopg2.connect(host=os.getenv("DB_HOST", "localhost"), dbname=dbname,
                            user=os.getenv("DB_USER"), password=os.getenv("DB_PASS"), connect_timeout=5)


@pytest.fixture(scope="session")
def client():
    try:
        c = _admin_conn()
        c.autocommit = True
        c.cursor().execute(f'CREATE DATABASE "{TEST_DB}"')
        c.close()
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"no PostgreSQL available for tests ({type(e).__name__}: {str(e).splitlines()[0][:80]})")

    os.environ.update(DB_NAME=TEST_DB, SECRET_KEY=secrets.token_hex(32), ADMIN_INITIAL_PASSWORD=ADMIN_PW,
                      ALLOWED_ORIGINS="", ENCRYPTION_KEY="")
    from fastapi.testclient import TestClient
    import main
    with TestClient(main.app) as tc:
        yield tc
    try:
        c = _admin_conn()
        c.autocommit = True
        c.cursor().execute(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)')
    except Exception:  # noqa: BLE001
        pass


@pytest.fixture(scope="session")
def db(client):
    import psycopg2.extras
    c = _admin_conn(TEST_DB)
    c.autocommit = True
    yield c
    c.close()


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return _login(client, "admin", ADMIN_PW)


@pytest.fixture(scope="session")
def analyst(client, admin):
    """A full-access, non-admin analyst, created through the invite flow."""
    inv = client.post("/invites", json={"role": "analyst"}, headers=admin)
    assert inv.status_code in (200, 201), inv.text
    code = inv.json().get("code")
    pw = "Ana-" + secrets.token_hex(8)
    r = client.post("/auth/signup", json={"username": "analyst1", "password": pw, "invite_code": code})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def analyst2(client, admin):
    inv = client.post("/invites", json={"role": "analyst"}, headers=admin)
    pw = "Ana-" + secrets.token_hex(8)
    r = client.post("/auth/signup", json={"username": "analyst2", "password": pw, "invite_code": inv.json()["code"]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def explorer(client):
    """Open signup gives the restricted explorer role."""
    pw = "Exp-" + secrets.token_hex(8)
    r = client.post("/auth/signup", json={"username": "explorer1", "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def data(client, db, admin):
    """A small, deterministic intelligence graph:

    campaign 'Op Tidewater' (actor 'APT-Test') owns IOCs 1.2.3.4, evil.example, hxxp url on evil.example;
    'LummaTest' malware family on the hash; asset 'WidgetOS' with CVE-2099-0001 (KEV) and -0002.
    """
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE username='admin'")
    admin_id = cur.fetchone()[0]
    now = datetime.utcnow()
    camp = f"campaign--{uuid.uuid4()}"
    cur.execute("INSERT INTO campaigns (id,name,description,threat_actor,industry_targets,created_by) VALUES (%s,%s,%s,%s,%s,%s)",
                (camp, "Op Tidewater", "test campaign", "APT-Test", ["Fintech"], admin_id))
    import psycopg2.extras as ex
    ids = {}

    def ioc(key, typ, value, conf=80, fam=None, campaign=None, source=None, author=admin_id, valid_days=90, tags=None):
        iid = f"indicator--{uuid.uuid4()}"
        enr = {}
        if source:
            enr["source"] = source
        if fam:
            enr["malware_family"] = fam
        cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,created_by,enrichment,
                        valid_until,campaign_id,created_at) VALUES (%s,%s,%s,%s,'General','AMBER',%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (iid, typ, value, value, conf, f"test {key}", tags or ["c2"], author, ex.Json(enr),
                     now + timedelta(days=valid_days), campaign, now - timedelta(days=3)))
        ids[key] = iid
        return iid

    ioc("ip", "IPv4", "1.2.3.4", 92, campaign=camp)
    ioc("domain", "Domain", "evil.example", 85, campaign=camp)
    ioc("url", "URL", "http://evil.example/payload.bin", 88, fam="LummaTest", source="URLhaus")
    ioc("hash", "SHA256", "a" * 64, 95, fam="LummaTest", source="MalwareBazaar", author=None)
    ioc("expired", "Domain", "old.example", 60, valid_days=-2)
    ioc("lowconf", "Domain", "meh.example", 30)

    asset = f"asset--{uuid.uuid4()}"
    cur.execute("INSERT INTO assets (id,name,vendor,version,created_by) VALUES (%s,%s,%s,%s,%s)", (asset, "WidgetOS", "Acme", "4.2", admin_id))
    for n, (score, sev, kev) in enumerate([(9.8, "CRITICAL", True), (5.0, "MEDIUM", False)], start=1):
        cur.execute("""INSERT INTO cve_findings (id,cve_id,asset_id,title,description,cvss_score,cvss_severity,epss_score,kev_listed,
                        kev_date,cwe,affected_versions,published_date,modified_date,patch_available,"references",created_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (f"cve--{uuid.uuid4()}", f"CVE-2099-000{n}", asset, f"CVE-2099-000{n}: Widget flaw {n}", f"Widget overflow {n}. C2 at 1.2.3.4",
                     score, sev, 0.5, kev, "2099-01-05" if kev else None, "CWE-787", "< 4.3", "2099-01-01", "2099-01-02", not kev,
                     ex.Json([{"url": "https://acme.example/advisory/1", "tags": ["Vendor Advisory"]},
                              {"url": "javascript:alert(1)", "tags": ["Patch"]}]), now - timedelta(days=2)))
    cur.execute("INSERT INTO cve_ioc_links (cve_id, ioc_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", ("CVE-2099-0001", ids["ip"]))
    ids.update(campaign=camp, asset=asset)
    return ids


@pytest.fixture(autouse=True)
def _fresh_rate_limits(client):
    """Limits are process-wide; without this the suite trips its own signup limiter."""
    import main
    main.limiter.reset()
    yield
