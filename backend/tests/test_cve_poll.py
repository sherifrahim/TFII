"""NVD polling: per-asset findings, rate-limit retry, background poll-now, error reporting."""
import asyncio
import time
import uuid
from datetime import datetime, timedelta


class FakeResp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._b, self.headers = status, body or {}, headers or {}

    def json(self):
        return self._b


def _vuln(cve_id):
    return {"cve": {"id": cve_id, "published": (datetime.utcnow() - timedelta(days=5)).strftime("%Y-%m-%dT00:00:00.000"),
                    "lastModified": "2026-09-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": f"{cve_id} flaw in the product"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH", "vectorString": "AV:N"}}]},
                    "references": [{"url": "https://vendor.example/adv", "tags": ["Vendor Advisory"]}]}}


def _patch_upstreams(monkeypatch, vulns, calls=None, fail=False):
    import main

    async def fake_request(params, headers, errors, attempts=4):
        if calls is not None:
            calls.append(dict(params))
        if fail:
            errors.append("NVD HTTP 503")
            return FakeResp(503)
        if params.get("resultsPerPage") == 1:
            return FakeResp(200, {"totalResults": len(vulns)})
        return FakeResp(200, {"vulnerabilities": vulns})

    async def no_kev():
        return {"CVE-2098-0001": "2098-01-02"}

    async def no_epss(ids):
        return {}

    monkeypatch.setattr(main, "_nvd_request", fake_request)
    monkeypatch.setattr(main, "fetch_kev_catalog", no_kev)
    monkeypatch.setattr(main, "fetch_epss", no_epss)


def _wait_done(client, admin, seconds=15):
    end = time.time() + seconds
    while time.time() < end:
        st = client.get("/cves/poll-status", headers=admin).json()
        if not st["running"] and st["result"] is not None:
            return st
        time.sleep(0.15)
    raise AssertionError("poll did not finish")


def _add_assets(db, admin_id_query="SELECT id FROM users WHERE username='admin'"):
    cur = db.cursor()
    cur.execute(admin_id_query)
    uid = cur.fetchone()[0]
    ids = []
    for name in ("PollAlpha", "PollBeta"):
        aid = f"asset--{uuid.uuid4()}"
        cur.execute("INSERT INTO assets (id,name,vendor,version,created_by,active) VALUES (%s,%s,%s,%s,%s,TRUE)", (aid, name, "pollvendor", "1.0", uid))
        ids.append(aid)
    return ids


def test_poll_requires_admin(client, analyst):
    assert client.post("/cves/poll-now", headers=analyst).status_code == 403
    assert client.get("/cves/poll-status", headers=analyst).status_code == 403


def test_shared_cve_is_stored_for_every_affected_asset(client, admin, db, data, monkeypatch):
    """Regression: findings were de-duplicated by CVE id alone, so a CVE affecting two monitored
    products was only ever recorded against whichever was polled first (production: 2927 findings = 2927 CVEs)."""
    a, b = _add_assets(db)
    db.cursor().execute("UPDATE assets SET active = FALSE WHERE id NOT IN (%s, %s)", (a, b))
    _patch_upstreams(monkeypatch, [_vuln("CVE-2098-0001"), _vuln("CVE-2098-0002")])
    r = client.post("/cves/poll-now", headers=admin)
    assert r.status_code == 200 and r.json()["status"] in ("started", "running")
    st = _wait_done(client, admin)
    res = st["result"]
    assert res["assets_polled"] == 2 and res["new_cves"] == 4 and res["errors"] == []
    cur = db.cursor()
    cur.execute("SELECT COUNT(*), COUNT(DISTINCT cve_id), COUNT(DISTINCT asset_id) FROM cve_findings WHERE cve_id IN ('CVE-2098-0001','CVE-2098-0002')")
    assert cur.fetchone() == (4, 2, 2)
    cur.execute("SELECT BOOL_AND(kev_listed) FROM cve_findings WHERE cve_id='CVE-2098-0001'")
    assert cur.fetchone()[0] is True                          # KEV flag applied to both rows
    cur.execute("SELECT assets_polled, new_cves FROM cve_poll_log ORDER BY polled_at DESC LIMIT 1")
    assert cur.fetchone() == (2, 4)                            # the button is logged like the schedule
    # a second poll finds nothing new
    _patch_upstreams(monkeypatch, [_vuln("CVE-2098-0001"), _vuln("CVE-2098-0002")])
    client.post("/cves/poll-now", headers=admin)
    assert _wait_done(client, admin)["result"]["new_cves"] == 0
    cur.execute("UPDATE assets SET active = TRUE")
    cur.execute("DELETE FROM assets WHERE id IN (%s, %s)", (a, b))


def test_upstream_failure_is_reported_not_swallowed(client, admin, db, data, monkeypatch):
    a, b = _add_assets(db)
    db.cursor().execute("UPDATE assets SET active = FALSE WHERE id NOT IN (%s, %s)", (a, b))
    _patch_upstreams(monkeypatch, [], fail=True)
    client.post("/cves/poll-now", headers=admin)
    res = _wait_done(client, admin)["result"]
    assert res["new_cves"] == 0 and len(res["errors"]) >= 2 and "NVD HTTP 503" in res["errors"][0]
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM notifications WHERE title = 'NVD polling is failing'")
    assert cur.fetchone()[0] >= 1                              # visible in the notification centre, not only the log
    cur.execute("UPDATE assets SET active = TRUE")
    cur.execute("DELETE FROM assets WHERE id IN (%s, %s)", (a, b))


def test_nvd_requests_are_paced_and_retried_on_429(monkeypatch):
    import main
    seen, sleeps = [], []
    seq = [FakeResp(429, headers={"Retry-After": "3"}), FakeResp(200, {"ok": 1})]

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, params=None, headers=None):
            seen.append(params)
            return seq.pop(0)

    async def fake_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(main.httpx, "AsyncClient", lambda *a, **k: FakeClient())
    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    main._nvd_gate.update(lock=None, last=0.0)
    errors = []
    r = asyncio.run(main._nvd_request({"x": 1}, {}, errors))
    assert r.status_code == 200 and len(seen) == 2
    assert 3 in sleeps, "must honour Retry-After"
