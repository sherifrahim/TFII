"""Bulk lookup: batch size limit, geo chunking, and the time budget."""
import asyncio

import httpx
import pytest


def _ips(n):
    return "\n".join(f"93.184.{i // 250}.{i % 250 + 1}" for i in range(n))


@pytest.fixture
def offline(monkeypatch):
    """No network: geo returns nothing, enrichment returns an empty (unknown) answer."""
    import main

    async def no_geo(ips): return {}

    async def no_enrich(ioc_type, value, base, conn=None, **kw): return {}
    monkeypatch.setattr(main, "geo_org_lookup_batch", no_geo)
    monkeypatch.setattr(main, "enrich", no_enrich)
    return main


def test_a_full_batch_is_accepted_and_one_more_is_not(client, analyst, offline):
    n = offline.MAX_BULK_INDICATORS
    assert n == 150
    ok = client.post("/iocs/bulk-lookup", json={"input": _ips(n)}, headers=analyst)
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["summary"]["total"] == n and len(body["results"]) == n
    too_many = client.post("/iocs/bulk-lookup", json={"input": _ips(n + 1)}, headers=analyst)
    assert too_many.status_code == 400 and f"Max {n}" in too_many.json()["detail"]


def test_the_file_upload_shares_the_limit(client, analyst, offline):
    n = offline.MAX_BULK_INDICATORS
    r = client.post("/iocs/bulk-lookup/file", files={"file": ("l.txt", _ips(n + 1), "text/plain")}, headers=analyst)
    assert r.status_code == 400 and f"Max {n}" in r.json()["detail"]
    r = client.post("/iocs/bulk-lookup/file", files={"file": ("l.txt", _ips(5), "text/plain")}, headers=analyst)
    assert r.status_code == 200 and r.json()["summary"]["total"] == 5


def test_rows_not_reached_in_time_are_reported_not_lost(client, analyst, offline, monkeypatch):
    monkeypatch.setattr(offline, "BULK_DEADLINE_SECONDS", -1)              # budget already spent
    r = client.post("/iocs/bulk-lookup", json={"input": _ips(4)}, headers=analyst)
    assert r.status_code == 200
    rows = r.json()["results"]
    assert len(rows) == 4 and all(x.get("not_checked") and x["verdict"] == "unknown" and "Run these again" in x["reason"] for x in rows)


def test_geo_lookup_sends_more_than_100_addresses_in_chunks(monkeypatch):
    import main
    sizes = []

    def handler(req):
        import json
        batch = json.loads(req.content)
        sizes.append(len(batch))
        return httpx.Response(200, json=[{"query": b["query"], "status": "success", "country": "X"} for b in batch])

    real = httpx.AsyncClient
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler)))
    ips = [f"93.184.0.{i}" for i in range(1, 151)] + [f"93.184.1.{i}" for i in range(1, 51)]
    out = asyncio.run(main.geo_org_lookup_batch(ips))
    assert sizes == [100, 100] and len(out) == 200


def test_a_failing_geo_chunk_does_not_lose_the_others(monkeypatch):
    import main
    calls = []

    def handler(req):
        import json
        batch = json.loads(req.content)
        calls.append(len(batch))
        if len(calls) == 1:
            return httpx.Response(500)
        return httpx.Response(200, json=[{"query": b["query"], "status": "success"} for b in batch])

    real = httpx.AsyncClient
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler)))
    out = asyncio.run(main.geo_org_lookup_batch([f"93.184.0.{i}" for i in range(1, 131)]))
    assert calls == [100, 30] and len(out) == 30
