"""VirusSign: lookups, the event feed (cursor, quota bounds, revocations), and how both land in TFII."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

import feeds
import keycheck
import virussign


def _event(i, value, typ="domain", action="upsert", malicious=True, confidence=80, family="AsyncRAT", tags=("c2",)):
    return {"id": f"event--{i}", "timestamp": "2026-10-14T10:00:00Z", "action": action, "reason": "CTX",
            "indicator": {"type": typ, "value": value}, "analysis": {"malicious": malicious, "confidence": confidence, "family": family, "severity": "high"},
            "validity": {"first_seen": "2026-10-13T12:00:00Z", "last_seen": "2026-10-14T09:00:00Z"}, "tags": list(tags)}


# ── Requests and errors ───────────────────────────────────────────────────────
def test_every_indicator_type_has_the_documented_endpoint():
    assert virussign.lookup_request("Domain", "example.com") == ("/v1/ioc/domains/example.com", {"view": "full"})
    assert virussign.lookup_request("IPv4", "1.2.3.4")[0] == "/v1/ioc/ips/1.2.3.4"
    assert virussign.lookup_request("SHA256", "a" * 64)[0] == f"/v1/ioc/files/{'a' * 64}"
    assert virussign.lookup_request("MD5", "b" * 32)[0].startswith("/v1/ioc/files/")
    assert virussign.lookup_request("URL", "http://x.example/a?b=1") == ("/v1/ioc/urls", {"q": "http://x.example/a?b=1", "view": "full"})
    assert virussign.lookup_request("Email", "a@b.example") is None and virussign.lookup_request("CVE", "CVE-2026-1") is None


@pytest.mark.parametrize("status,body,expect", [
    (401, None, "rejected the API key"), (403, {"detail": {"error": {"code": 7, "message": "quota exceeded"}}}, "quota is used up"),
    (403, {"detail": {"error": {"code": 9}}}, "refused the request"), (429, None, "rate limiting"), (422, None, "did not accept"), (503, None, "HTTP 503"),
])
def test_failures_are_explained_without_leaking_anything(status, body, expect):
    out = virussign.interpret(status, body)
    assert expect in out["error"] and "found" not in out


def test_no_record_is_not_a_clean_verdict():
    out = virussign.interpret(404, {"detail": "not found"})
    assert out["found"] is False and "not evidence that it is safe" in out["note"]


def test_a_found_indicator_is_summarised_with_only_documented_fields():
    body = {"meta": {"quota_remaining": 321, "request_id": "r"}, "indicator": {"type": "file", "value": "x", "analysis": {"malicious": True, "severity": "high", "confidence": 91,
            "family": "Lumma", "detections": 42}, "first_seen": "2026-09-01T00:00:00Z", "last_seen": "2026-09-29T00:00:00Z", "surprise": "<script>"}}
    out = virussign.interpret(200, body)
    assert out == {"source": "VirusSign", "found": True, "malicious": True, "severity": "high", "confidence": 91, "family": "Lumma", "detections": 42,
                   "first_seen": "2026-09-01T00:00:00Z", "last_seen": "2026-09-29T00:00:00Z", "link": virussign.HOME, "quota_remaining": 321}


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_lookup_sends_the_key_only_in_the_header_to_the_fixed_host():
    seen = {}

    def handler(request):
        seen.update(url=str(request.url), key=request.headers.get("x-api-key"))
        return httpx.Response(200, json={"indicator": {"analysis": {"malicious": False, "confidence": 20}}})

    async def go():
        async with _client(handler) as c:
            return await virussign.lookup(c, "vs_secret_key", "Domain", "example.com")
    out = asyncio.run(go())
    assert seen["url"].startswith("https://api.virussign.com/v1/ioc/domains/example.com") and seen["key"] == "vs_secret_key" and "vs_secret_key" not in seen["url"]
    assert out["malicious"] is False and "_raw" in out


# ── Feed: windows, paging, quota bounds, resuming ─────────────────────────────
NOW = datetime(2026, 10, 15, 6, 0, 0, tzinfo=timezone.utc)


def test_the_first_window_is_the_last_day_and_never_more_than_a_week():
    w = virussign.plan_window({}, NOW)
    assert (w["since"], w["until"], w["cursor"]) == ("2026-10-14T06:00:00Z", "2026-10-15T06:00:00Z", None)
    old = virussign.plan_window({"until": "2026-08-01T00:00:00Z"}, NOW)
    assert old["since"] == "2026-10-08T06:00:00Z"                                          # a long gap is capped at 7 days
    assert virussign.plan_window({"until": "2026-10-15T01:00:00Z"}, NOW)["since"] == "2026-10-15T01:00:00Z"   # otherwise resume where it ended
    assert virussign.plan_window({"since": "a", "until": "b", "cursor": "c"}, NOW) == {"since": "a", "until": "b", "cursor": "c"}


def _pager(pages, record=None):
    """A fake feed: each call returns the next page, with has_next and a cursor until the last one."""
    calls = []

    def handler(request):
        q = dict(request.url.params)
        calls.append(q)
        i = int(q.get("cursor", "c0")[1:])
        items = pages[i] if i < len(pages) else []
        more = i + 1 < len(pages)
        return httpx.Response(200, json={"meta": {"returned": len(items), "has_next": more, "next_cursor": f"c{i + 1}", "quota_remaining": 900 - i}, "items": items})
    return handler, calls


def test_the_feed_reads_every_page_and_remembers_only_the_window_end():
    handler, calls = _pager([[_event(1, "a.example")], [_event(2, "b.example")]])

    async def go():
        async with _client(handler) as c:
            return await virussign.fetch_events(c, "k", {}, max_events=500, now=NOW)
    items, state, meta = asyncio.run(go())
    assert [i["id"] for i in items] == ["event--1", "event--2"] and state == {"until": "2026-10-15T06:00:00Z"} and meta["pages"] == 2 and meta["quota_remaining"] == 899
    assert calls[0]["mode"] == "events" and calls[0]["since"] == "2026-10-14T06:00:00Z" and calls[1]["cursor"] == "c1" and calls[1]["until"] == calls[0]["until"]


def test_the_quota_bound_stops_the_run_and_the_next_run_resumes_from_the_cursor():
    handler, calls = _pager([[_event(i, f"{i}.example") for i in range(50)] for _ in range(4)])

    async def go(state):
        async with _client(handler) as c:
            return await virussign.fetch_events(c, "k", state, max_events=100, now=NOW)
    items, state, meta = asyncio.run(go({}))
    assert len(items) == 100 and meta["pages"] == 2 and state == {"since": "2026-10-14T06:00:00Z", "until": "2026-10-15T06:00:00Z", "cursor": "c2"}
    items2, state2, _ = asyncio.run(go(state))                                            # the next run continues the same window
    assert calls[2]["cursor"] == "c2" and calls[2]["since"] == "2026-10-14T06:00:00Z" and len(items2) == 100
    assert state2 == {"until": "2026-10-15T06:00:00Z"}                                       # the window is finished; the next one starts here


def test_a_failure_on_the_first_page_raises_and_later_ones_keep_what_was_read():
    def bad(request):
        return httpx.Response(403, json={"detail": {"error": {"code": 7}}})

    async def first():
        async with _client(bad) as c:
            return await virussign.fetch_events(c, "k", {}, max_events=100, now=NOW)
    with pytest.raises(virussign.VirusSignError) as e:
        asyncio.run(first())
    assert e.value.status == 403 and "quota" in e.value.message

    calls = []

    def flaky(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(200, json={"meta": {"has_next": True, "next_cursor": "c1"}, "items": [_event(1, "a.example")]})
        return httpx.Response(429, json={})

    async def second():
        async with _client(flaky) as c:
            return await virussign.fetch_events(c, "k", {}, max_events=500, now=NOW)
    items, state, meta = asyncio.run(second())
    assert len(items) == 1 and state["cursor"] == "c1" and "rate limiting" in meta["stopped"]


# ── Events into candidates ────────────────────────────────────────────────────
def test_events_are_typed_filtered_deduplicated_and_scored_by_their_own_confidence():
    items = [_event(1, "bad.example", confidence=92), _event(1, "bad.example"),                       # duplicate id
             _event(2, "1.2.3.4", typ="ip"), _event(3, "a" * 64, typ="file"), _event(4, "http://x.example/p", typ="url"),
             _event(5, "fine.example", malicious=False), _event(6, "not a value!"), _event(7, "gone.example", action="revoke"), "junk",
             {"id": "e8", "indicator": {"type": "domain", "value": "noconf.example"}, "analysis": {"malicious": True}}]
    out = virussign.parse_events(items)
    assert [(r["type"], r["value"]) for r in out["upserts"]] == [("Domain", "bad.example"), ("IPv4", "1.2.3.4"), ("SHA256", "a" * 64), ("URL", "http://x.example/p"), ("Domain", "noconf.example")]
    assert out["upserts"][0]["reliability"] == pytest.approx(0.92) and out["upserts"][4]["reliability"] == virussign.DEFAULT_RELIABILITY
    assert out["upserts"][0]["family"] == "AsyncRAT" and "virussign" in out["upserts"][0]["tags"] and "asyncrat" in out["upserts"][0]["tags"]
    assert [r["value"] for r in out["revocations"]] == ["gone.example"] and out["not_malicious"] == 1 and out["untyped"] == 1


def test_confidence_is_bounded():
    assert virussign.reliability({"confidence": 100}) == 0.95 and virussign.reliability({"confidence": 3}) == 0.30 and virussign.reliability({}) == virussign.DEFAULT_RELIABILITY


# ── Into the database ─────────────────────────────────────────────────────────
def _run_feed(client, texts, state=None, cfg=None):
    import main
    conn = main.get_db_direct()
    try:
        return asyncio.run(feeds.run_feed(conn, "virussign", cfg or {"min_confidence": 70}, ingest=main._ingest_feed_ioc, record_score=main.record_score,
                                          defang=main.defang, trusted_domains=tuple(main.TRUSTED_DOMAINS), texts=texts, state=state, revoke=main._revoke_feed_ioc))
    finally:
        conn.close()


def _row(db, value):
    cur = db.cursor()
    cur.execute("SELECT confidence, enrichment->>'source', enrichment->>'malware_family', tags, valid_until FROM iocs WHERE value=%s", (value,))
    return cur.fetchone()


def test_the_feed_creates_indicators_with_their_confidence_and_provenance(client, db):
    text = json.dumps({"items": [_event(1, "vs-new.example", confidence=88), _event(2, "9.9.9.9", typ="ip", confidence=40), _event(3, "b" * 64, typ="file", confidence=95)]})
    r = _run_feed(client, {"virussign": text})
    assert r["ok"] and r["added"] == 2 and r["below_floor"] == 1 and r["revoked"] == 0        # the 40-confidence one is under the floor
    conf, src, fam, tags, _ = _row(db, "vs-new.example")
    assert (conf, src, fam) == (88, "VirusSign", "AsyncRAT") and "virussign" in tags
    assert _row(db, "9.9.9.9") is None and _row(db, "b" * 64)[0] == 95
    cur = db.cursor()
    cur.execute("SELECT obs_type, source, source_type FROM entity_observations WHERE entity_ref='vs-new.example'")
    assert cur.fetchall() == [("ingested", "VirusSign", "feed")]


def test_a_revocation_expires_an_indicator_only_this_feed_vouched_for(client, db):
    _run_feed(client, {"virussign": json.dumps({"items": [_event(10, "vs-only.example"), _event(11, "vs-shared.example")]})})
    # a second feed also lists the shared one
    import main
    conn = main.get_db_direct()
    cur = conn.cursor()
    main._ingest_feed_ioc(cur, conn, type_="Domain", value="vs-shared.example", defanged="vs-shared[.]example", tlp="AMBER", confidence=70, description="x", tags=["feed"],
                          enrichment={"source": "OpenPhish"}, valid_days=7, source="OpenPhish")
    conn.commit()
    conn.close()
    r = _run_feed(client, {"virussign": json.dumps({"items": [_event(12, "vs-only.example", action="revoke"), _event(13, "vs-shared.example", action="revoke"),
                                                               _event(14, "vs-unknown.example", action="revoke")]})})
    assert r["ok"] and r["revoked"] == 3 and r["expired"] == 1
    assert _row(db, "vs-only.example")[4] <= datetime.utcnow() + timedelta(seconds=5)                          # expired now
    assert _row(db, "vs-shared.example")[4] > datetime.utcnow() + timedelta(days=1)                            # still stands: another feed vouches for it
    cur = db.cursor()
    cur.execute("SELECT obs_type FROM entity_observations WHERE entity_ref='vs-only.example' ORDER BY id")
    assert [x[0] for x in cur.fetchall()] == ["ingested", "revocation"]


def test_an_analyst_tracked_indicator_is_not_expired_by_a_revocation(client, db):
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE username='admin'")
    admin_id = cur.fetchone()[0]
    _run_feed(client, {"virussign": json.dumps({"items": [_event(20, "vs-analyst.example")]})})
    cur.execute("UPDATE iocs SET created_by=%s WHERE value='vs-analyst.example'", (admin_id,))
    _run_feed(client, {"virussign": json.dumps({"items": [_event(21, "vs-analyst.example", action="revoke")]})})
    assert _row(db, "vs-analyst.example")[4] > datetime.utcnow() + timedelta(days=1)


def test_the_feed_runner_uses_the_fetcher_and_saves_its_state(client, monkeypatch):
    async def fake_fetch(feed, key, fcfg, state):
        assert key == "vs_key" and fcfg == {"limit": 120}
        state.clear()
        state.update({"until": "2026-10-15T06:00:00Z", "quota_remaining": 777})
        return json.dumps({"items": [_event(30, "vs-fetched.example")]})
    monkeypatch.setattr(feeds.FEEDS["virussign"], "fetch", fake_fetch)
    import main
    conn = main.get_db_direct()
    state = {}
    try:
        r = asyncio.run(feeds.run_feed(conn, "virussign", {"min_confidence": 70, "feeds": {"virussign": {"limit": 120}}}, ingest=main._ingest_feed_ioc,
                                       record_score=main.record_score, defang=main.defang, key="vs_key", state=state, revoke=main._revoke_feed_ioc))
    finally:
        conn.close()
    assert r["ok"] and r["added"] == 1 and state == {"until": "2026-10-15T06:00:00Z", "quota_remaining": 777}


def test_a_feed_failure_is_reported_not_raised(client, monkeypatch):
    async def boom(feed, key, fcfg, state):
        raise RuntimeError("VirusSign says the quota is used up.")
    monkeypatch.setattr(feeds.FEEDS["virussign"], "fetch", boom)
    import main
    conn = main.get_db_direct()
    try:
        r = asyncio.run(feeds.run_feed(conn, "virussign", {}, ingest=main._ingest_feed_ioc, record_score=main.record_score, defang=main.defang, key="k"))
    finally:
        conn.close()
    assert r["ok"] is False and "quota is used up" in r["error"]


# ── The lookup inside TFII's verdict ─────────────────────────────────────────
def test_a_confident_virussign_classification_makes_the_verdict_malicious(client):
    import main
    v = main.compute_verdict({"virussign": {"found": True, "malicious": True, "confidence": 91, "family": "Lumma"}})
    assert v["verdict"] == "malicious" and v["score"] == 91 and "VirusSign: classified malicious (91% confidence, Lumma)" in v["reason"]
    weak = main.compute_verdict({"virussign": {"found": True, "malicious": True, "confidence": 40}})
    assert weak["verdict"] == "suspicious"
    none = main.compute_verdict({"virussign": {"found": False}})
    assert none["verdict"] == "unknown"                                  # "no record" is neither clean nor malicious
    clean = main.compute_verdict({"virustotal": {"malicious": 0, "total": 70}, "virussign": {"found": False}})
    assert clean["verdict"] == "clean"


def test_virussign_raises_confidence_but_no_record_never_lowers_it(client):
    import main
    score, reasons = main.calc_confidence({"virussign": {"found": True, "malicious": True, "confidence": 93}}, 50)
    assert score == 93 and any("VirusSign" in r for r in reasons)
    score2, _ = main.calc_confidence({"virussign": {"found": False}}, 80)
    assert score2 == 80


def test_enrich_asks_virussign_when_a_key_exists_and_leaves_it_out_otherwise(client, monkeypatch):
    import main
    asked = []

    async def fake(ioc_type, value, conn=None, key=None, user_id=None):
        asked.append((ioc_type, value, key))
        return {"source": "VirusSign", "found": True, "malicious": True, "confidence": 90, "_detail": {"sections": [{"title": "Assessment", "type": "kv", "rows": [["Malicious", "Yes"]]}]}}
    monkeypatch.setattr(main, "virussign_lookup", fake)
    monkeypatch.setitem(main.PLATFORM_KEYS, "virussign", "vs_platform")
    out = asyncio.run(main.enrich("Domain", "vs-enrich.example", 50, None, force=True))
    assert asked == [("Domain", "vs-enrich.example", "vs_platform")] and out["virussign"]["malicious"] is True and "_detail" not in out["virussign"]
    assert out["calculated_confidence"] >= 90
    asked.clear()
    monkeypatch.setitem(main.PLATFORM_KEYS, "virussign", "")
    out2 = asyncio.run(main.enrich("Domain", "vs-enrich.example", 50, None, force=True))
    assert asked == [] and "virussign" not in out2                                      # no key anywhere: not even a "skipped" card
    monkeypatch.setitem(main.PLATFORM_KEYS, "virussign", "vs_platform")
    asyncio.run(main.enrich("Domain", "vs-enrich.example", 50, None, force=True, skip=("virussign",)))
    assert asked == []                                                                    # background enrichment does not spend VirusSign quota


def test_the_detailed_report_lists_virussign_as_a_provider():
    import details
    enr = {"virussign": {"source": "VirusSign", "found": True, "malicious": True, "confidence": 88, "family": "Lumma"}}
    raw = {"analysis": {"malicious": True, "confidence": 88, "family": "Lumma", "detections": 12}, "sha256": "a" * 64, "filenames": ["x.exe"], "tags": ["stealer"]}
    prov = details.build_providers(enr, {"virussign": {"sections": details.vs_sections(raw)}})
    assert prov[0]["name"] == "VirusSign" and prov[0]["status"] == "ok" and prov[0]["headline"] == "Malicious, confidence 88%, Lumma"
    titles = [s["title"] for s in prov[0]["sections"]]
    assert titles == ["Assessment", "File", "File names", "Tags"]
    nf = details.build_providers({"virussign": {"source": "VirusSign", "found": False}}, {})
    assert nf[0]["status"] == "not_found" and nf[0]["headline"] == "No record"


# ── Key check ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("status,expect", [(200, "valid"), (404, "valid"), (401, "invalid"), (403, "unexpected"), (429, "rate_limited"), (503, "unreachable")])
def test_the_virussign_key_check_treats_no_record_as_a_working_key(status, expect):
    async def go():
        async with _client(lambda r: httpx.Response(status, json={})) as c:
            return await keycheck.check_key("virussign", "vs_key_value", c)
    out = asyncio.run(go())
    assert out["status"] == expect
    if status == 403:
        assert "refused the request" in out["message"]


def test_the_key_can_be_saved_and_the_feed_is_in_the_catalog(client, admin):
    r = client.post("/users/me/api-keys/virussign", json={"api_key": "vs_test_key_123456"}, headers=admin)
    assert r.status_code in (200, 201), r.text
    try:
        cat = client.get("/admin/connectors/catalog", headers=admin).json()
        vs = next(f for f in cat["feeds"] if f["id"] == "virussign")
        assert vs["name"] == "VirusSign threat intelligence" and vs["needs_key"] is True and vs["key_configured"] is True and vs["limit"] == 500
        assert "vs_test_key_123456" not in json.dumps(cat)
    finally:
        client.delete("/users/me/api-keys/virussign", headers=admin)
