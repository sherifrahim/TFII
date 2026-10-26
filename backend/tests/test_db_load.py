"""Database load: the observation lookups use an index, a feed that re-lists an indicator refreshes one row, batches commit,
downloads retry, and the connectors report readable errors."""
import asyncio
import json

import httpx
import pytest

import dbmaint
import entities
import feeds


def _plan(db, sql, params=()):
    cur = db.cursor()
    cur.execute("SET enable_seqscan = off")                       # the table is tiny in tests; ask what the planner CAN do
    try:
        cur.execute("EXPLAIN " + sql, params)
        return "\n".join(r[0] for r in cur.fetchall())
    finally:
        cur.execute("RESET enable_seqscan")


def test_the_lower_entity_ref_lookup_has_an_index(client, db):
    import main
    first = dbmaint.run(main.get_db_direct, force=True)
    assert first["index"] in ("created", "present") and "error" not in first
    assert dbmaint.run(main.get_db_direct)["index"] == "present"                 # repeating it is harmless
    cur = db.cursor()
    cur.execute("SELECT indexdef FROM pg_indexes WHERE tablename = 'entity_observations' AND indexname = 'idx_eo_entity_lower'")
    row = cur.fetchone()
    assert row and "lower(entity_ref)" in row[0].lower() and "entity_kind" in row[0]
    plan = _plan(db, "SELECT source, MAX(confidence) FROM entity_observations WHERE entity_kind = 'indicator' AND LOWER(entity_ref) = LOWER(%s) GROUP BY source", ("x.example",))
    assert "idx_eo_entity_lower" in plan
    batch = _plan(db, "SELECT source FROM entity_observations WHERE entity_kind = 'indicator' AND LOWER(entity_ref) = ANY(%s)", (["x.example", "y.example"],))
    assert "idx_eo_entity_lower" in batch


def _count(db, ref, obs_type="sighting"):
    cur = db.cursor()
    cur.execute("SELECT COUNT(*), MAX((data->>'times_seen')::int) FROM entity_observations WHERE entity_ref = %s AND obs_type = %s", (ref, obs_type))
    return cur.fetchone()


def test_a_repeat_sighting_refreshes_one_row_instead_of_adding_one(client, db):
    import main
    conn = main.get_db_direct()
    try:
        for _ in range(4):
            entities.touch_sighting(conn, "indicator", "Repeat.example", "OpenPhish", "feed", confidence=80, summary="Seen again")
        entities.touch_sighting(conn, "indicator", "repeat.example", "IPsum", "feed", confidence=70, summary="Seen again")     # another source: its own row
        conn.commit()
    finally:
        conn.close()
    cur = db.cursor()
    cur.execute("SELECT source, (data->>'times_seen')::int FROM entity_observations WHERE LOWER(entity_ref) = 'repeat.example' AND obs_type = 'sighting' ORDER BY source")
    assert cur.fetchall() == [("IPsum", 1), ("OpenPhish", 4)]


def test_the_feed_ingest_uses_it_and_provenance_still_names_every_source(client, db):
    import main
    conn = main.get_db_direct()
    try:
        cur = conn.cursor()
        kw = dict(type_="Domain", value="refresh-me.example", defanged="refresh-me[.]example", tlp="AMBER", confidence=70, description="x", tags=["feed"],
                  enrichment={"source": "OpenPhish"}, valid_days=7, source="OpenPhish")
        assert main._ingest_feed_ioc(cur, conn, **kw)[0] is True
        for _ in range(3):
            assert main._ingest_feed_ioc(cur, conn, **kw)[0] is False
        conn.commit()
    finally:
        conn.close()
    assert _count(db, "refresh-me.example") == (1, 3)
    assert _count(db, "refresh-me.example", "ingested")[0] == 1


def test_the_cleanup_collapses_old_sighting_rows_and_keeps_the_count(client, db):
    cur = db.cursor()
    for i in range(5):
        cur.execute("""INSERT INTO entity_observations (entity_kind, entity_ref, obs_type, source, source_type, confidence, ingested_at)
                       VALUES ('indicator', 'Old-Dupes.example', 'sighting', 'IPsum', 'feed', %s, NOW() - %s * INTERVAL '1 day')""", (60 + i, 5 - i))
    cur.execute("INSERT INTO entity_observations (entity_kind, entity_ref, obs_type, source, source_type) VALUES ('indicator', 'old-dupes.example', 'sighting', 'CINS Army', 'feed')")
    cur.execute("INSERT INTO entity_observations (entity_kind, entity_ref, obs_type, source, source_type) VALUES ('indicator', 'old-dupes.example', 'ingested', 'IPsum', 'feed')")
    # a row the new code already refreshed (times_seen 3) plus two older plain rows: 3 + 1 + 1 = 5 sightings in all
    for i, seen in enumerate((None, None, 3)):
        cur.execute("""INSERT INTO entity_observations (entity_kind, entity_ref, obs_type, source, source_type, data, ingested_at)
                       VALUES ('indicator', 'mixed.example', 'sighting', 'OpenPhish', 'feed', %s, NOW() - %s * INTERVAL '1 hour')""",
                    (json.dumps({"times_seen": seen} if seen else {}), 3 - i))
    out = dbmaint.collapse_sightings(cur, batch=1, pause=0)                      # one group per batch: exercises the loop
    assert out == {"groups": 2, "deleted": 6, "batches": 2}              # IPsum (5 rows -> 1) and OpenPhish (3 -> 1), one group per batch
    cur.execute("SELECT obs_type, source, confidence, (data->>'times_seen')::int FROM entity_observations WHERE LOWER(entity_ref) = 'old-dupes.example' ORDER BY obs_type, source")
    assert cur.fetchall() == [("ingested", "IPsum", None, None), ("sighting", "CINS Army", None, None), ("sighting", "IPsum", 64, 5)]      # newest kept, 5 counted
    cur.execute("SELECT (data->>'times_seen')::int FROM entity_observations WHERE entity_ref = 'mixed.example'")
    assert cur.fetchall() == [(5,)]
    assert dbmaint.collapse_sightings(cur, pause=0) == {"groups": 0, "deleted": 0, "batches": 0}      # nothing left to do


def test_the_maintenance_job_skips_when_another_worker_has_it_and_remembers_when_done(client, db):
    import main
    holder = main.get_db_direct()
    try:
        holder.autocommit = True
        holder.cursor().execute("SELECT pg_advisory_lock(%s)", (dbmaint.LOCK_ID,))
        assert dbmaint.run(main.get_db_direct) == {"skipped": "another worker is running it"}
    finally:
        holder.close()                                                          # closing the session releases its lock
    done = dbmaint.run(main.get_db_direct, force=True)
    assert "error" not in done and done["collapse"]["batches"] >= 0
    again = dbmaint.run(main.get_db_direct)
    assert again["collapse"] == "already done"


def test_startup_does_not_run_the_heavy_work_inside_a_migration():
    import migrations
    text = " ".join(sql for _v, _n, steps in migrations.MIGRATIONS for sql, _o in steps)
    assert "idx_eo_entity_lower" not in text and "ROW_NUMBER" not in text


# ── Batched corroboration gives the same answer as the per-indicator query ────
def test_a_batch_scores_the_same_as_the_single_lookup(client, db):
    import main
    conn = main.get_db_direct()
    try:
        cur = conn.cursor()
        for src, conf in (("OpenPhish", 80), ("Phishing Database", 60)):
            main._ingest_feed_ioc(cur, conn, type_="Domain", value="both.example", defanged="both[.]example", tlp="AMBER", confidence=conf, description="x",
                                  tags=["feed"], enrichment={"source": src}, valid_days=7, source=src)
        conn.commit()
        batch = feeds.observation_scores(conn, ["Both.example", "nobody.example"])
        assert batch == {"both.example": {"OpenPhish": 80, "Phishing Database": 60}}
        cur.execute("SELECT id FROM iocs WHERE value = 'both.example'")
        ioc_id = cur.fetchone()[0]
        calls = []
        new = feeds.corroborate(conn, ioc_id, "both.example", lambda *a: calls.append(a), observed=batch["both.example"])
        cur.execute("SELECT confidence FROM iocs WHERE id = %s", (ioc_id,))
        assert new == cur.fetchone()[0] and new > 80 and calls                       # raised by the second source, history written
    finally:
        conn.close()


def test_a_run_with_many_indicators_makes_a_few_observation_queries_not_one_each(client, db, monkeypatch):
    import main
    seen = {"batch": 0, "single": 0}
    real_obs, real_cor = feeds.observation_scores, feeds.corroborate

    def counting_obs(*a, **k):
        seen["batch"] += 1
        return real_obs(*a, **k)

    def counting_cor(conn, ioc_id, key, rs, actor="feed corroboration", observed=None):
        seen["single"] += observed is None
        return real_cor(conn, ioc_id, key, rs, actor, observed)
    monkeypatch.setattr(feeds, "observation_scores", counting_obs)
    monkeypatch.setattr(feeds, "corroborate", counting_cor)
    text = "\n".join(f"http://load-{i}.example/p" for i in range(60))
    conn = main.get_db_direct()
    try:
        res = asyncio.run(feeds.run_feed(conn, "openphish", {"min_confidence": 70}, ingest=main._ingest_feed_ioc, record_score=main.record_score, defang=main.defang,
                                         trusted_domains=(), texts={"openphish": text}))
    finally:
        conn.close()
    assert res["ok"] and res["added"] == 60 and seen == {"batch": 1, "single": 0}


def test_a_long_run_commits_in_batches(client, db, monkeypatch):
    import main
    monkeypatch.setattr(feeds, "COMMIT_EVERY", 25)
    commits = []

    class Spy:
        def __init__(self, conn):
            self._c = conn

        def commit(self):
            commits.append(1)
            return self._c.commit()

        def __getattr__(self, n):
            return getattr(self._c, n)
    raw = main.get_db_direct()
    try:
        text = "\n".join(f"http://batch-{i}.example/p" for i in range(60))
        res = asyncio.run(feeds.run_feed(Spy(raw), "openphish", {"min_confidence": 70}, ingest=main._ingest_feed_ioc, record_score=main.record_score, defang=main.defang,
                                         trusted_domains=(), texts={"openphish": text}))
    finally:
        raw.close()
    assert res["ok"] and res["added"] == 60 and len(commits) == 3            # at 25, at 50, and the final one


# ── Downloads and error messages ──────────────────────────────────────────────
def test_a_dropped_connection_is_retried_then_reported_with_its_type(monkeypatch):
    monkeypatch.setattr(feeds, "FETCH_PAUSE", (0, 0))
    tries = []

    async def flaky(feed, key=None):
        tries.append(1)
        if len(tries) < 3:
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
        return "1.2.3.4"
    monkeypatch.setattr(feeds, "_fetch_text_once", flaky)
    assert asyncio.run(feeds.fetch_text(feeds.FEEDS["cins"])) == "1.2.3.4" and len(tries) == 3

    async def always(feed, key=None):
        raise httpx.ReadTimeout("")
    monkeypatch.setattr(feeds, "_fetch_text_once", always)
    with pytest.raises(RuntimeError) as e:
        asyncio.run(feeds.fetch_text(feeds.FEEDS["cins"]))
    assert "ReadTimeout" in str(e.value) and "3 times" in str(e.value)


def test_an_http_error_status_is_not_retried(monkeypatch):
    tries = []

    async def forbidden(feed, key=None):
        tries.append(1)
        raise RuntimeError("HTTP 403")
    monkeypatch.setattr(feeds, "_fetch_text_once", forbidden)
    with pytest.raises(RuntimeError):
        asyncio.run(feeds.fetch_text(feeds.FEEDS["cins"]))
    assert len(tries) == 1


def test_a_timeout_never_becomes_an_empty_error(client):
    import main
    assert main._exc_text(httpx.ReadTimeout("")) == "ReadTimeout"
    assert main._exc_text(httpx.RemoteProtocolError("Server disconnected")) == "RemoteProtocolError: Server disconnected"


def test_abusech_calls_retry_once_and_urlhaus_reports_what_failed(client, monkeypatch):
    import main
    calls = []

    class FakeClient:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, **kw):
            calls.append(url)
            raise httpx.ReadTimeout("")
    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)

    async def nosleep(_):
        return None
    monkeypatch.setattr(main.asyncio, "sleep", nosleep)
    conn = main.get_db_direct()
    try:
        res = asyncio.run(main.run_urlhaus_connector(conn, "k"))
    finally:
        conn.close()
    assert res == {"ok": False, "error": "ReadTimeout"} and len(calls) == 2


def test_the_database_connection_ends_idle_transactions(client):
    import main
    conn = main.get_db_direct()
    try:
        cur = conn.cursor()
        cur.execute("SHOW idle_in_transaction_session_timeout")
        assert cur.fetchone()[0] in ("15min", "900s", "900000ms")
    finally:
        conn.close()
