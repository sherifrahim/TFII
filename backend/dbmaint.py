"""Background database maintenance that must not delay startup.

The observation lookups feed runs depend on need an index on (entity_kind, LOWER(entity_ref)), and the thousands of
repeated "seen again" rows older versions wrote are collapsed to one per indicator and source. Both are too slow to run
inside a schema migration (a deploy's health check gives the app seconds to come up), so they run here, after startup, in
a worker thread: the index is built CONCURRENTLY (writes continue), the collapse works in small committed batches, and the
whole thing is safe to repeat and to run from several workers at once (one takes an advisory lock, the rest skip).
"""
import json
import time
from typing import Callable, Optional

INDEX_NAME = "idx_eo_entity_lower"
INDEX_SQL = f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX_NAME} ON entity_observations (entity_kind, LOWER(entity_ref))"
LOCK_ID = 727002
DONE_KEY = "dbmaint_observations_v1"
BATCH_GROUPS = 2000                  # indicator+source groups collapsed per transaction
PAUSE = 0.2                          # seconds between batches, so the collapse never starves the app

COLLAPSE_SQL = """
WITH g AS (
    SELECT entity_kind AS k, LOWER(entity_ref) AS r, source AS s FROM entity_observations
    WHERE obs_type = 'sighting' AND source_type = 'feed'
    GROUP BY 1, 2, 3 HAVING COUNT(*) > 1 LIMIT %s),
ranked AS (
    SELECT o.id,
           ROW_NUMBER() OVER (PARTITION BY o.entity_kind, LOWER(o.entity_ref), o.source ORDER BY o.ingested_at DESC NULLS LAST, o.id DESC) AS rn,
           SUM(COALESCE((o.data->>'times_seen')::int, 1)) OVER (PARTITION BY o.entity_kind, LOWER(o.entity_ref), o.source) AS n
    FROM entity_observations o JOIN g ON o.entity_kind = g.k AND LOWER(o.entity_ref) = g.r AND o.source = g.s
    WHERE o.obs_type = 'sighting' AND o.source_type = 'feed'),
kept AS (
    UPDATE entity_observations o SET data = jsonb_set(COALESCE(o.data, '{}'::jsonb), '{times_seen}', to_jsonb(r.n))
    FROM ranked r WHERE o.id = r.id AND r.rn = 1 AND r.n > 1 RETURNING o.id),
gone AS (
    DELETE FROM entity_observations WHERE id IN (SELECT id FROM ranked WHERE rn > 1) RETURNING id)
SELECT (SELECT COUNT(*) FROM g), (SELECT COUNT(*) FROM gone), (SELECT COUNT(*) FROM kept)"""


def ensure_index(cur) -> str:
    """Create the lookup index if it is missing; replace one a failed CONCURRENTLY build left invalid."""
    cur.execute("SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = %s", (INDEX_NAME,))
    row = cur.fetchone()
    if row and row[0]:
        return "present"
    if row:
        cur.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}")
    cur.execute(INDEX_SQL)
    return "rebuilt" if row else "created"


def collapse_sightings(cur, batch: int = BATCH_GROUPS, pause: float = PAUSE, max_batches: Optional[int] = None) -> dict:
    """Keep only the newest 'sighting' row per indicator and source, with data.times_seen = how many there were.
    Runs on an autocommit cursor, so every batch commits on its own. Returns {"groups", "deleted", "batches"}."""
    groups = deleted = batches = 0
    while max_batches is None or batches < max_batches:
        cur.execute(COLLAPSE_SQL, (batch,))
        g, gone, _kept = cur.fetchone()
        if not g:
            break
        groups += g
        deleted += gone
        batches += 1
        if not gone:                                     # nothing could be removed: do not loop on the same groups
            break
        if pause:
            time.sleep(pause)
    return {"groups": groups, "deleted": deleted, "batches": batches}


def run(conn_factory: Callable, force: bool = False) -> dict:
    """The whole job. Never raises; returns what it did (also stored under DONE_KEY once it has finished)."""
    conn = None
    try:
        conn = conn_factory()
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_ID,))
        if not cur.fetchone()[0]:
            return {"skipped": "another worker is running it"}
        try:
            t0 = time.time()
            result = {"index": ensure_index(cur)}
            cur.execute("SELECT value FROM system_settings WHERE key = %s", (DONE_KEY,))
            if cur.fetchone() and not force:
                result["collapse"] = "already done"
                return result
            result["collapse"] = collapse_sightings(cur)
            cur.execute("ANALYZE entity_observations")
            result["seconds"] = round(time.time() - t0, 1)
            cur.execute("INSERT INTO system_settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                        (DONE_KEY, json.dumps(result)))
            print(f"[dbmaint] observations: {result}")
            return result
        finally:
            cur.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
    except Exception as e:
        line = str(e).strip().splitlines()[0][:200] if str(e).strip() else type(e).__name__
        print(f"[dbmaint] skipped, will retry next start: {line}")
        return {"error": line}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
