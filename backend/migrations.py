"""
Versioned, additive schema migrations.

main.py still creates the original v1 tables at startup (CREATE TABLE IF NOT
EXISTS). Everything added since lives here, in numbered migrations recorded in
`schema_migrations`, so what has been applied to a given database is knowable
and a new migration is a new list entry rather than another ad-hoc ALTER.

Rules every migration follows:
  * additive and idempotent (IF NOT EXISTS) — nothing is dropped or rewritten,
    so rolling the code back leaves a working database;
  * a statement marked optional (extensions and EVERY index) may fail on a
    restricted database without blocking the migration. Indexes are optional
    because the app's database role does not always own the older v1 tables
    ("must be owner of table cve_findings" on production stopped migration 1
    and therefore migration 2); an index is an optimisation, a column is not;
  * a required statement that fails stops that migration, is retried on the next
    start, and never stops the application from booting.
"""
import time

# (sql, optional)
def R(sql): return (sql, False)
def O(sql): return (sql, True)


# Expression used for "which host does this URL point at". Shared by the URL →
# domain relationship queries and the index that serves them, so the planner can
# use the index (the expression text must match exactly).
URL_HOST_SQL = ("LOWER(substring(value from '^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/@?#]*@)?"
                "(\\[[0-9a-fA-F:.]+\\]|[^/:?#]+)'))")


MIGRATIONS = [
    (1, "phase1_workspace_and_indexes", [
        # Created lazily by several v1 endpoints; a fresh install needs it up
        # front for connector status, backups and notification settings.
        R("CREATE TABLE IF NOT EXISTS system_settings (key VARCHAR PRIMARY KEY, value TEXT)"),
        R("ALTER TABLE iocs ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP"),
        R("""CREATE TABLE IF NOT EXISTS ioc_provenance (
            id SERIAL PRIMARY KEY, ioc_id VARCHAR(100) NOT NULL, source_type VARCHAR(40) NOT NULL,
            source_ref TEXT, confidence_label VARCHAR(60), observed_at TIMESTAMP DEFAULT NOW(),
            context TEXT, created_by VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())"""),
        R("""CREATE TABLE IF NOT EXISTS investigations (
            id VARCHAR(100) PRIMARY KEY, seq SERIAL, name VARCHAR(200) NOT NULL,
            description TEXT DEFAULT '', status VARCHAR(20) DEFAULT 'open',
            severity VARCHAR(20) DEFAULT 'medium', tags TEXT[] DEFAULT '{}',
            owner_id VARCHAR(100), owner_name VARCHAR(50),
            created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())"""),
        R("""CREATE TABLE IF NOT EXISTS investigation_items (
            id SERIAL PRIMARY KEY, investigation_id VARCHAR(100) NOT NULL, item_type VARCHAR(30) NOT NULL,
            ref_id TEXT, value TEXT, label TEXT, data JSONB DEFAULT '{}', created_by VARCHAR(50),
            created_at TIMESTAMP DEFAULT NOW())"""),
        R("""CREATE TABLE IF NOT EXISTS investigation_events (
            id SERIAL PRIMARY KEY, investigation_id VARCHAR(100) NOT NULL, event_type VARCHAR(30) NOT NULL,
            title TEXT NOT NULL, body TEXT, ref_type VARCHAR(30), ref_id TEXT, created_by VARCHAR(50),
            occurred_at TIMESTAMP DEFAULT NOW(), created_at TIMESTAMP DEFAULT NOW())"""),
        R("ALTER TABLE admin_notes ADD COLUMN IF NOT EXISTS investigation_id VARCHAR(100)"),
        O("CREATE INDEX IF NOT EXISTS idx_iocs_created_at ON iocs (created_at DESC)"),
        O("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs (type)"),
        O("CREATE INDEX IF NOT EXISTS idx_iocs_campaign ON iocs (campaign_id)"),
        O("CREATE INDEX IF NOT EXISTS idx_iocs_value_hash ON iocs USING hash (value)"),
        O("CREATE INDEX IF NOT EXISTS idx_cvef_asset ON cve_findings (asset_id)"),
        O("CREATE INDEX IF NOT EXISTS idx_cvef_cve ON cve_findings (cve_id)"),
        O("CREATE INDEX IF NOT EXISTS idx_rel_source ON ioc_relationships (source_id)"),
        O("CREATE INDEX IF NOT EXISTS idx_rel_target ON ioc_relationships (target_id)"),
        O("CREATE INDEX IF NOT EXISTS idx_invitems_inv ON investigation_items (investigation_id)"),
        O("CREATE INDEX IF NOT EXISTS idx_invitems_ref ON investigation_items (item_type, ref_id)"),
        O("CREATE INDEX IF NOT EXISTS idx_invevents_inv ON investigation_events (investigation_id)"),
        O("CREATE INDEX IF NOT EXISTS idx_prov_ioc ON ioc_provenance (ioc_id)"),
    ]),

    (2, "phase2_intelligence_core", [
        # ── Triage status. NULL = untriaged (shown as "active"). The lifecycle
        #    states (expired, false positive) stay derived from valid_until and
        #    false_positive, so existing data and v1 endpoints keep their meaning.
        R("ALTER TABLE iocs ADD COLUMN IF NOT EXISTS analyst_status VARCHAR(20)"),

        # ── Relationship engine. Polymorphic edges between entities; an entity is
        #    (kind, ref). Indicators are keyed by their normalised VALUE, not their
        #    row id, so an edge to a not-yet-tracked observable stays valid when it
        #    is later added as an IOC. Every edge carries its own provenance.
        R("""CREATE TABLE IF NOT EXISTS entity_relationships (
            id SERIAL PRIMARY KEY,
            src_kind VARCHAR(20) NOT NULL, src_ref TEXT NOT NULL,
            rel_type VARCHAR(40) NOT NULL,
            dst_kind VARCHAR(20) NOT NULL, dst_ref TEXT NOT NULL,
            confidence INTEGER,
            source VARCHAR(100) NOT NULL DEFAULT 'analyst',
            source_type VARCHAR(30) NOT NULL DEFAULT 'analyst',
            source_ref TEXT,
            evidence JSONB DEFAULT '{}',
            observed_at TIMESTAMP,
            created_by VARCHAR(100),
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE (src_kind, src_ref, rel_type, dst_kind, dst_ref, source))"""),
        O("CREATE INDEX IF NOT EXISTS idx_er_src ON entity_relationships (src_kind, src_ref)"),
        O("CREATE INDEX IF NOT EXISTS idx_er_dst ON entity_relationships (dst_kind, dst_ref)"),

        # ── Observations / provenance: one row per thing a source told us (or an
        #    analyst did) about an entity. observed_at is when the SOURCE says it
        #    happened (NULL if unknown — never guessed); ingested_at is when TFII
        #    recorded it.
        R("""CREATE TABLE IF NOT EXISTS entity_observations (
            id SERIAL PRIMARY KEY,
            entity_kind VARCHAR(20) NOT NULL, entity_ref TEXT NOT NULL,
            obs_type VARCHAR(30) NOT NULL,
            source VARCHAR(100) NOT NULL,
            source_type VARCHAR(30) NOT NULL,
            source_ref TEXT,
            observed_at TIMESTAMP,
            ingested_at TIMESTAMP DEFAULT NOW(),
            confidence INTEGER,
            actor VARCHAR(100),
            summary TEXT,
            data JSONB DEFAULT '{}')"""),
        O("CREATE INDEX IF NOT EXISTS idx_eo_entity ON entity_observations (entity_kind, entity_ref)"),
        O("CREATE INDEX IF NOT EXISTS idx_eo_ingested ON entity_observations (ingested_at DESC)"),

        # ── Workspace: why is this entity part of the investigation?
        R("ALTER TABLE investigation_items ADD COLUMN IF NOT EXISTS reason TEXT"),

        # ── MITRE ATT&CK group profiles. The upstream dataset is tens of MB; the
        #    server has < 1GB of RAM, so results are cached per group.
        R("""CREATE TABLE IF NOT EXISTS mitre_cache (
            name_key VARCHAR(200) PRIMARY KEY, payload JSONB NOT NULL,
            fetched_at TIMESTAMP DEFAULT NOW())"""),

        # ── Lookup indexes for the entity resolver and search.
        O("CREATE INDEX IF NOT EXISTS idx_iocs_lower_value ON iocs (LOWER(value))"),
        O("CREATE INDEX IF NOT EXISTS idx_iocs_analyst_status ON iocs (analyst_status) WHERE analyst_status IS NOT NULL"),
        O("CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs (last_seen DESC)"),
        O("CREATE INDEX IF NOT EXISTS idx_iocs_family ON iocs (LOWER(enrichment->>'malware_family')) WHERE enrichment ? 'malware_family'"),
        O("CREATE INDEX IF NOT EXISTS idx_campaigns_actor ON campaigns (LOWER(threat_actor))"),
        O("CREATE INDEX IF NOT EXISTS idx_invitems_value ON investigation_items (LOWER(value))"),
        O(f"CREATE INDEX IF NOT EXISTS idx_iocs_url_host ON iocs (({URL_HOST_SQL})) WHERE type = 'URL'"),
        # Trigram indexes make substring search (ILIKE '%…%') index-assisted once
        # the table is large. pg_trgm is a trusted extension on PostgreSQL 13+.
        O("CREATE EXTENSION IF NOT EXISTS pg_trgm"),
        O("CREATE INDEX IF NOT EXISTS idx_iocs_value_trgm ON iocs USING gin (value gin_trgm_ops)"),
        O("CREATE INDEX IF NOT EXISTS idx_cvef_title_trgm ON cve_findings USING gin (title gin_trgm_ops)"),
    ]),

    (3, "dns_intel_cache", [
        # NSLookup.io allows 30 requests a minute per IP, shared by every user, so answers are cached per domain.
        R("""CREATE TABLE IF NOT EXISTS dns_intel_cache (
            domain VARCHAR(253) PRIMARY KEY, data JSONB NOT NULL, fetched_at TIMESTAMP DEFAULT NOW())"""),
    ]),
    (4, "lookup_detail_cache", [
        # What each provider said about an indicator a user looked up, kept per user (the answers come from that user's
        # keys and quota) so the Detailed report can be opened without asking the providers again.
        R("""CREATE TABLE IF NOT EXISTS lookup_detail_cache (
            user_id VARCHAR(100) NOT NULL, value TEXT NOT NULL, ioc_type VARCHAR(20) NOT NULL, data JSONB NOT NULL,
            fetched_at TIMESTAMP DEFAULT NOW(), PRIMARY KEY (user_id, value))"""),
        O("CREATE INDEX IF NOT EXISTS idx_lookup_detail_fetched ON lookup_detail_cache (fetched_at)"),
    ]),
]


def run_migrations(conn_factory, migrations=None):
    """Apply pending migrations. Never raises: a failure is logged and retried next boot."""
    migrations = migrations if migrations is not None else MIGRATIONS
    applied = []
    conn = conn_factory()
    try:
        conn.autocommit = True
        cur = conn.cursor()
        # One runner at a time if several workers start together.
        cur.execute("SELECT pg_advisory_lock(727001)")
        cur.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMP DEFAULT NOW())""")
        cur.execute("SELECT version FROM schema_migrations")
        done = {r[0] for r in cur.fetchall()}
        for version, name, statements in migrations:
            if version in done:
                continue
            ok = True
            t0 = time.time()
            for sql, optional in statements:
                try:
                    cur.execute(sql)
                except Exception as e:
                    line = str(e).strip().splitlines()[0][:200] if str(e).strip() else type(e).__name__
                    if optional:
                        print(f"[migrations] {version} optional step skipped: {line}")
                    else:
                        print(f"[migrations] {version} {name} FAILED: {line}")
                        ok = False
                        break
            if ok:
                cur.execute("INSERT INTO schema_migrations (version, name) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                            (version, name))
                applied.append(version)
                print(f"[migrations] applied {version} {name} in {time.time() - t0:.2f}s")
            else:
                break   # later migrations may depend on this one
        cur.execute("SELECT pg_advisory_unlock(727001)")
    except Exception as e:
        print(f"[migrations] runner error: {e}")
    finally:
        conn.close()
    return applied
