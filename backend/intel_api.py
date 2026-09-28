"""
TFII intelligence API (v2).

Read-optimised, paginated endpoints that back the redesigned UI: the analyst
IOC table, entity pages, relationship graphs, unified search, the Command
Center, software/vulnerability intelligence, investigations and grouped
notifications.

Nothing here replaces a v1 route. The original endpoints in main.py keep their
contracts (older clients, the TAXII consumers and scripts depend on them); this
module only adds `/v2/*` routes next to them and a few additive schema
migrations. Dependencies (DB handle, auth guards, IOC helpers) are injected by
main.py via `register()` so this module never imports main and there is no
circular import.
"""
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import psycopg2
import psycopg2.extras
from fastapi import Depends, HTTPException
from pydantic import BaseModel


# ── Schema ────────────────────────────────────────────────────────────────────
# Every statement is additive (IF NOT EXISTS) and runs in autocommit, so one
# failure cannot roll back the others and existing data is never touched.
SCHEMA = [
    # Created lazily by several v1 endpoints; a fresh install needs it up front
    # for connector status, backups and notification settings.
    "CREATE TABLE IF NOT EXISTS system_settings (key VARCHAR PRIMARY KEY, value TEXT)",
    "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP",
    """CREATE TABLE IF NOT EXISTS ioc_provenance (
        id SERIAL PRIMARY KEY,
        ioc_id VARCHAR(100) NOT NULL,
        source_type VARCHAR(40) NOT NULL,
        source_ref TEXT,
        confidence_label VARCHAR(60),
        observed_at TIMESTAMP DEFAULT NOW(),
        context TEXT,
        created_by VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS investigations (
        id VARCHAR(100) PRIMARY KEY,
        seq SERIAL,
        name VARCHAR(200) NOT NULL,
        description TEXT DEFAULT '',
        status VARCHAR(20) DEFAULT 'open',
        severity VARCHAR(20) DEFAULT 'medium',
        tags TEXT[] DEFAULT '{}',
        owner_id VARCHAR(100),
        owner_name VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS investigation_items (
        id SERIAL PRIMARY KEY,
        investigation_id VARCHAR(100) NOT NULL,
        item_type VARCHAR(30) NOT NULL,
        ref_id TEXT,
        value TEXT,
        label TEXT,
        data JSONB DEFAULT '{}',
        created_by VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS investigation_events (
        id SERIAL PRIMARY KEY,
        investigation_id VARCHAR(100) NOT NULL,
        event_type VARCHAR(30) NOT NULL,
        title TEXT NOT NULL,
        body TEXT,
        ref_type VARCHAR(30),
        ref_id TEXT,
        created_by VARCHAR(50),
        occurred_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW())""",
    "ALTER TABLE admin_notes ADD COLUMN IF NOT EXISTS investigation_id VARCHAR(100)",
    # Indexes: the IOC table is in the thousands and every list/search/sort
    # used to be a sequential scan. Hash index on value because URLs can exceed
    # the btree row limit.
    "CREATE INDEX IF NOT EXISTS idx_iocs_created_at ON iocs (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs (type)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_campaign ON iocs (campaign_id)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_value_hash ON iocs USING hash (value)",
    "CREATE INDEX IF NOT EXISTS idx_cvef_asset ON cve_findings (asset_id)",
    "CREATE INDEX IF NOT EXISTS idx_cvef_cve ON cve_findings (cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_rel_source ON ioc_relationships (source_id)",
    "CREATE INDEX IF NOT EXISTS idx_rel_target ON ioc_relationships (target_id)",
    "CREATE INDEX IF NOT EXISTS idx_invitems_inv ON investigation_items (investigation_id)",
    "CREATE INDEX IF NOT EXISTS idx_invitems_ref ON investigation_items (item_type, ref_id)",
    "CREATE INDEX IF NOT EXISTS idx_invevents_inv ON investigation_events (investigation_id)",
    "CREATE INDEX IF NOT EXISTS idx_prov_ioc ON ioc_provenance (ioc_id)",
]


def ensure_schema(conn_factory):
    conn = conn_factory()
    try:
        conn.autocommit = True
        cur = conn.cursor()
        for sql in SCHEMA:
            try:
                cur.execute(sql)
            except Exception as e:  # never block startup on a migration
                print(f"[intel_api] schema step skipped: {str(e).splitlines()[0][:160]}")
    finally:
        conn.close()


# ── Shared SQL fragments ──────────────────────────────────────────────────────
# Where an indicator came from. Connectors write enrichment.source; bulk lookup
# only leaves a tag; everything else was entered by an analyst.
SOURCE_SQL = """COALESCE(NULLIF(i.enrichment->>'source',''),
    CASE WHEN 'bulk-lookup' = ANY(i.tags) THEN 'Bulk Lookup' ELSE 'Manual' END)"""

STATUS_SQL = """CASE WHEN i.false_positive THEN 'false_positive'
    WHEN i.valid_until IS NOT NULL AND i.valid_until <= NOW() THEN 'expired'
    ELSE 'active' END"""

ACTIVE_SQL = """(i.valid_until IS NULL OR i.valid_until > NOW())
    AND (i.false_positive IS NULL OR i.false_positive = FALSE)"""

SEV_SQL = """CASE
    WHEN UPPER(COALESCE(cf.cvss_severity,'')) IN ('CRITICAL','HIGH','MEDIUM','LOW') THEN UPPER(cf.cvss_severity)
    WHEN cf.cvss_score >= 9 THEN 'CRITICAL' WHEN cf.cvss_score >= 7 THEN 'HIGH'
    WHEN cf.cvss_score >= 4 THEN 'MEDIUM' WHEN cf.cvss_score > 0 THEN 'LOW'
    ELSE 'NONE' END"""

UNPATCHED_SQL = "(cf.patch_available = FALSE OR cf.patch_available IS NULL)"

IOC_SORTS = {
    "created": "i.created_at", "last_seen": "COALESCE(i.last_seen, i.created_at)",
    "confidence": "i.confidence", "type": "i.type", "value": "i.value",
    "tlp": "i.tlp", "source": SOURCE_SQL,
}

TYPE_GROUPS = {
    "ip": ("IPv4", "IPv6"), "domain": ("Domain",), "url": ("URL",),
    "hash": ("MD5", "SHA1", "SHA256"), "email": ("Email",),
}

# Tags every connector row carries; useless for "related by tag" pivots.
GENERIC_TAGS = {"connector", "threatfox", "malwarebazaar", "urlhaus", "bulk-lookup",
                "malicious", "suspicious", "clean", "unknown", "malware-hash", "malware-url"}


def _dict_cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def _safe(conn, fn, default):
    """Run an optional query; a missing table or column degrades to a default."""
    try:
        return fn()
    except Exception as e:
        conn.rollback()
        print(f"[intel_api] optional query failed: {str(e).splitlines()[0][:160]}")
        return default


def _inv_key(row):
    return f"INV-{int(row.get('seq') or 0):04d}"


# ── Models ────────────────────────────────────────────────────────────────────
class IocPatch(BaseModel):
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    tlp: Optional[str] = None
    confidence: Optional[int] = None
    extend_days: Optional[int] = None


class BulkAction(BaseModel):
    ids: List[str]
    action: str                      # assign_campaign | add_tag | mark_fp | unmark_fp | add_to_investigation
    campaign_id: Optional[str] = None
    tag: Optional[str] = None
    investigation_id: Optional[str] = None
    reason: Optional[str] = ""


class CampaignPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    threat_actor: Optional[str] = None
    industry_targets: Optional[List[str]] = None


class InvestigationIn(BaseModel):
    name: str
    description: Optional[str] = ""
    severity: Optional[str] = "medium"
    status: Optional[str] = "open"
    tags: Optional[List[str]] = []


class InvestigationPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None


class InvItemIn(BaseModel):
    item_type: str
    ref_id: Optional[str] = None
    value: Optional[str] = None
    label: Optional[str] = None
    data: Optional[dict] = None


class InvEventIn(BaseModel):
    title: str
    body: Optional[str] = ""
    occurred_at: Optional[str] = None


class InvNoteIn(BaseModel):
    title: Optional[str] = ""
    content: Optional[str] = ""
    tags: Optional[List[str]] = []
    pinned: Optional[bool] = False


INV_ITEM_TYPES = {"ioc", "cve", "campaign", "actor", "asset", "observable",
                  "query", "detection", "screenshot", "artifact", "malware"}
INV_STATUSES = {"open", "active", "monitoring", "closed"}
SEVERITIES = {"critical", "high", "medium", "low"}


def register(app, d):
    """Attach the v2 routes. `d` carries the dependencies owned by main.py."""
    get_db = d.get_db
    full = d.require_full_access
    admin = d.require_admin
    current = d.get_current_user

    @app.on_event("startup")
    async def _intel_schema():
        ensure_schema(d.get_db_direct)

    # ══════════════════════════════════════════════════════════════════════
    # IOC INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════════
    def _ioc_where(q, type_, tlp, source, tag, campaign_id, min_conf, status,
                   since_days, analyst, has_campaign):
        where, params = ["1=1"], []
        if q:
            norm = d.refang(q.strip())
            where.append("""(i.value ILIKE %s OR i.value_defanged ILIKE %s OR i.description ILIKE %s
                             OR %s = ANY(i.tags) OR i.enrichment->>'malware_family' ILIKE %s)""")
            params += [f"%{norm}%", f"%{q.strip()}%", f"%{q.strip()}%", q.strip().lower(), f"%{q.strip()}%"]
        if type_:
            types = []
            for t in type_.split(","):
                types.extend(TYPE_GROUPS.get(t.lower(), (t,)))
            where.append("i.type = ANY(%s)"); params.append(types)
        if tlp:
            where.append("i.tlp = ANY(%s)"); params.append(tlp.upper().split(","))
        if source:
            where.append(f"{SOURCE_SQL} = ANY(%s)"); params.append(source.split(","))
        if tag:
            where.append("%s = ANY(i.tags)"); params.append(tag)
        if campaign_id:
            where.append("i.campaign_id = %s"); params.append(campaign_id)
        if has_campaign:
            where.append("i.campaign_id IS NOT NULL")
        if min_conf:
            where.append("i.confidence >= %s"); params.append(min_conf)
        if analyst:
            where.append("u.username = %s"); params.append(analyst)
        if since_days:
            where.append("i.created_at >= NOW() - (%s || ' days')::interval"); params.append(str(int(since_days)))
        status = status or "active"
        if status != "all":
            where.append(f"{STATUS_SQL} = ANY(%s)"); params.append(status.split(","))
        return where, params

    @app.get("/v2/iocs")
    def v2_list_iocs(q: str = "", type: str = "", tlp: str = "", source: str = "", tag: str = "",
                     campaign_id: str = "", min_conf: int = 0, status: str = "active",
                     since_days: int = 0, analyst: str = "", has_campaign: bool = False,
                     sort: str = "created", dir: str = "desc", limit: int = 50, offset: int = 0,
                     facets: bool = True, user=Depends(full), conn=Depends(get_db)):
        limit = max(1, min(limit, 500)); offset = max(0, offset)
        where, params = _ioc_where(q, type, tlp, source, tag, campaign_id, min_conf, status,
                                   since_days, analyst, has_campaign)
        order = IOC_SORTS.get(sort, "i.created_at")
        direction = "ASC" if dir.lower() == "asc" else "DESC"
        base = f"""FROM iocs i LEFT JOIN users u ON i.created_by = u.id
                   LEFT JOIN campaigns c ON i.campaign_id = c.id WHERE {' AND '.join(where)}"""
        cur = _dict_cur(conn)
        cur.execute(f"""SELECT i.id, i.type, i.value, i.value_defanged, i.industry, i.tlp, i.confidence,
                i.description, i.tags, i.created_by, i.valid_until, i.false_positive, i.fp_reason,
                i.mitre_techniques, i.campaign_id, i.created_at,
                COALESCE(i.last_seen, i.created_at) AS last_seen,
                u.username AS author, c.name AS campaign_name, c.threat_actor,
                {SOURCE_SQL} AS source, {STATUS_SQL} AS status,
                i.enrichment->>'malware_family' AS malware_family,
                COALESCE(i.enrichment->'abuseipdb'->>'country', i.enrichment->'virustotal'->>'country') AS country
            {base} ORDER BY {order} {direction} NULLS LAST, i.id LIMIT %s OFFSET %s""",
            params + [limit, offset])
        items = cur.fetchall()
        cur.execute(f"SELECT COUNT(*) AS n {base}", params)
        total = cur.fetchone()["n"]
        out = {"items": items, "total": total, "limit": limit, "offset": offset}
        if facets:
            fcur = _dict_cur(conn)
            fcur.execute(f"SELECT i.type AS k, COUNT(*) AS n {base} GROUP BY i.type ORDER BY n DESC", params)
            ftypes = fcur.fetchall()
            fcur.execute(f"SELECT {SOURCE_SQL} AS k, COUNT(*) AS n {base} GROUP BY 1 ORDER BY n DESC LIMIT 12", params)
            fsources = fcur.fetchall()
            fcur.execute(f"SELECT i.tlp AS k, COUNT(*) AS n {base} GROUP BY i.tlp ORDER BY n DESC", params)
            ftlp = fcur.fetchall()
            out["facets"] = {"types": ftypes, "sources": fsources, "tlp": ftlp}
        return out

    @app.get("/v2/iocs/facets")
    def v2_ioc_facets(user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute(f"SELECT {SOURCE_SQL} AS k, COUNT(*) AS n FROM iocs i GROUP BY 1 ORDER BY n DESC LIMIT 30")
        sources = cur.fetchall()
        cur.execute("""SELECT t AS k, COUNT(*) AS n FROM iocs i, UNNEST(i.tags) t
                       GROUP BY t ORDER BY n DESC LIMIT 40""")
        tags = cur.fetchall()
        cur.execute("""SELECT u.username AS k, COUNT(*) AS n FROM iocs i JOIN users u ON i.created_by=u.id
                       GROUP BY u.username ORDER BY n DESC LIMIT 20""")
        analysts = cur.fetchall()
        return {"sources": sources, "tags": tags, "analysts": analysts}

    @app.patch("/v2/iocs/{ioc_id}")
    def v2_patch_ioc(ioc_id: str, body: IocPatch, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute("SELECT id, created_by, value, type, valid_until FROM iocs WHERE id=%s", (ioc_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "IOC not found")
        if user["role"] != "admin" and row["created_by"] != user["id"]:
            raise HTTPException(403, "You can only edit your own IOCs")
        sets, params = [], []
        if body.description is not None: sets.append("description=%s"); params.append(body.description)
        if body.tags is not None:
            sets.append("tags=%s"); params.append([t.strip() for t in body.tags if t.strip()][:40])
        if body.tlp is not None:
            if body.tlp.upper() not in ("WHITE", "GREEN", "AMBER", "RED", "CLEAR"):
                raise HTTPException(400, "Invalid TLP")
            sets.append("tlp=%s"); params.append(body.tlp.upper())
        if body.confidence is not None:
            sets.append("confidence=%s"); params.append(max(0, min(100, body.confidence)))
        if body.extend_days:
            sets.append("valid_until = GREATEST(COALESCE(valid_until, NOW()), NOW()) + (%s || ' days')::interval")
            params.append(str(int(body.extend_days)))
        if not sets:
            return {"status": "unchanged"}
        cur.execute(f"UPDATE iocs SET {', '.join(sets)} WHERE id=%s", params + [ioc_id])
        d.audit(conn, "EDIT", ioc_id, row["value"], row["type"], user)
        conn.commit()
        return {"status": "updated"}

    @app.post("/v2/iocs/bulk-action")
    def v2_bulk_action(body: BulkAction, user=Depends(full), conn=Depends(get_db)):
        ids = list(dict.fromkeys(body.ids))[:1000]
        if not ids:
            raise HTTPException(400, "No IOCs selected")
        cur = _dict_cur(conn)
        is_admin = user["role"] == "admin"
        if body.action == "assign_campaign":
            cur.execute("UPDATE iocs SET campaign_id=%s WHERE id = ANY(%s)", (body.campaign_id or None, ids))
        elif body.action == "add_tag":
            tag = (body.tag or "").strip().lower()
            if not tag:
                raise HTTPException(400, "Tag required")
            cur.execute("""UPDATE iocs SET tags = array_append(COALESCE(tags,'{}'), %s)
                           WHERE id = ANY(%s) AND NOT (%s = ANY(COALESCE(tags,'{}')))""", (tag, ids, tag))
        elif body.action in ("mark_fp", "unmark_fp"):
            fp = body.action == "mark_fp"
            if is_admin:
                cur.execute("UPDATE iocs SET false_positive=%s, fp_reason=%s WHERE id = ANY(%s)",
                            (fp, body.reason or "", ids))
            else:
                cur.execute("""UPDATE iocs SET false_positive=%s, fp_reason=%s
                               WHERE id = ANY(%s) AND created_by=%s""", (fp, body.reason or "", ids, user["id"]))
        elif body.action == "add_to_investigation":
            if not body.investigation_id:
                raise HTTPException(400, "investigation_id required")
            _get_investigation(conn, body.investigation_id)
            cur.execute("SELECT id, value, type FROM iocs WHERE id = ANY(%s)", (ids,))
            added = 0
            for r in cur.fetchall():
                if _add_item(conn, body.investigation_id, "ioc", r["id"], r["value"], r["type"], {}, user):
                    added += 1
            if added:
                _event(conn, body.investigation_id, "ioc_added",
                       f"{added} IOC{'s' if added != 1 else ''} added", None, None, None, user)
            conn.commit()
            return {"status": "ok", "affected": added}
        else:
            raise HTTPException(400, "Unknown action")
        affected = cur.rowcount
        conn.commit()
        return {"status": "ok", "affected": affected}

    # ══════════════════════════════════════════════════════════════════════
    # ENTITY INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════════
    @app.get("/v2/entities/resolve")
    def v2_resolve(value: str, user=Depends(full), conn=Depends(get_db)):
        norm = d.refang(value.strip())
        cur = _dict_cur(conn)
        cur.execute("SELECT id, type, value FROM iocs WHERE value = %s ORDER BY created_at LIMIT 1", (norm,))
        row = cur.fetchone()
        return {"found": bool(row), "id": row["id"] if row else None,
                "value": norm, "type": row["type"] if row else d.detect_type(norm)}

    @app.get("/v2/entities/ioc/{ioc_id}")
    def v2_entity_ioc(ioc_id: str, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute(f"""SELECT i.*, u.username AS author, c.name AS campaign_name, c.threat_actor,
                c.description AS campaign_description, {SOURCE_SQL} AS source, {STATUS_SQL} AS status,
                COALESCE(i.last_seen, i.created_at) AS last_seen_at
            FROM iocs i LEFT JOIN users u ON i.created_by=u.id LEFT JOIN campaigns c ON i.campaign_id=c.id
            WHERE i.id=%s""", (ioc_id,))
        ioc = cur.fetchone()
        if not ioc:
            raise HTTPException(404, "IOC not found")
        enr = ioc.get("enrichment") or {}

        cur.execute("""SELECT r.id, r.relationship_type, r.note, r.created_at, r.source_id, r.target_id,
                s.value AS source_value, s.type AS source_type, s.confidence AS source_confidence,
                t.value AS target_value, t.type AS target_type, t.confidence AS target_confidence
            FROM ioc_relationships r JOIN iocs s ON r.source_id=s.id JOIN iocs t ON r.target_id=t.id
            WHERE r.source_id=%s OR r.target_id=%s ORDER BY r.created_at DESC""", (ioc_id, ioc_id))
        relationships = cur.fetchall()

        cur.execute("SELECT * FROM ioc_notes WHERE ioc_id=%s ORDER BY created_at DESC", (ioc_id,))
        notes = cur.fetchall()
        cur.execute("SELECT * FROM ioc_score_history WHERE ioc_id=%s ORDER BY created_at DESC LIMIT 50", (ioc_id,))
        history = cur.fetchall()
        cur.execute(f"""SELECT DISTINCT ON (cf.cve_id) cf.cve_id, cf.title, cf.cvss_score, {SEV_SQL} AS severity,
                cf.kev_listed, cf.patch_available, a.name AS asset_name
            FROM cve_ioc_links l JOIN cve_findings cf ON cf.cve_id=l.cve_id
            LEFT JOIN assets a ON a.id=cf.asset_id WHERE l.ioc_id=%s""", (ioc_id,))
        cves = cur.fetchall()
        provenance = _safe(conn, lambda: (cur.execute(
            "SELECT * FROM ioc_provenance WHERE ioc_id=%s ORDER BY observed_at DESC", (ioc_id,)), cur.fetchall())[1], [])
        investigations = _safe(conn, lambda: (cur.execute(
            """SELECT inv.id, inv.seq, inv.name, inv.status, inv.severity, it.created_at AS linked_at
               FROM investigation_items it JOIN investigations inv ON inv.id=it.investigation_id
               WHERE it.item_type='ioc' AND it.ref_id=%s ORDER BY it.created_at DESC""", (ioc_id,)), cur.fetchall())[1], [])
        for inv in investigations:
            inv["key"] = _inv_key(inv)

        related = {"campaign": [], "malware": [], "subnet": [], "tags": []}
        if ioc.get("campaign_id"):
            cur.execute("""SELECT id, type, value, confidence, created_at FROM iocs
                           WHERE campaign_id=%s AND id<>%s ORDER BY created_at DESC LIMIT 25""",
                        (ioc["campaign_id"], ioc_id))
            related["campaign"] = cur.fetchall()
        family = enr.get("malware_family") if isinstance(enr, dict) else None
        if family and family not in ("unknown", ""):
            cur.execute("""SELECT id, type, value, confidence, created_at FROM iocs
                           WHERE enrichment->>'malware_family' = %s AND id<>%s
                           ORDER BY created_at DESC LIMIT 25""", (family, ioc_id))
            related["malware"] = cur.fetchall()
        if ioc["type"] == "IPv4" and ioc["value"].count(".") == 3:
            subnet = ".".join(ioc["value"].split(".")[:3]) + ".%"
            cur.execute("""SELECT id, type, value, confidence, created_at FROM iocs
                           WHERE type='IPv4' AND value LIKE %s AND id<>%s ORDER BY created_at DESC LIMIT 25""",
                        (subnet, ioc_id))
            related["subnet"] = cur.fetchall()
        specific = [t for t in (ioc.get("tags") or []) if t and t.lower() not in GENERIC_TAGS][:6]
        if specific:
            cur.execute("""SELECT id, type, value, confidence, created_at, tags FROM iocs
                           WHERE tags && %s AND id<>%s ORDER BY created_at DESC LIMIT 25""",
                        (specific, ioc_id))
            related["tags"] = cur.fetchall()

        geo = {}
        if isinstance(enr, dict):
            ab, vt = enr.get("abuseipdb") or {}, enr.get("virustotal") or {}
            geo = {k: v for k, v in {
                "country": ab.get("country") or vt.get("country"),
                "isp": ab.get("isp"), "asn": vt.get("asn"), "as_owner": vt.get("as_owner"),
                "usage_type": ab.get("usage_type"), "domain": ab.get("domain"),
            }.items() if v}

        return {"ioc": ioc, "relationships": relationships, "notes": notes, "score_history": history,
                "cves": cves, "provenance": provenance, "investigations": investigations,
                "related": related, "geo": geo, "malware_family": family}

    # ══════════════════════════════════════════════════════════════════════
    # RELATIONSHIP GRAPH
    # ══════════════════════════════════════════════════════════════════════
    class _G:
        def __init__(self, cap=260):
            self.nodes, self.edges, self.cap, self.seen_e = {}, [], cap, set()

        def node(self, nid, kind, label, **kw):
            if nid not in self.nodes:
                if len(self.nodes) >= self.cap:
                    return False
                self.nodes[nid] = {"id": nid, "kind": kind, "label": label, **kw}
            return True

        def edge(self, a, b, t):
            k = (a, b, t)
            if a in self.nodes and b in self.nodes and k not in self.seen_e:
                self.seen_e.add(k); self.edges.append({"source": a, "target": b, "type": t})

    def _ioc_node(g, r, **kw):
        return g.node(f"ioc:{r['id']}", "ioc", r.get("value_defanged") or r["value"], ioc_type=r["type"],
                      ref=r["id"], confidence=r.get("confidence"), **kw)

    def _expand_ioc(conn, g, ioc_id, depth, frontier):
        cur = _dict_cur(conn)
        cur.execute("""SELECT i.id, i.type, i.value, i.value_defanged, i.confidence, i.campaign_id,
                i.enrichment->>'malware_family' AS family, c.name AS campaign_name, c.threat_actor
            FROM iocs i LEFT JOIN campaigns c ON c.id=i.campaign_id WHERE i.id=%s""", (ioc_id,))
        r = cur.fetchone()
        if not r:
            return
        nid = f"ioc:{r['id']}"
        _ioc_node(g, r)
        if r["campaign_id"]:
            cid = f"campaign:{r['campaign_id']}"
            if g.node(cid, "campaign", r["campaign_name"] or "campaign", ref=r["campaign_id"]):
                g.edge(nid, cid, "part_of")
                if r["threat_actor"]:
                    aid = f"actor:{r['threat_actor']}"
                    g.node(aid, "actor", r["threat_actor"], ref=r["threat_actor"])
                    g.edge(cid, aid, "attributed_to")
        if r["family"] and r["family"] != "unknown":
            mid = f"malware:{r['family']}"
            g.node(mid, "malware", r["family"], ref=r["family"])
            g.edge(nid, mid, "indicates")
        cur.execute("""SELECT r.relationship_type, r.source_id, r.target_id,
                s.id sid, s.type stype, s.value svalue, s.value_defanged sdef, s.confidence sconf,
                t.id tid, t.type ttype, t.value tvalue, t.value_defanged tdef, t.confidence tconf
            FROM ioc_relationships r JOIN iocs s ON r.source_id=s.id JOIN iocs t ON r.target_id=t.id
            WHERE r.source_id=%s OR r.target_id=%s LIMIT 80""", (ioc_id, ioc_id))
        for rel in cur.fetchall():
            for p in ("s", "t"):
                _ioc_node(g, {"id": rel[p + "id"], "type": rel[p + "type"], "value": rel[p + "value"],
                              "value_defanged": rel[p + "def"], "confidence": rel[p + "conf"]})
            g.edge(f"ioc:{rel['source_id']}", f"ioc:{rel['target_id']}", rel["relationship_type"])
            other = rel["target_id"] if rel["source_id"] == ioc_id else rel["source_id"]
            frontier.append(other)
        cur.execute("""SELECT DISTINCT l.cve_id FROM cve_ioc_links l WHERE l.ioc_id=%s LIMIT 20""", (ioc_id,))
        for c in cur.fetchall():
            cvid = f"cve:{c['cve_id']}"
            g.node(cvid, "cve", c["cve_id"], ref=c["cve_id"])
            g.edge(nid, cvid, "related_to")
        invs = _safe(conn, lambda: (cur.execute(
            """SELECT inv.id, inv.seq, inv.name FROM investigation_items it
               JOIN investigations inv ON inv.id=it.investigation_id
               WHERE it.item_type='ioc' AND it.ref_id=%s LIMIT 10""", (ioc_id,)), cur.fetchall())[1], [])
        for inv in invs:
            iid = f"investigation:{inv['id']}"
            g.node(iid, "investigation", f"{_inv_key(inv)} {inv['name']}", ref=inv["id"])
            g.edge(nid, iid, "tracked_in")

    def _campaign_graph(conn, g, campaign_id, limit=150):
        cur = _dict_cur(conn)
        cur.execute("SELECT * FROM campaigns WHERE id=%s", (campaign_id,))
        c = cur.fetchone()
        if not c:
            raise HTTPException(404, "Campaign not found")
        cid = f"campaign:{c['id']}"
        g.node(cid, "campaign", c["name"], ref=c["id"])
        if c.get("threat_actor"):
            g.node(f"actor:{c['threat_actor']}", "actor", c["threat_actor"], ref=c["threat_actor"])
            g.edge(cid, f"actor:{c['threat_actor']}", "attributed_to")
        cur.execute("""SELECT id, type, value, value_defanged, confidence, enrichment->>'malware_family' AS family
                       FROM iocs WHERE campaign_id=%s ORDER BY confidence DESC, created_at DESC LIMIT %s""",
                    (c["id"], limit))
        ids = []
        for r in cur.fetchall():
            if _ioc_node(g, r):
                ids.append(r["id"])
                g.edge(f"ioc:{r['id']}", cid, "part_of")
                if r["family"] and r["family"] != "unknown":
                    g.node(f"malware:{r['family']}", "malware", r["family"], ref=r["family"])
                    g.edge(f"ioc:{r['id']}", f"malware:{r['family']}", "indicates")
        if ids:
            cur.execute("""SELECT source_id, target_id, relationship_type FROM ioc_relationships
                           WHERE source_id = ANY(%s) AND target_id = ANY(%s)""", (ids, ids))
            for rel in cur.fetchall():
                g.edge(f"ioc:{rel['source_id']}", f"ioc:{rel['target_id']}", rel["relationship_type"])
        return c

    @app.get("/v2/graph")
    def v2_graph(kind: str, id: str, depth: int = 1, user=Depends(full), conn=Depends(get_db)):
        g = _G()
        depth = max(1, min(depth, 2))
        cur = _dict_cur(conn)
        if kind == "ioc":
            frontier = []
            _expand_ioc(conn, g, id, depth, frontier)
            if not g.nodes:
                raise HTTPException(404, "IOC not found")
            if depth > 1:
                for other in list(dict.fromkeys(frontier))[:25]:
                    _expand_ioc(conn, g, other, 1, [])
        elif kind == "campaign":
            _campaign_graph(conn, g, id)
        elif kind == "actor":
            aid = f"actor:{id}"
            g.node(aid, "actor", id, ref=id)
            cur.execute("SELECT id FROM campaigns WHERE LOWER(threat_actor)=LOWER(%s)", (id,))
            for c in cur.fetchall():
                _campaign_graph(conn, g, c["id"], limit=60)
        elif kind == "malware":
            mid = f"malware:{id}"
            g.node(mid, "malware", id, ref=id)
            cur.execute("""SELECT i.id, i.type, i.value, i.value_defanged, i.confidence, i.campaign_id,
                    c.name AS campaign_name, c.threat_actor
                FROM iocs i LEFT JOIN campaigns c ON c.id=i.campaign_id
                WHERE i.enrichment->>'malware_family'=%s ORDER BY i.created_at DESC LIMIT 150""", (id,))
            for r in cur.fetchall():
                if _ioc_node(g, r):
                    g.edge(f"ioc:{r['id']}", mid, "indicates")
                    if r["campaign_id"]:
                        g.node(f"campaign:{r['campaign_id']}", "campaign", r["campaign_name"], ref=r["campaign_id"])
                        g.edge(f"ioc:{r['id']}", f"campaign:{r['campaign_id']}", "part_of")
        elif kind == "investigation":
            inv = _get_investigation(conn, id)
            iid = f"investigation:{id}"
            g.node(iid, "investigation", f"{_inv_key(inv)} {inv['name']}", ref=id)
            cur.execute("SELECT * FROM investigation_items WHERE investigation_id=%s", (id,))
            for it in cur.fetchall():
                t = it["item_type"]
                if t == "ioc" and it["ref_id"]:
                    before = len(g.nodes)
                    _expand_ioc(conn, g, it["ref_id"], 1, [])
                    if len(g.nodes) >= before:
                        g.edge(f"ioc:{it['ref_id']}", iid, "tracked_in")
                elif t in ("cve", "campaign", "actor", "malware", "observable", "asset"):
                    nid = f"{t}:{it['ref_id'] or it['value']}"
                    g.node(nid, t, it["label"] or it["value"] or it["ref_id"], ref=it["ref_id"] or it["value"],
                           ioc_type=(it.get("data") or {}).get("type"))
                    g.edge(nid, iid, "tracked_in")
        else:
            raise HTTPException(400, "Unknown graph kind")
        return {"nodes": list(g.nodes.values()), "edges": g.edges, "truncated": len(g.nodes) >= g.cap}

    # ══════════════════════════════════════════════════════════════════════
    # GLOBAL SEARCH
    # ══════════════════════════════════════════════════════════════════════
    @app.get("/v2/search")
    def v2_search(q: str, limit: int = 6, user=Depends(current), conn=Depends(get_db)):
        q = (q or "").strip()
        if not q:
            return {"query": q, "groups": {}, "detected_type": None}
        limit = max(1, min(limit, 25))
        norm = d.refang(q)
        detected = d.detect_type(norm)
        caps = d.effective_caps(user, conn)
        groups = {}
        like = f"%{q}%"
        if "data.workspace" in caps:
            cur = _dict_cur(conn)
            cur.execute(f"""SELECT i.id, i.type, i.value, i.value_defanged, i.confidence, i.tlp, i.created_at,
                    {STATUS_SQL} AS status, i.enrichment->>'malware_family' AS malware_family
                FROM iocs i
                WHERE i.value ILIKE %s OR i.value_defanged ILIKE %s OR %s = ANY(i.tags)
                   OR i.enrichment->>'malware_family' ILIKE %s
                ORDER BY (i.value = %s) DESC, i.confidence DESC, i.created_at DESC LIMIT %s""",
                (f"%{norm}%", like, q.lower(), like, norm, limit))
            groups["iocs"] = cur.fetchall()
            cur.execute(f"""SELECT * FROM (SELECT DISTINCT ON (cf.cve_id) cf.cve_id, cf.title, cf.cvss_score,
                    {SEV_SQL} AS severity, cf.kev_listed, cf.patch_available, a.name AS asset_name, a.id AS asset_id
                FROM cve_findings cf LEFT JOIN assets a ON a.id=cf.asset_id
                WHERE cf.cve_id ILIKE %s OR cf.title ILIKE %s
                ORDER BY cf.cve_id, cf.cvss_score DESC NULLS LAST) x
                ORDER BY cvss_score DESC NULLS LAST LIMIT %s""", (like, like, limit))
            groups["cves"] = cur.fetchall()
            cur.execute("""SELECT a.id, a.name, a.vendor, a.version, COUNT(cf.id) AS cve_count
                FROM assets a LEFT JOIN cve_findings cf ON cf.asset_id=a.id
                WHERE a.active=TRUE AND (a.name ILIKE %s OR a.vendor ILIKE %s)
                GROUP BY a.id ORDER BY cve_count DESC LIMIT %s""", (like, like, limit))
            groups["software"] = cur.fetchall()
            cur.execute("""SELECT c.id, c.name, c.threat_actor, COUNT(i.id) AS ioc_count
                FROM campaigns c LEFT JOIN iocs i ON i.campaign_id=c.id
                WHERE c.name ILIKE %s OR c.description ILIKE %s OR c.threat_actor ILIKE %s
                GROUP BY c.id ORDER BY ioc_count DESC LIMIT %s""", (like, like, like, limit))
            groups["campaigns"] = cur.fetchall()
            cur.execute("""SELECT threat_actor AS name, COUNT(*) AS campaigns FROM campaigns
                WHERE threat_actor ILIKE %s AND COALESCE(threat_actor,'')<>''
                GROUP BY threat_actor ORDER BY campaigns DESC LIMIT %s""", (like, limit))
            groups["actors"] = cur.fetchall()
            cur.execute("""SELECT enrichment->>'malware_family' AS name, COUNT(*) AS iocs FROM iocs
                WHERE enrichment->>'malware_family' ILIKE %s GROUP BY 1 ORDER BY iocs DESC LIMIT %s""", (like, limit))
            groups["malware"] = cur.fetchall()
            invs = _safe(conn, lambda: (cur.execute(
                """SELECT id, seq, name, status, severity, updated_at FROM investigations
                   WHERE name ILIKE %s OR description ILIKE %s OR %s = ANY(tags)
                   ORDER BY updated_at DESC LIMIT %s""", (like, like, q.lower(), limit)), cur.fetchall())[1], [])
            for inv in invs:
                inv["key"] = _inv_key(inv)
            groups["investigations"] = invs
            if "admin.panel" in caps:
                groups["notes"] = _safe(conn, lambda: (cur.execute(
                    """SELECT id, title, LEFT(content, 160) AS snippet, investigation_id, updated_at FROM admin_notes
                       WHERE archived=FALSE AND (title ILIKE %s OR content ILIKE %s)
                       ORDER BY updated_at DESC LIMIT %s""", (like, like, limit)), cur.fetchall())[1], [])
        return {"query": q, "normalized": norm, "detected_type": detected, "groups": groups,
                "limited": "data.workspace" not in caps}

    # ══════════════════════════════════════════════════════════════════════
    # COMMAND CENTER
    # ══════════════════════════════════════════════════════════════════════
    def _series(cur, sql, params, days):
        cur.execute(sql, params)
        found = {r["d"].isoformat(): int(r["n"]) for r in cur.fetchall()}
        today = datetime.now(timezone.utc).date()
        return [found.get((today - timedelta(days=i)).isoformat(), 0) for i in range(days - 1, -1, -1)]

    @app.get("/v2/command-center")
    def v2_command_center(user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        m = {}
        cur.execute(f"""SELECT
                COUNT(*) FILTER (WHERE {ACTIVE_SQL}) AS active,
                COUNT(*) FILTER (WHERE {ACTIVE_SQL} AND i.confidence >= 80) AS high_conf,
                COUNT(*) FILTER (WHERE {ACTIVE_SQL} AND i.confidence >= 90) AS critical,
                COUNT(*) FILTER (WHERE i.created_at >= CURRENT_DATE) AS today,
                COUNT(*) FILTER (WHERE i.created_at >= CURRENT_DATE - 1 AND i.created_at < CURRENT_DATE) AS yesterday,
                COUNT(*) FILTER (WHERE i.created_at >= NOW() - INTERVAL '7 days') AS last7,
                COUNT(*) FILTER (WHERE i.created_at >= NOW() - INTERVAL '14 days'
                                   AND i.created_at < NOW() - INTERVAL '7 days') AS prev7,
                COUNT(*) FILTER (WHERE i.valid_until IS NOT NULL AND i.valid_until <= NOW()) AS expired,
                COUNT(*) FILTER (WHERE i.false_positive) AS fp,
                COUNT(*) AS total
            FROM iocs i""")
        m["iocs"] = cur.fetchone()
        m["ioc_series"] = _series(cur, """SELECT created_at::date AS d, COUNT(*) AS n FROM iocs
            WHERE created_at >= CURRENT_DATE - 13 GROUP BY 1""", (), 14)
        m["high_series"] = _series(cur, """SELECT created_at::date AS d, COUNT(*) AS n FROM iocs
            WHERE created_at >= CURRENT_DATE - 13 AND confidence >= 80 GROUP BY 1""", (), 14)

        cur.execute(f"""SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE {UNPATCHED_SQL}) AS unpatched,
                COUNT(*) FILTER (WHERE cf.patch_available) AS patched,
                COUNT(*) FILTER (WHERE cf.kev_listed) AS kev,
                COUNT(*) FILTER (WHERE cf.kev_listed AND {UNPATCHED_SQL}) AS kev_unpatched,
                COUNT(*) FILTER (WHERE {SEV_SQL}='CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE {SEV_SQL}='CRITICAL' AND {UNPATCHED_SQL}) AS critical_unpatched,
                COUNT(*) FILTER (WHERE cf.created_at >= NOW() - INTERVAL '7 days') AS new7
            FROM cve_findings cf""")
        m["cves"] = cur.fetchone()
        m["cve_series"] = _series(cur, """SELECT created_at::date AS d, COUNT(*) AS n FROM cve_findings
            WHERE created_at >= CURRENT_DATE - 13 GROUP BY 1""", (), 14)
        cur.execute(f"""SELECT {SEV_SQL} AS severity,
                COUNT(*) FILTER (WHERE {UNPATCHED_SQL}) AS unpatched,
                COUNT(*) FILTER (WHERE cf.patch_available) AS patched
            FROM cve_findings cf GROUP BY 1""")
        m["cve_exposure"] = cur.fetchall()

        cur.execute("""SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM iocs i WHERE i.campaign_id=c.id
                                                 AND i.created_at >= NOW() - INTERVAL '30 days')) AS active
            FROM campaigns c""")
        m["campaigns"] = cur.fetchone()

        # IOC activity: 30 days, per type
        cur.execute("""SELECT created_at::date AS d, type, COUNT(*) AS n FROM iocs
            WHERE created_at >= CURRENT_DATE - 29 GROUP BY 1,2""")
        rows = cur.fetchall()
        today = datetime.now(timezone.utc).date()
        days = [(today - timedelta(days=i)).isoformat() for i in range(29, -1, -1)]
        by_type = {}
        for r in rows:
            by_type.setdefault(r["type"], {})[r["d"].isoformat()] = int(r["n"])
        activity = {"days": days, "series": [
            {"type": t, "values": [v.get(dd, 0) for dd in days], "total": sum(v.values())}
            for t, v in sorted(by_type.items(), key=lambda kv: -sum(kv[1].values()))]}

        cur.execute(f"""SELECT i.type, COUNT(*) AS n FROM iocs i WHERE {ACTIVE_SQL}
            GROUP BY i.type ORDER BY n DESC""")
        type_dist = cur.fetchall()

        cur.execute("""SELECT c.threat_actor AS name, COUNT(DISTINCT c.id) AS campaigns, COUNT(i.id) AS iocs,
                MAX(i.created_at) AS last_activity
            FROM campaigns c LEFT JOIN iocs i ON i.campaign_id=c.id
            WHERE COALESCE(c.threat_actor,'')<>'' GROUP BY c.threat_actor ORDER BY iocs DESC LIMIT 8""")
        actors = cur.fetchall()
        cur.execute("""SELECT enrichment->>'malware_family' AS name, COUNT(*) AS iocs, MAX(created_at) AS last_activity,
                COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') AS recent
            FROM iocs WHERE COALESCE(enrichment->>'malware_family','') NOT IN ('','unknown')
            GROUP BY 1 ORDER BY recent DESC, iocs DESC LIMIT 8""")
        malware = cur.fetchall()

        cur.execute(f"""SELECT i.id, i.type, i.value, i.value_defanged, i.confidence, i.created_at, i.tlp,
                {SOURCE_SQL} AS source, i.enrichment->>'malware_family' AS malware_family, c.name AS campaign_name
            FROM iocs i LEFT JOIN campaigns c ON c.id=i.campaign_id
            ORDER BY i.created_at DESC LIMIT 10""")
        recent_iocs = cur.fetchall()
        cur.execute(f"""SELECT cf.cve_id, cf.title, cf.cvss_score, {SEV_SQL} AS severity, cf.kev_listed,
                cf.patch_available, cf.created_at, a.name AS asset_name, a.id AS asset_id
            FROM cve_findings cf LEFT JOIN assets a ON a.id=cf.asset_id
            ORDER BY cf.created_at DESC LIMIT 8""")
        recent_cves = cur.fetchall()

        # Threat pulse — every item derived from rows in this database.
        pulse = []
        cur.execute(f"""SELECT cf.cve_id, cf.title, cf.cvss_score, a.name AS asset_name, a.id AS asset_id,
                cf.created_at, cf.patch_available
            FROM cve_findings cf LEFT JOIN assets a ON a.id=cf.asset_id
            WHERE cf.kev_listed AND {UNPATCHED_SQL}
            ORDER BY cf.created_at DESC LIMIT 3""")
        for r in cur.fetchall():
            pulse.append({"kind": "exploitation", "label": "ACTIVE EXPLOITATION",
                          "title": r["asset_name"] or r["cve_id"],
                          "detail": f"{r['cve_id']} is in CISA KEV and unpatched"
                                    + (f" (CVSS {r['cvss_score']})" if r["cvss_score"] else ""),
                          "severity": "critical", "route": f"/cve/{r['cve_id']}", "ts": r["created_at"]})
        for r in malware[:3]:
            if r["recent"]:
                pulse.append({"kind": "malware", "label": "MALWARE", "title": r["name"],
                              "detail": f"{r['recent']} new indicator{'s' if r['recent'] != 1 else ''} in the last 7 days",
                              "severity": "high", "route": f"/malware/{r['name']}", "ts": r["last_activity"]})
        cur.execute("""SELECT c.id, c.name, c.threat_actor, COUNT(i.id) AS n, MAX(i.created_at) AS last
            FROM campaigns c JOIN iocs i ON i.campaign_id=c.id
            WHERE i.created_at >= NOW() - INTERVAL '14 days' GROUP BY c.id ORDER BY last DESC LIMIT 3""")
        for r in cur.fetchall():
            pulse.append({"kind": "campaign", "label": "CAMPAIGN", "title": r["name"],
                          "detail": f"{r['n']} new indicator{'s' if r['n'] != 1 else ''} observed"
                                    + (f" · {r['threat_actor']}" if r["threat_actor"] else ""),
                          "severity": "medium", "route": f"/campaigns/{r['id']}", "ts": r["last"]})
        cur.execute(f"""SELECT cf.cve_id, cf.cvss_score, a.name AS asset_name, cf.created_at
            FROM cve_findings cf LEFT JOIN assets a ON a.id=cf.asset_id
            WHERE {SEV_SQL}='CRITICAL' AND {UNPATCHED_SQL} AND NOT cf.kev_listed
              AND cf.created_at >= NOW() - INTERVAL '14 days'
            ORDER BY cf.created_at DESC LIMIT 2""")
        for r in cur.fetchall():
            pulse.append({"kind": "vulnerability", "label": "CRITICAL CVE", "title": r["asset_name"] or r["cve_id"],
                          "detail": f"{r['cve_id']} (CVSS {r['cvss_score']}) with no patch detected",
                          "severity": "high", "route": f"/cve/{r['cve_id']}", "ts": r["created_at"]})
        pulse.sort(key=lambda p: p["ts"] or datetime.min, reverse=True)
        sev_rank = {"critical": 0, "high": 1, "medium": 2}
        pulse.sort(key=lambda p: sev_rank.get(p["severity"], 3))

        # Platform health snapshot
        health = {"connectors": [], "last_cve_poll": None, "backup": None}
        import json as _json
        if _table_exists(conn, "system_settings"):
            cur.execute("SELECT key, value FROM system_settings WHERE key LIKE %s", ("connector_last_run_%",))
            for r in cur.fetchall():
                try:
                    v = _json.loads(r["value"])
                except Exception:
                    v = {}
                health["connectors"].append({"name": r["key"].replace("connector_last_run_", ""),
                                             "ok": bool(v.get("ok")), "added": v.get("added", 0),
                                             "ran_at": v.get("ran_at"), "error": v.get("error")})
            cur.execute("SELECT value FROM system_settings WHERE key='backup_last_result'")
            b = cur.fetchone()
            if b:
                try:
                    health["backup"] = _json.loads(b["value"])
                except Exception:
                    pass
        cur.execute("SELECT polled_at, new_cves, error FROM cve_poll_log ORDER BY polled_at DESC LIMIT 1")
        health["last_cve_poll"] = cur.fetchone()

        open_invs = []
        if _table_exists(conn, "investigations"):
            cur.execute("""SELECT id, seq, name, status, severity, updated_at FROM investigations
                WHERE status <> 'closed' ORDER BY updated_at DESC LIMIT 5""")
            open_invs = cur.fetchall()
        for inv in open_invs:
            inv["key"] = _inv_key(inv)

        return {"metrics": m, "activity": activity, "type_distribution": type_dist,
                "actors": actors, "malware": malware, "recent_iocs": recent_iocs,
                "recent_cves": recent_cves, "pulse": pulse[:8], "health": health,
                "investigations": open_invs, "generated_at": datetime.now(timezone.utc).isoformat()}

    def _table_exists(conn, name):
        c = conn.cursor()
        c.execute("SELECT to_regclass(%s)", (name,))
        return c.fetchone()[0] is not None

    # ══════════════════════════════════════════════════════════════════════
    # SOFTWARE / VULNERABILITY INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════════
    SOFT_AGG = f"""COUNT(cf.id) AS total,
        COUNT(cf.id) FILTER (WHERE {SEV_SQL}='CRITICAL') AS critical,
        COUNT(cf.id) FILTER (WHERE {SEV_SQL}='HIGH') AS high,
        COUNT(cf.id) FILTER (WHERE {SEV_SQL}='MEDIUM') AS medium,
        COUNT(cf.id) FILTER (WHERE {SEV_SQL}='LOW') AS low,
        COUNT(cf.id) FILTER (WHERE cf.kev_listed) AS kev,
        COUNT(cf.id) FILTER (WHERE cf.kev_listed AND {UNPATCHED_SQL}) AS kev_unpatched,
        COUNT(cf.id) FILTER (WHERE {SEV_SQL}='CRITICAL' AND {UNPATCHED_SQL}) AS critical_unpatched,
        COUNT(cf.id) FILTER (WHERE {UNPATCHED_SQL}) AS unpatched,
        COUNT(cf.id) FILTER (WHERE cf.patch_available) AS patched,
        MAX(cf.published_date) AS latest_published, MAX(cf.epss_score) AS max_epss"""

    def _soft_status(r):
        if r["kev_unpatched"]:
            return "kev_exposed"
        if r["critical_unpatched"]:
            return "critical_exposed"
        if r["unpatched"]:
            return "exposed"
        return "covered" if r["total"] else "clean"

    @app.get("/v2/software")
    def v2_software(year: int = 0, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        join_cond = "cf.asset_id=a.id"
        params = []
        if year:
            join_cond += " AND cf.published_date LIKE %s"; params.append(f"{year}%")
        cur.execute(f"""SELECT a.id, a.name, a.vendor, a.version, a.asset_type, a.criticality, a.cpe, a.created_at,
                {SOFT_AGG}
            FROM assets a LEFT JOIN cve_findings cf ON {join_cond}
            WHERE a.active=TRUE GROUP BY a.id ORDER BY kev_unpatched DESC, critical DESC, total DESC""", params)
        rows = cur.fetchall()
        for r in rows:
            r["status"] = _soft_status(r)
        return {"software": rows}

    @app.get("/v2/software/{asset_id}")
    def v2_software_detail(asset_id: str, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute(f"""SELECT a.*, {SOFT_AGG} FROM assets a LEFT JOIN cve_findings cf ON cf.asset_id=a.id
            WHERE a.id=%s GROUP BY a.id""", (asset_id,))
        a = cur.fetchone()
        if not a:
            raise HTTPException(404, "Software not found")
        a["status"] = _soft_status(a)
        cur.execute(f"""SELECT SUBSTRING(cf.published_date,1,4) AS year, {SEV_SQL} AS severity, COUNT(*) AS n
            FROM cve_findings cf WHERE cf.asset_id=%s GROUP BY 1,2 ORDER BY 1""", (asset_id,))
        by_year = cur.fetchall()
        cols = """cf.id, cf.cve_id, cf.title, cf.description, cf.cvss_score, cf.cvss_vector, cf.epss_score,
                  cf.epss_percentile, cf.kev_listed, cf.kev_date, cf.cwe, cf.affected_versions, cf.published_date,
                  cf.patch_available, cf.patch_url"""
        cur.execute(f"""SELECT {cols}, {SEV_SQL} AS severity FROM cve_findings cf WHERE cf.asset_id=%s
            ORDER BY cf.published_date DESC NULLS LAST LIMIT 15""", (asset_id,))
        recent = cur.fetchall()
        cur.execute(f"""SELECT {cols}, {SEV_SQL} AS severity FROM cve_findings cf
            WHERE cf.asset_id=%s AND cf.kev_listed ORDER BY cf.published_date DESC NULLS LAST""", (asset_id,))
        kev = cur.fetchall()
        cur.execute(f"""SELECT {cols}, {SEV_SQL} AS severity FROM cve_findings cf
            WHERE cf.asset_id=%s AND cf.epss_score IS NOT NULL ORDER BY cf.epss_score DESC LIMIT 10""", (asset_id,))
        epss = cur.fetchall()
        cur.execute(f"""SELECT cf.affected_versions AS versions, COUNT(*) AS n,
                COUNT(*) FILTER (WHERE {SEV_SQL} IN ('CRITICAL','HIGH')) AS severe,
                COUNT(*) FILTER (WHERE {UNPATCHED_SQL}) AS unpatched
            FROM cve_findings cf WHERE cf.asset_id=%s AND COALESCE(cf.affected_versions,'')<>''
            GROUP BY 1 ORDER BY n DESC LIMIT 30""", (asset_id,))
        versions = cur.fetchall()
        cur.execute("""SELECT cf.cwe, COUNT(*) AS n FROM cve_findings cf
            WHERE cf.asset_id=%s AND COALESCE(cf.cwe,'')<>'' GROUP BY 1 ORDER BY n DESC LIMIT 10""", (asset_id,))
        cwes = cur.fetchall()
        cur.execute("""SELECT cf."references" AS refs FROM cve_findings cf
            WHERE cf.asset_id=%s AND cf."references" IS NOT NULL
            ORDER BY cf.published_date DESC NULLS LAST LIMIT 300""", (asset_id,))
        domains, advisories = {}, []
        for r in cur.fetchall():
            for ref in (r["refs"] or []):
                url = ref.get("url") if isinstance(ref, dict) else ref if isinstance(ref, str) else None
                if not url:
                    continue
                m = re.match(r"https?://([^/]+)", url)
                if m:
                    host = m.group(1).lower()
                    domains[host] = domains.get(host, 0) + 1
                tags = ref.get("tags") if isinstance(ref, dict) else None
                if tags and ("Vendor Advisory" in tags or "Patch" in tags) and len(advisories) < 15 \
                        and url not in advisories:
                    advisories.append(url)
        cur.execute("""SELECT COUNT(DISTINCT l.ioc_id) AS n FROM cve_ioc_links l
            JOIN cve_findings cf ON cf.cve_id=l.cve_id WHERE cf.asset_id=%s""", (asset_id,))
        linked_iocs = cur.fetchone()["n"]
        return {"software": a, "by_year": by_year, "recent": recent, "kev": kev, "top_epss": epss,
                "versions": versions, "cwes": cwes, "linked_iocs": linked_iocs,
                "reference_domains": sorted(({"domain": k, "n": v} for k, v in domains.items()),
                                            key=lambda x: -x["n"])[:15],
                "advisories": advisories}

    # ══════════════════════════════════════════════════════════════════════
    # THREAT ACTORS / MALWARE / CAMPAIGNS
    # ══════════════════════════════════════════════════════════════════════
    @app.get("/v2/actors")
    def v2_actors(user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute("""SELECT c.threat_actor AS name, COUNT(DISTINCT c.id) AS campaigns, COUNT(i.id) AS iocs,
                MAX(i.created_at) AS last_activity, ARRAY_AGG(DISTINCT c.name) AS campaign_names
            FROM campaigns c LEFT JOIN iocs i ON i.campaign_id=c.id
            WHERE COALESCE(c.threat_actor,'')<>'' GROUP BY c.threat_actor ORDER BY iocs DESC""")
        actors = cur.fetchall()
        cur.execute("""SELECT enrichment->>'malware_family' AS name, COUNT(*) AS iocs, MIN(created_at) AS first_seen,
                MAX(created_at) AS last_seen, COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') AS recent,
                ARRAY_AGG(DISTINCT type) AS types
            FROM iocs WHERE COALESCE(enrichment->>'malware_family','') NOT IN ('','unknown')
            GROUP BY 1 ORDER BY recent DESC, iocs DESC LIMIT 60""")
        malware = cur.fetchall()
        return {"actors": actors, "malware": malware}

    @app.get("/v2/actors/{name}")
    def v2_actor(name: str, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute("""SELECT c.*, COUNT(i.id) AS ioc_count, MAX(i.created_at) AS last_activity
            FROM campaigns c LEFT JOIN iocs i ON i.campaign_id=c.id
            WHERE LOWER(c.threat_actor)=LOWER(%s) GROUP BY c.id ORDER BY last_activity DESC NULLS LAST""", (name,))
        campaigns = cur.fetchall()
        ids = [c["id"] for c in campaigns]
        iocs, types, families = [], [], []
        if ids:
            cur.execute("""SELECT id, type, value, value_defanged, confidence, created_at, campaign_id
                FROM iocs WHERE campaign_id = ANY(%s) ORDER BY created_at DESC LIMIT 200""", (ids,))
            iocs = cur.fetchall()
            cur.execute("SELECT type, COUNT(*) AS n FROM iocs WHERE campaign_id = ANY(%s) GROUP BY type ORDER BY n DESC", (ids,))
            types = cur.fetchall()
            cur.execute("""SELECT enrichment->>'malware_family' AS name, COUNT(*) AS n FROM iocs
                WHERE campaign_id = ANY(%s) AND COALESCE(enrichment->>'malware_family','') NOT IN ('','unknown')
                GROUP BY 1 ORDER BY n DESC LIMIT 10""", (ids,))
            families = cur.fetchall()
        return {"name": name, "campaigns": campaigns, "iocs": iocs, "types": types, "malware": families}

    @app.get("/v2/malware/{family}")
    def v2_malware(family: str, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute(f"""SELECT COUNT(*) AS total, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
                COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') AS recent
            FROM iocs i WHERE i.enrichment->>'malware_family'=%s""", (family,))
        stats = cur.fetchone()
        cur.execute("""SELECT type, COUNT(*) AS n FROM iocs WHERE enrichment->>'malware_family'=%s
            GROUP BY type ORDER BY n DESC""", (family,))
        types = cur.fetchall()
        cur.execute(f"""SELECT {SOURCE_SQL} AS source, COUNT(*) AS n FROM iocs i
            WHERE i.enrichment->>'malware_family'=%s GROUP BY 1 ORDER BY n DESC""", (family,))
        sources = cur.fetchall()
        cur.execute(f"""SELECT i.id, i.type, i.value, i.value_defanged, i.confidence, i.created_at, i.tags,
                {STATUS_SQL} AS status FROM iocs i
            WHERE i.enrichment->>'malware_family'=%s ORDER BY i.created_at DESC LIMIT 200""", (family,))
        iocs = cur.fetchall()
        cur.execute("""SELECT DISTINCT c.id, c.name, c.threat_actor FROM iocs i JOIN campaigns c ON c.id=i.campaign_id
            WHERE i.enrichment->>'malware_family'=%s""", (family,))
        campaigns = cur.fetchall()
        return {"name": family, "stats": stats, "types": types, "sources": sources,
                "iocs": iocs, "campaigns": campaigns}

    @app.get("/v2/campaigns/{campaign_id}")
    def v2_campaign(campaign_id: str, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute("""SELECT c.*, u.username AS created_by_name FROM campaigns c
            LEFT JOIN users u ON u.id=c.created_by WHERE c.id=%s""", (campaign_id,))
        c = cur.fetchone()
        if not c:
            raise HTTPException(404, "Campaign not found")
        cur.execute(f"""SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE {ACTIVE_SQL}) AS active,
                MIN(i.created_at) AS first_seen, MAX(i.created_at) AS last_seen, AVG(i.confidence)::int AS avg_conf
            FROM iocs i WHERE i.campaign_id=%s""", (campaign_id,))
        stats = cur.fetchone()
        cur.execute("SELECT type, COUNT(*) AS n FROM iocs WHERE campaign_id=%s GROUP BY type ORDER BY n DESC", (campaign_id,))
        types = cur.fetchall()
        cur.execute(f"""SELECT i.id, i.type, i.value, i.value_defanged, i.confidence, i.created_at, i.tlp, i.tags,
                {STATUS_SQL} AS status, {SOURCE_SQL} AS source FROM iocs i
            WHERE i.campaign_id=%s ORDER BY i.created_at DESC LIMIT 500""", (campaign_id,))
        iocs = cur.fetchall()
        activity = _series(cur, """SELECT created_at::date AS d, COUNT(*) AS n FROM iocs
            WHERE campaign_id=%s AND created_at >= CURRENT_DATE - 29 GROUP BY 1""", (campaign_id,), 30)
        invs = _safe(conn, lambda: (cur.execute(
            """SELECT DISTINCT inv.id, inv.seq, inv.name, inv.status FROM investigation_items it
               JOIN investigations inv ON inv.id=it.investigation_id
               WHERE (it.item_type='campaign' AND it.ref_id=%s)""", (campaign_id,)), cur.fetchall())[1], [])
        for inv in invs:
            inv["key"] = _inv_key(inv)
        return {"campaign": c, "stats": stats, "types": types, "iocs": iocs,
                "activity": activity, "investigations": invs}

    @app.patch("/v2/campaigns/{campaign_id}")
    def v2_patch_campaign(campaign_id: str, body: CampaignPatch, user=Depends(full), conn=Depends(get_db)):
        sets, params = [], []
        for k in ("name", "description", "threat_actor", "industry_targets"):
            v = getattr(body, k)
            if v is not None:
                sets.append(f"{k}=%s"); params.append(v)
        if not sets:
            return {"status": "unchanged"}
        cur = conn.cursor()
        cur.execute(f"UPDATE campaigns SET {', '.join(sets)} WHERE id=%s", params + [campaign_id])
        if cur.rowcount == 0:
            raise HTTPException(404, "Campaign not found")
        conn.commit()
        return {"status": "updated"}

    # ══════════════════════════════════════════════════════════════════════
    # INVESTIGATIONS (Workspace)
    # ══════════════════════════════════════════════════════════════════════
    def _get_investigation(conn, inv_id):
        cur = _dict_cur(conn)
        cur.execute("SELECT * FROM investigations WHERE id=%s", (inv_id,))
        inv = cur.fetchone()
        if not inv:
            raise HTTPException(404, "Investigation not found")
        inv["key"] = _inv_key(inv)
        return inv

    def _event(conn, inv_id, etype, title, body, ref_type, ref_id, user, occurred_at=None):
        cur = conn.cursor()
        cur.execute("""INSERT INTO investigation_events
            (investigation_id, event_type, title, body, ref_type, ref_id, created_by, occurred_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,COALESCE(%s::timestamp, NOW()))""",
            (inv_id, etype, title[:500], body, ref_type, ref_id, user.get("username"), occurred_at))
        cur.execute("UPDATE investigations SET updated_at=NOW() WHERE id=%s", (inv_id,))

    def _add_item(conn, inv_id, item_type, ref_id, value, label, data, user):
        cur = conn.cursor()
        key = ref_id or value
        cur.execute("""SELECT 1 FROM investigation_items WHERE investigation_id=%s AND item_type=%s
                       AND COALESCE(ref_id, value)=%s""", (inv_id, item_type, key))
        if cur.fetchone():
            return False
        cur.execute("""INSERT INTO investigation_items (investigation_id, item_type, ref_id, value, label, data, created_by)
            VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (inv_id, item_type, ref_id, value, label, psycopg2.extras.Json(data or {}), user.get("username")))
        return True

    @app.get("/v2/investigations")
    def v2_investigations(status: str = "", q: str = "", user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        where, params = ["1=1"], []
        if status:
            where.append("inv.status = ANY(%s)"); params.append(status.split(","))
        if q:
            where.append("(inv.name ILIKE %s OR inv.description ILIKE %s)"); params += [f"%{q}%", f"%{q}%"]
        cur.execute(f"""SELECT inv.*,
                (SELECT COUNT(*) FROM investigation_items it WHERE it.investigation_id=inv.id AND it.item_type='ioc') AS iocs,
                (SELECT COUNT(*) FROM investigation_items it WHERE it.investigation_id=inv.id AND it.item_type='cve') AS cves,
                (SELECT COUNT(*) FROM investigation_items it WHERE it.investigation_id=inv.id) AS items,
                (SELECT COUNT(*) FROM admin_notes n WHERE n.investigation_id=inv.id) AS notes,
                (SELECT MAX(e.occurred_at) FROM investigation_events e WHERE e.investigation_id=inv.id) AS last_event
            FROM investigations inv WHERE {' AND '.join(where)}
            ORDER BY CASE inv.status WHEN 'closed' THEN 1 ELSE 0 END, inv.updated_at DESC""", params)
        rows = cur.fetchall()
        for r in rows:
            r["key"] = _inv_key(r)
        return {"investigations": rows}

    @app.post("/v2/investigations", status_code=201)
    def v2_create_investigation(body: InvestigationIn, user=Depends(full), conn=Depends(get_db)):
        if not body.name.strip():
            raise HTTPException(400, "Name required")
        inv_id = f"investigation--{uuid.uuid4()}"
        sev = (body.severity or "medium").lower()
        cur = _dict_cur(conn)
        cur.execute("""INSERT INTO investigations (id, name, description, status, severity, tags, owner_id, owner_name)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (inv_id, body.name.strip()[:200], body.description or "",
             body.status if body.status in INV_STATUSES else "open",
             sev if sev in SEVERITIES else "medium", body.tags or [], user["id"], user["username"]))
        inv = cur.fetchone()
        _event(conn, inv_id, "created", "Investigation opened", body.description or None, None, None, user)
        conn.commit()
        inv["key"] = _inv_key(inv)
        return inv

    @app.get("/v2/investigations/{inv_id}")
    def v2_investigation(inv_id: str, user=Depends(full), conn=Depends(get_db)):
        inv = _get_investigation(conn, inv_id)
        cur = _dict_cur(conn)
        cur.execute(f"""SELECT it.*, i.type AS ioc_type, i.value AS ioc_value, i.value_defanged AS ioc_defanged,
                i.confidence AS ioc_confidence, i.tlp AS ioc_tlp,
                CASE WHEN i.id IS NULL THEN NULL ELSE {STATUS_SQL} END AS ioc_status,
                i.enrichment->>'malware_family' AS malware_family
            FROM investigation_items it LEFT JOIN iocs i ON it.item_type='ioc' AND i.id=it.ref_id
            WHERE it.investigation_id=%s ORDER BY it.created_at DESC""", (inv_id,))
        items = cur.fetchall()
        cve_ids = [it["ref_id"] for it in items if it["item_type"] == "cve" and it["ref_id"]]
        if cve_ids:
            cur.execute(f"""SELECT DISTINCT ON (cf.cve_id) cf.cve_id, cf.title, cf.cvss_score, {SEV_SQL} AS severity,
                    cf.kev_listed, cf.patch_available, a.name AS asset_name
                FROM cve_findings cf LEFT JOIN assets a ON a.id=cf.asset_id WHERE cf.cve_id = ANY(%s)""", (cve_ids,))
            cvemap = {r["cve_id"]: r for r in cur.fetchall()}
            for it in items:
                if it["item_type"] == "cve":
                    it["cve"] = cvemap.get(it["ref_id"])
        cur.execute("SELECT * FROM investigation_events WHERE investigation_id=%s ORDER BY occurred_at DESC, id DESC", (inv_id,))
        events = cur.fetchall()
        cur.execute("SELECT * FROM admin_notes WHERE investigation_id=%s ORDER BY pinned DESC, updated_at DESC", (inv_id,))
        notes = cur.fetchall()
        stats = {"iocs": 0, "domains": 0, "ips": 0, "urls": 0, "hashes": 0, "emails": 0,
                 "cves": 0, "queries": 0, "detections": 0, "artifacts": 0, "notes": len(notes)}
        for it in items:
            t = it["item_type"]
            if t in ("ioc", "observable"):
                stats["iocs"] += 1
                ty = it.get("ioc_type") or (it.get("data") or {}).get("type") or ""
                if ty == "Domain": stats["domains"] += 1
                elif ty in ("IPv4", "IPv6"): stats["ips"] += 1
                elif ty == "URL": stats["urls"] += 1
                elif ty in ("MD5", "SHA1", "SHA256"): stats["hashes"] += 1
                elif ty == "Email": stats["emails"] += 1
            elif t == "cve": stats["cves"] += 1
            elif t == "query": stats["queries"] += 1
            elif t == "detection": stats["detections"] += 1
            elif t in ("artifact", "screenshot"): stats["artifacts"] += 1
        return {"investigation": inv, "items": items, "events": events, "notes": notes, "stats": stats}

    @app.patch("/v2/investigations/{inv_id}")
    def v2_patch_investigation(inv_id: str, body: InvestigationPatch, user=Depends(full), conn=Depends(get_db)):
        inv = _get_investigation(conn, inv_id)
        sets, params = [], []
        if body.name is not None and body.name.strip(): sets.append("name=%s"); params.append(body.name.strip()[:200])
        if body.description is not None: sets.append("description=%s"); params.append(body.description)
        if body.severity is not None and body.severity.lower() in SEVERITIES:
            sets.append("severity=%s"); params.append(body.severity.lower())
        if body.status is not None and body.status in INV_STATUSES:
            sets.append("status=%s"); params.append(body.status)
        if body.tags is not None: sets.append("tags=%s"); params.append(body.tags)
        if not sets:
            return {"status": "unchanged"}
        cur = conn.cursor()
        cur.execute(f"UPDATE investigations SET {', '.join(sets)}, updated_at=NOW() WHERE id=%s", params + [inv_id])
        if body.status and body.status != inv["status"] and body.status in INV_STATUSES:
            _event(conn, inv_id, "status", f"Status changed: {inv['status']} → {body.status}", None, None, None, user)
        if body.severity and body.severity.lower() != inv["severity"] and body.severity.lower() in SEVERITIES:
            _event(conn, inv_id, "severity", f"Severity set to {body.severity.lower()}", None, None, None, user)
        conn.commit()
        return {"status": "updated"}

    @app.delete("/v2/investigations/{inv_id}")
    def v2_delete_investigation(inv_id: str, user=Depends(admin), conn=Depends(get_db)):
        _get_investigation(conn, inv_id)
        cur = conn.cursor()
        cur.execute("DELETE FROM investigation_items WHERE investigation_id=%s", (inv_id,))
        cur.execute("DELETE FROM investigation_events WHERE investigation_id=%s", (inv_id,))
        # Notes survive in the general workspace rather than being destroyed.
        cur.execute("UPDATE admin_notes SET investigation_id=NULL WHERE investigation_id=%s", (inv_id,))
        cur.execute("DELETE FROM investigations WHERE id=%s", (inv_id,))
        conn.commit()
        return {"status": "deleted"}

    @app.post("/v2/investigations/{inv_id}/items", status_code=201)
    def v2_add_item(inv_id: str, body: InvItemIn, user=Depends(full), conn=Depends(get_db)):
        _get_investigation(conn, inv_id)
        t = body.item_type
        if t not in INV_ITEM_TYPES:
            raise HTTPException(400, f"item_type must be one of {sorted(INV_ITEM_TYPES)}")
        ref_id, value, label, data = body.ref_id, (body.value or "").strip() or None, body.label, body.data or {}
        cur = _dict_cur(conn)
        if t in ("ioc", "observable") and not ref_id and value:
            # A raw value: link the tracked IOC when one exists, otherwise keep
            # it as an untracked observable instead of silently creating an IOC.
            norm = d.refang(value)
            cur.execute("SELECT id, type, value FROM iocs WHERE value=%s LIMIT 1", (norm,))
            row = cur.fetchone()
            if row:
                t, ref_id, value, label = "ioc", row["id"], row["value"], row["type"]
            else:
                t, value = "observable", norm
                data = {**data, "type": d.detect_type(norm)}
                label = label or data["type"]
        elif t == "ioc" and ref_id:
            cur.execute("SELECT id, type, value FROM iocs WHERE id=%s", (ref_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "IOC not found")
            value, label = row["value"], row["type"]
        elif t == "cve":
            ref_id = (ref_id or value or "").upper().strip()
            if not re.match(r"^CVE-\d{4}-\d{4,}$", ref_id):
                raise HTTPException(400, "Invalid CVE ID")
            value = ref_id
        elif t == "campaign" and ref_id:
            cur.execute("SELECT id, name FROM campaigns WHERE id=%s", (ref_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Campaign not found")
            value, label = row["name"], row["name"]
        elif t in ("query", "detection"):
            body_text = data.get("query") or data.get("rule") or ""
            if not (body_text or value):
                raise HTTPException(400, "Query/rule content required")
            value = value or label or body_text[:80]
        if not (ref_id or value):
            raise HTTPException(400, "ref_id or value required")
        if not _add_item(conn, inv_id, t, ref_id, value, label, data, user):
            raise HTTPException(409, "Already part of this investigation")
        noun = {"ioc": "IOC", "cve": "CVE", "observable": "Observable", "query": "Query",
                "detection": "Detection", "campaign": "Campaign", "actor": "Threat actor",
                "malware": "Malware", "asset": "Software", "artifact": "Artifact",
                "screenshot": "Screenshot"}.get(t, t)
        _event(conn, inv_id, f"{t}_added", f"{noun} added: {(label if t in ('query','detection') else value) or ref_id}",
               None, t, ref_id or value, user)
        conn.commit()
        return {"status": "added", "item_type": t, "ref_id": ref_id, "value": value}

    @app.delete("/v2/investigations/{inv_id}/items/{item_id}")
    def v2_remove_item(inv_id: str, item_id: int, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute("DELETE FROM investigation_items WHERE id=%s AND investigation_id=%s RETURNING *", (item_id, inv_id))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Item not found")
        _event(conn, inv_id, "item_removed", f"Removed {row['item_type']}: {row['label'] or row['value'] or row['ref_id']}",
               None, row["item_type"], row["ref_id"], user)
        conn.commit()
        return {"status": "removed"}

    @app.post("/v2/investigations/{inv_id}/events", status_code=201)
    def v2_add_event(inv_id: str, body: InvEventIn, user=Depends(full), conn=Depends(get_db)):
        _get_investigation(conn, inv_id)
        if not body.title.strip():
            raise HTTPException(400, "Title required")
        occurred = None
        if body.occurred_at:
            try:
                occurred = datetime.fromisoformat(body.occurred_at.replace("Z", "")).isoformat()
            except ValueError:
                raise HTTPException(400, "occurred_at must be ISO-8601")
        _event(conn, inv_id, "manual", body.title.strip(), body.body or None, None, None, user, occurred)
        conn.commit()
        return {"status": "created"}

    @app.delete("/v2/investigations/{inv_id}/events/{event_id}")
    def v2_delete_event(inv_id: str, event_id: int, user=Depends(full), conn=Depends(get_db)):
        cur = conn.cursor()
        cur.execute("DELETE FROM investigation_events WHERE id=%s AND investigation_id=%s AND event_type='manual'",
                    (event_id, inv_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Only manual timeline entries can be deleted")
        conn.commit()
        return {"status": "deleted"}

    @app.post("/v2/investigations/{inv_id}/notes", status_code=201)
    def v2_add_inv_note(inv_id: str, body: InvNoteIn, user=Depends(full), conn=Depends(get_db)):
        _get_investigation(conn, inv_id)
        if not (body.title or "").strip() and not (body.content or "").strip():
            raise HTTPException(400, "Empty note")
        nid = f"note--{uuid.uuid4()}"
        cur = _dict_cur(conn)
        cur.execute("""INSERT INTO admin_notes (id, title, content, note_type, tags, pinned, investigation_id)
            VALUES (%s,%s,%s,'text',%s,%s,%s) RETURNING *""",
            (nid, body.title or "", body.content or "", body.tags or [], bool(body.pinned), inv_id))
        note = cur.fetchone()
        _event(conn, inv_id, "note", f"Note added{': ' + body.title if body.title else ''}", None, "note", nid, user)
        conn.commit()
        return note

    @app.patch("/v2/investigations/{inv_id}/notes/{note_id}")
    def v2_edit_inv_note(inv_id: str, note_id: str, body: InvNoteIn, user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        cur.execute("""UPDATE admin_notes SET title=%s, content=%s, tags=%s, pinned=%s, updated_at=NOW()
            WHERE id=%s AND investigation_id=%s RETURNING *""",
            (body.title or "", body.content or "", body.tags or [], bool(body.pinned), note_id, inv_id))
        note = cur.fetchone()
        if not note:
            raise HTTPException(404, "Note not found")
        conn.commit()
        return note

    @app.delete("/v2/investigations/{inv_id}/notes/{note_id}")
    def v2_delete_inv_note(inv_id: str, note_id: str, user=Depends(full), conn=Depends(get_db)):
        cur = conn.cursor()
        cur.execute("DELETE FROM admin_notes WHERE id=%s AND investigation_id=%s", (note_id, inv_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Note not found")
        conn.commit()
        return {"status": "deleted"}

    # ══════════════════════════════════════════════════════════════════════
    # NOTIFICATIONS (grouped, actionable)
    # ══════════════════════════════════════════════════════════════════════
    SYSTEM_TYPES = {"connector_error", "system", "backup", "health"}

    def _notif_route(n):
        meta = n.get("metadata") or {}
        if meta.get("route"):
            return meta["route"]
        t = n.get("type")
        if t == "cve_new":
            cves = meta.get("new_cves") or []
            return f"/cve/{cves[0]['cve_id']}" if len(cves) == 1 and cves[0].get("cve_id") else "/cve"
        if t == "patch_available":
            return "/cve"
        if t == "ioc_auto":
            return "/iocs"
        if t == "access_request":
            return "/platform/users"
        if t in SYSTEM_TYPES:
            return "/platform/connectors" if t == "connector_error" else "/platform/health"
        return None

    @app.get("/v2/notifications")
    def v2_notifications(limit: int = 100, user=Depends(current), conn=Depends(get_db)):
        if "admin.panel" not in d.effective_caps(user, conn):
            return {"items": [], "unread": 0, "groups": {"critical": 0, "intelligence": 0, "system": 0}}
        cur = _dict_cur(conn)
        cur.execute("SELECT * FROM notifications ORDER BY created_at DESC LIMIT %s", (max(1, min(limit, 300)),))
        items = cur.fetchall()
        groups = {"critical": 0, "intelligence": 0, "system": 0}
        for n in items:
            if n["type"] in SYSTEM_TYPES:
                g = "system"
            elif n.get("severity") == "critical":
                g = "critical"
            else:
                g = "intelligence"
            n["group"] = g
            n["route"] = _notif_route(n)
            if not n["read"]:
                groups[g] += 1
        return {"items": items, "unread": sum(groups.values()), "groups": groups}

    # ══════════════════════════════════════════════════════════════════════
    # INTEL WALL — one merged, classified feed
    # ══════════════════════════════════════════════════════════════════════
    # The v1 endpoints tag every item with its feed's category, so a CISA KEV
    # alert and a SANS podcast were both "Malware/Medium". Here each item is
    # classified from its own text, entities are extracted, and CVEs are cross-
    # referenced against monitored software. Cached to keep upstream polite.
    import asyncio as _asyncio
    _wall_cache = {"at": None, "payload": None}

    RX = {
        "ransomware": re.compile(r"ransomware|lockbit|blackcat|alphv|akira|\bcl0p\b|\bclop\b|black ?basta|rhysida|medusa locker|qilin|play ransomware|extortion gang", re.I),
        "apt": re.compile(r"\bapt ?\d+\b|nation[- ]state|state[- ]sponsored|lazarus|kimsuky|volt typhoon|salt typhoon|silk typhoon|sandworm|fancy bear|cozy bear|turla|cyber ?espionage|espionage campaign|threat actor|hacking group", re.I),
        "vuln": re.compile(r"vulnerab|zero[- ]day|0[- ]day|security update|patch(es|ed)?\b|exploit|remote code|\brce\b|privilege escalation|advisory|flaw", re.I),
        "malware": re.compile(r"malware|trojan|stealer|botnet|loader|backdoor|\brat\b|infostealer|worm|spyware|dropper|phishing kit", re.I),
        "ioc": re.compile(r"indicators? of compromise|\biocs?\b|c2 server|command[- ]and[- ]control|malicious (ip|domain)s?|honeypot|scanning activity", re.I),
        "critical": re.compile(r"actively exploited|exploited in the wild|zero[- ]day|0[- ]day|\bkev\b|emergency directive|critical", re.I),
        "high": re.compile(r"exploit|ransomware|remote code|\brce\b|breach|backdoor|compromis", re.I),
        "low": re.compile(r"podcast|weekly|week in review|newsletter|webinar|stormcast", re.I),
    }
    ACTORS = ["Lazarus", "Kimsuky", "APT28", "APT29", "APT41", "Sandworm", "Volt Typhoon", "Salt Typhoon",
              "Silk Typhoon", "Scattered Spider", "Turla", "FIN7", "MuddyWater", "OilRig", "LockBit", "BlackCat",
              "ALPHV", "Akira", "Cl0p", "Black Basta", "Rhysida", "Qilin", "ShinyHunters", "Storm-0558"]

    def _classify(it):
        text = f"{it.get('title','')} {it.get('summary') or it.get('description') or ''}"
        cves = sorted(set(m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)))[:8]
        if RX["ransomware"].search(text): cat = "Ransomware"
        elif RX["apt"].search(text): cat = "APT"
        elif cves: cat = "CVE"
        elif RX["vuln"].search(text): cat = "Vulnerability"
        elif RX["malware"].search(text): cat = "Malware"
        elif RX["ioc"].search(text): cat = "IOC"
        else: cat = "General"
        if RX["low"].search(it.get("title", "")): sev = "low"
        elif RX["critical"].search(text): sev = "critical"
        elif RX["high"].search(text): sev = "high"
        else: sev = "medium"
        actors = [a for a in ACTORS if re.search(rf"\b{re.escape(a)}\b", text, re.I)][:5]
        return cat, sev, cves, actors

    @app.get("/v2/intel-wall")
    async def v2_intel_wall(refresh: bool = False, user=Depends(current), conn=Depends(get_db)):
        now = datetime.now(timezone.utc)
        cached = _wall_cache["payload"]
        if not refresh and cached and _wall_cache["at"] and (now - _wall_cache["at"]).total_seconds() < 900:
            payload = cached
        else:
            seen_urls, news_feeds = set(), []
            for feeds in d.RSS_FEEDS.values():
                for url, source, cat, sev in feeds:
                    if url not in seen_urls:
                        seen_urls.add(url); news_feeds.append((url, source, cat, sev))
            news_tasks = [d.fetch_rss(u, s, c, v, 12) for u, s, c, v in news_feeds]
            cve_tasks = [d.fetch_cve_rss(u, s, c) for u, s, c in d.CVE_FEEDS]
            results = await _asyncio.gather(*news_tasks, *cve_tasks, return_exceptions=True)
            items, feeds = [], []
            for (u, s, _c, _v), r in zip(news_feeds, results[:len(news_feeds)]):
                ok = isinstance(r, list) and len(r) > 0
                feeds.append({"source": s, "ok": ok, "count": len(r) if isinstance(r, list) else 0,
                              "error": None if ok else (str(r)[:120] if isinstance(r, Exception) else "no items")})
                if isinstance(r, list):
                    items.extend({**x, "kind": "news"} for x in r)
            for (u, s, _c), r in zip(d.CVE_FEEDS, results[len(news_feeds):]):
                if isinstance(r, dict):
                    feeds.append({"source": s, "ok": r.get("ok"), "count": len(r.get("items", [])), "error": r.get("error")})
                    items.extend({**x, "summary": x.get("description", ""), "kind": "advisory"} for x in r.get("items", []))
                else:
                    feeds.append({"source": s, "ok": False, "count": 0, "error": str(r)[:120]})
            out, seen = [], set()
            for it in sorted(items, key=lambda x: x.get("date") or "", reverse=True):
                key = re.sub(r"\W+", "", (it.get("title") or "").lower())[:80]
                if not key or key in seen:
                    continue
                seen.add(key)
                cat, sev, cves, actors = _classify(it)
                out.append({"title": it.get("title"), "summary": it.get("summary") or "", "url": it.get("url"),
                            "source": it.get("source"), "date": it.get("date"), "category": cat, "severity": sev,
                            "cves": cves, "actors": actors, "kind": it["kind"],
                            "id": uuid.uuid5(uuid.NAMESPACE_URL, it.get("url") or key).hex[:16]})
            payload = {"items": out[:150], "feeds": feeds, "fetched_at": now.isoformat()}
            _wall_cache.update(at=now, payload=payload)

        # Per-request enrichment against the analyst's own data (not cached —
        # it depends on who is asking and on what is monitored right now).
        items = [dict(x) for x in payload["items"]]
        if "data.workspace" in d.effective_caps(user, conn):
            all_cves = sorted({c for x in items for c in x["cves"]})
            tracked = {}
            if all_cves:
                cur = _dict_cur(conn)
                cur.execute("""SELECT DISTINCT ON (cf.cve_id) cf.cve_id, a.name AS asset_name, a.id AS asset_id, cf.kev_listed
                    FROM cve_findings cf LEFT JOIN assets a ON a.id=cf.asset_id WHERE cf.cve_id = ANY(%s)""", (all_cves,))
                tracked = {r["cve_id"]: r for r in cur.fetchall()}
            for x in items:
                hits = [tracked[c] for c in x["cves"] if c in tracked]
                x["affects"] = [{"cve_id": h["cve_id"], "asset_id": h["asset_id"], "asset_name": h["asset_name"]} for h in hits]
        counts = {}
        for x in items:
            counts[x["category"]] = counts.get(x["category"], 0) + 1
        return {**payload, "items": items, "counts": counts}

    # ══════════════════════════════════════════════════════════════════════
    # API USAGE
    # ══════════════════════════════════════════════════════════════════════
    @app.get("/v2/api-usage")
    def v2_api_usage(days: int = 14, user=Depends(admin), conn=Depends(get_db)):
        days = max(1, min(days, 60))
        cur = _dict_cur(conn)
        cur.execute("""SELECT created_at::date AS d, api_name, cache_hit, COUNT(*) AS n FROM api_usage_log
            WHERE created_at >= CURRENT_DATE - %s GROUP BY 1,2,3""", (days - 1,))
        rows = cur.fetchall()
        today = datetime.now(timezone.utc).date()
        labels = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
        services, cache = {}, {k: 0 for k in labels}
        for r in rows:
            k = r["d"].isoformat()
            if r["cache_hit"]:
                cache[k] = cache.get(k, 0) + int(r["n"])
            else:
                services.setdefault(r["api_name"], {})[k] = int(r["n"])
        cur.execute("""SELECT u.username, l.api_name, COUNT(*) AS n FROM api_usage_log l
            LEFT JOIN users u ON u.id=l.user_id
            WHERE l.created_at >= CURRENT_DATE - %s AND l.cache_hit=FALSE
            GROUP BY 1,2 ORDER BY n DESC LIMIT 30""", (days - 1,))
        by_user = cur.fetchall()
        return {"days": labels,
                "services": [{"name": s, "values": [v.get(k, 0) for k in labels], "total": sum(v.values())}
                             for s, v in sorted(services.items(), key=lambda kv: -sum(kv[1].values()))],
                "cache_hits": [cache.get(k, 0) for k in labels], "by_user": by_user}
