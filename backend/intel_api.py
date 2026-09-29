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


from entities import (  # noqa: E402  (shared SQL fragments live with the entity model)
    SOURCE_SQL, STATUS_SQL, ACTIVE_SQL, SEV_SQL, SEVERITY_SQL, UNPATCHED_SQL, GENERIC_TAGS, like_escape)
import entities
import migrations
import security

IOC_SORTS = {
    "created": "i.created_at", "last_seen": "COALESCE(i.last_seen, i.created_at)",
    "confidence": "i.confidence", "type": "i.type", "value": "i.value",
    "tlp": "i.tlp", "source": SOURCE_SQL, "status": STATUS_SQL,
}

TYPE_GROUPS = {
    "ip": ("IPv4", "IPv6"), "domain": ("Domain",), "url": ("URL",),
    "hash": ("MD5", "SHA1", "SHA256"), "email": ("Email",),
}

# An IOC counts as enriched only when an upstream actually answered; connector
# rows carry an `enriched_at` stamp without ever having been looked up.
_UPSTREAMS = ("virustotal", "abuseipdb", "urlhaus")
ENRICHED_SQL = "(" + " OR ".join(
    f"(i.enrichment->'{u}' IS NOT NULL AND i.enrichment->'{u}'->>'skipped' IS NULL AND i.enrichment->'{u}'->>'error' IS NULL)"
    for u in _UPSTREAMS) + ")"
ENRICH_ERROR_SQL = "(" + " OR ".join(f"i.enrichment->'{u}'->>'error' IS NOT NULL" for u in _UPSTREAMS) + ")"
ENRICH_STATE_SQL = (f"CASE WHEN {ENRICH_ERROR_SQL} THEN 'error' WHEN {ENRICHED_SQL} THEN 'enriched' ELSE 'not_enriched' END")

LIVE_STATUSES = ("active", "suspicious", "confirmed", "unknown")


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
    action: str                      # assign_campaign | add_tag | mark_fp | unmark_fp | set_status | add_to_investigation
    campaign_id: Optional[str] = None
    status: Optional[str] = None
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

    entities.configure(d.detect_type, d.refang)

    @app.on_event("startup")
    async def _intel_schema():
        migrations.run_migrations(d.get_db_direct)

    # ══════════════════════════════════════════════════════════════════════
    # IOC INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════════
    def ioc_filters(q: str = "", type: str = "", tlp: str = "", source: str = "", tag: str = "",
                    campaign_id: str = "", malware: str = "", min_conf: int = 0, status: str = "live",
                    severity: str = "", enrichment: str = "", since_days: int = 0, last_seen_days: int = 0,
                    expiring_days: int = 0, analyst: str = "", has_campaign: bool = False):
        """Shared filter set for the IOC table and its facet counts."""
        return dict(q=q, type=type, tlp=tlp, source=source, tag=tag, campaign_id=campaign_id, malware=malware,
                    min_conf=min_conf, status=status, severity=severity, enrichment=enrichment,
                    since_days=since_days, last_seen_days=last_seen_days, expiring_days=expiring_days,
                    analyst=analyst, has_campaign=has_campaign)

    def _ioc_where(f):
        where, params = ["1=1"], []
        q = (f.get("q") or "").strip()
        if q:
            norm = d.refang(q)
            esc = like_escape(norm)
            where.append("""(i.value ILIKE %s ESCAPE '\\' OR i.value_defanged ILIKE %s ESCAPE '\\' OR i.description ILIKE %s ESCAPE '\\'
                             OR %s = ANY(i.tags) OR i.enrichment->>'malware_family' ILIKE %s ESCAPE '\\')""")
            params += [f"%{esc}%", f"%{like_escape(q)}%", f"%{like_escape(q)}%", q.lower(), f"%{like_escape(q)}%"]
        if f.get("type"):
            types = []
            for t in f["type"].split(","):
                types.extend(TYPE_GROUPS.get(t.lower(), (t,)))
            where.append("i.type = ANY(%s)"); params.append(types)
        if f.get("tlp"):
            where.append("i.tlp = ANY(%s)"); params.append(f["tlp"].upper().split(","))
        if f.get("source"):
            where.append(f"{SOURCE_SQL} = ANY(%s)"); params.append(f["source"].split(","))
        if f.get("tag"):
            where.append("%s = ANY(i.tags)"); params.append(f["tag"])
        if f.get("campaign_id"):
            where.append("i.campaign_id = %s"); params.append(f["campaign_id"])
        if f.get("has_campaign"):
            where.append("i.campaign_id IS NOT NULL")
        if f.get("malware"):
            where.append("LOWER(i.enrichment->>'malware_family') = LOWER(%s)"); params.append(f["malware"])
        if f.get("min_conf"):
            where.append("i.confidence >= %s"); params.append(f["min_conf"])
        if f.get("severity"):
            where.append(f"{SEVERITY_SQL} = ANY(%s)"); params.append(f["severity"].lower().split(","))
        if f.get("analyst"):
            where.append("u.username = %s"); params.append(f["analyst"])
        if f.get("since_days"):
            where.append("i.created_at >= NOW() - (%s || ' days')::interval"); params.append(str(int(f["since_days"])))
        if f.get("last_seen_days"):
            where.append("COALESCE(i.last_seen, i.created_at) >= NOW() - (%s || ' days')::interval")
            params.append(str(int(f["last_seen_days"])))
        if f.get("expiring_days"):
            where.append("i.valid_until IS NOT NULL AND i.valid_until > NOW() AND i.valid_until <= NOW() + (%s || ' days')::interval")
            params.append(str(int(f["expiring_days"])))
        es = f.get("enrichment")
        if es == "enriched":
            where.append(ENRICHED_SQL)
        elif es == "error":
            where.append(ENRICH_ERROR_SQL)
        elif es == "not_enriched":
            where.append(f"NOT {ENRICHED_SQL} AND NOT {ENRICH_ERROR_SQL}")
        st = f.get("status") or "live"
        if st == "live":
            where.append(f"{STATUS_SQL} = ANY(%s)"); params.append(list(LIVE_STATUSES))
        elif st != "all":
            where.append(f"{STATUS_SQL} = ANY(%s)"); params.append(st.split(","))
        return where, params

    _FROM = """FROM iocs i LEFT JOIN users u ON i.created_by = u.id LEFT JOIN campaigns c ON i.campaign_id = c.id"""

    @app.get("/v2/iocs")
    def v2_list_iocs(f: dict = Depends(ioc_filters), sort: str = "created", dir: str = "desc",
                     limit: int = 50, offset: int = 0, user=Depends(full), conn=Depends(get_db)):
        limit = max(1, min(limit, 500)); offset = max(0, offset)
        where, params = _ioc_where(f)
        order = IOC_SORTS.get(sort, "i.created_at")
        direction = "ASC" if dir.lower() == "asc" else "DESC"
        base = f"{_FROM} WHERE {' AND '.join(where)}"
        cur = _dict_cur(conn)
        cur.execute(f"""SELECT i.id, i.type, i.value, i.value_defanged, i.industry, i.tlp, i.confidence,
                i.description, i.tags, i.created_by, i.valid_until, i.false_positive, i.fp_reason, i.analyst_status,
                i.mitre_techniques, i.campaign_id, i.created_at,
                COALESCE(i.last_seen, i.created_at) AS last_seen,
                u.username AS author, c.name AS campaign_name, c.threat_actor,
                {SOURCE_SQL} AS source, {STATUS_SQL} AS status, {SEVERITY_SQL} AS severity,
                {ENRICH_STATE_SQL} AS enrichment_state,
                i.enrichment->>'malware_family' AS malware_family,
                COALESCE(i.enrichment->'abuseipdb'->>'country', i.enrichment->'virustotal'->>'country') AS country
            {base} ORDER BY {order} {direction} NULLS LAST, i.id LIMIT %s OFFSET %s""",
            params + [limit, offset])
        items = cur.fetchall()
        cur.execute(f"SELECT COUNT(*) AS n {base}", params)
        return {"items": items, "total": cur.fetchone()["n"], "limit": limit, "offset": offset}

    @app.get("/v2/iocs/facets")
    def v2_ioc_facets(f: dict = Depends(ioc_filters), user=Depends(full), conn=Depends(get_db)):
        """Counts for the current filter set. A separate call so paging and
        sorting never re-run three GROUP BYs over the whole filtered set."""
        where, params = _ioc_where(f)
        base = f"{_FROM} WHERE {' AND '.join(where)}"
        cur = _dict_cur(conn)
        cur.execute(f"SELECT i.type AS k, COUNT(*) AS n {base} GROUP BY i.type ORDER BY n DESC", params)
        types = cur.fetchall()
        cur.execute(f"SELECT {SOURCE_SQL} AS k, COUNT(*) AS n {base} GROUP BY 1 ORDER BY n DESC LIMIT 12", params)
        sources = cur.fetchall()
        cur.execute(f"SELECT {STATUS_SQL} AS k, COUNT(*) AS n {base} GROUP BY 1 ORDER BY n DESC", params)
        statuses = cur.fetchall()
        cur.execute(f"SELECT {SEVERITY_SQL} AS k, COUNT(*) AS n {base} GROUP BY 1", params)
        severities = cur.fetchall()
        return {"types": types, "sources": sources, "status": statuses, "severity": severities}

    @app.get("/v2/iocs/filter-options")
    def v2_ioc_filter_options(user=Depends(full), conn=Depends(get_db)):
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
        elif body.action == "set_status":
            # Triage verdicts only; false positives keep their own action (ownership rules).
            if body.status not in ("active",) + entities.ANALYST_STATUSES:
                raise HTTPException(400, "status must be one of active, suspicious, confirmed, unknown")
            # Lifting a false-positive flag follows the same ownership rule as setting it.
            cur.execute("""UPDATE iocs SET false_positive=FALSE, fp_reason=NULL, analyst_status=%s
                           WHERE id = ANY(%s) AND (NOT COALESCE(false_positive, FALSE) OR %s OR created_by = %s)
                           RETURNING value""", (None if body.status == "active" else body.status, ids, is_admin, user["id"]))
            for r in cur.fetchall():
                entities.record_observation(conn, "indicator", entities.normalize_indicator(r["value"])[0], "status_change",
                                            f"analyst:{user['username']}", "analyst", actor=user["username"],
                                            summary=f"Status set to {body.status} (bulk)")
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
    # COMMAND CENTER
    # ══════════════════════════════════════════════════════════════════════
    def _series(cur, sql, params, days):
        cur.execute(sql, params)
        found = {r["d"].isoformat(): int(r["n"]) for r in cur.fetchall()}
        today = datetime.now(timezone.utc).date()
        return [found.get((today - timedelta(days=i)).isoformat(), 0) for i in range(days - 1, -1, -1)]

    @app.get("/v2/cve/summary")
    def v2_cve_summary(user=Depends(full), conn=Depends(get_db)):
        """The CVE page's KPI strip. Kept apart from /v2/command-center, whose
        dozens of aggregates the CVE page never needed."""
        cur = _dict_cur(conn)
        cur.execute(f"""SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE {UNPATCHED_SQL}) AS unpatched,
                COUNT(*) FILTER (WHERE cf.patch_available) AS patched,
                COUNT(*) FILTER (WHERE cf.kev_listed) AS kev,
                COUNT(*) FILTER (WHERE cf.kev_listed AND {UNPATCHED_SQL}) AS kev_unpatched,
                COUNT(*) FILTER (WHERE {SEV_SQL}='CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE {SEV_SQL}='HIGH') AS high,
                COUNT(*) FILTER (WHERE {SEV_SQL}='MEDIUM') AS medium
            FROM cve_findings cf""")
        return cur.fetchone()

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

    def _add_item(conn, inv_id, item_type, ref_id, value, label, data, user, reason=None):
        cur = conn.cursor()
        key = ref_id or value
        cur.execute("""SELECT 1 FROM investigation_items WHERE investigation_id=%s AND item_type=%s
                       AND COALESCE(ref_id, value)=%s""", (inv_id, item_type, key))
        if cur.fetchone():
            return False
        cur.execute("""INSERT INTO investigation_items (investigation_id, item_type, ref_id, value, label, data, created_by, reason)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (inv_id, item_type, ref_id, value, label, psycopg2.extras.Json(data or {}), user.get("username"), reason))
        return True

    def _item_entity(it):
        """(kind, ref) an investigation item stands for — how the UI opens it."""
        t = it["item_type"]
        if t in ("ioc", "observable"):
            v = it.get("ioc_value") or it.get("value")
            return ("indicator", entities.normalize_indicator(v)[0]) if v else None
        if t == "asset":
            return ("software", it.get("ref_id"))
        if t in ("cve", "campaign", "actor", "malware"):
            return (t, it.get("ref_id") or it.get("value"))
        return None

    @app.get("/v2/investigations")
    def v2_investigations(status: str = "", q: str = "", user=Depends(full), conn=Depends(get_db)):
        cur = _dict_cur(conn)
        where, params = ["1=1"], []
        if status:
            where.append("inv.status = ANY(%s)"); params.append(status.split(","))
        if q:
            where.append("(inv.name ILIKE %s ESCAPE '\\' OR inv.description ILIKE %s ESCAPE '\\')")
            params += [f"%{like_escape(q)}%", f"%{like_escape(q)}%"]
        cur.execute(f"""SELECT inv.*,
                (SELECT COUNT(*) FROM investigation_items it WHERE it.investigation_id=inv.id AND it.item_type IN ('ioc','observable')) AS iocs,
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
        for it in items:
            ent = _item_entity(it)
            it["entity"] = {"kind": ent[0], "ref": ent[1]} if ent and ent[1] else None
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

    TAG_RX = {
        "zero-day": re.compile(r"zero[- ]day|0[- ]day", re.I),
        "actively-exploited": re.compile(r"actively exploited|exploited in the wild|under active exploitation|\bkev\b", re.I),
        "phishing": re.compile(r"phishing|spear-?phish|credential harvest", re.I),
        "supply-chain": re.compile(r"supply[- ]chain|npm|pypi|malicious package|typosquat", re.I),
        "data-breach": re.compile(r"data breach|leaked|exposed database|stolen data", re.I),
        "patch": re.compile(r"security update|patch(es|ed)?\b|fixes? (a )?vulnerab", re.I),
        "espionage": re.compile(r"espionage|state[- ]sponsored|nation[- ]state", re.I),
    }
    _IND_RX = re.compile(
        r"\b(?:\d{1,3}(?:\[?\.\]?\d{1,3}){3}|[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32}"
        r"|(?:[a-z0-9-]{1,63}(?:\[?\.\]?))+[a-z]{2,24})\b", re.I)
    _known = {"at": None, "rx": None, "map": None}

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
        tags = [t for t, rx in TAG_RX.items() if rx.search(text)]
        return cat, sev, cves, tags

    def _known_entities(conn):
        """Names TFII actually knows (60s cache): threat actors from campaigns, malware
        families from indicators, monitored software. News is matched against these,
        so a link means 'this exists in your data', plus a small dictionary of
        well-known actor names for items about actors you have not attributed yet."""
        now = datetime.now(timezone.utc)
        if _known["at"] and (now - _known["at"]).total_seconds() < 60:
            return _known["rx"], _known["map"]
        cur = _dict_cur(conn)
        mp = {}
        cur.execute("SELECT DISTINCT threat_actor AS n FROM campaigns WHERE COALESCE(threat_actor,'') <> ''")
        for r in cur.fetchall():
            mp[r["n"].lower()] = ("actor", r["n"], None)
        for a in ACTORS:
            mp.setdefault(a.lower(), ("actor", a, None))
        cur.execute("""SELECT enrichment->>'malware_family' AS n, COUNT(*) AS c FROM iocs
            WHERE COALESCE(enrichment->>'malware_family','') NOT IN ('','unknown') GROUP BY 1 ORDER BY c DESC LIMIT 300""")
        for r in cur.fetchall():
            if len(r["n"]) >= 4:
                mp.setdefault(r["n"].lower(), ("malware", r["n"], None))
        cur.execute("SELECT id, name, vendor FROM assets WHERE active = TRUE")
        for r in cur.fetchall():
            if len(r["name"]) >= 3:
                mp.setdefault(r["name"].lower(), ("software", r["name"], r["id"]))
        names = sorted(mp, key=len, reverse=True)[:800]
        rx = re.compile(r"(?<![\w-])(" + "|".join(re.escape(n) for n in names) + r")(?![\w-])", re.I) if names else None
        _known.update(at=now, rx=rx, map=mp)
        return rx, mp

    def _entities_for(conn, items):
        """Attach the entities each item is genuinely about: CVEs, actors, malware,
        monitored software and tracked indicators mentioned in the text."""
        rx, mp = _known_entities(conn)
        cands = set()
        for x in items:
            text = f"{x['title']} {x['summary']}"
            found, seen = [], set()
            if rx:
                for m in rx.finditer(text):
                    k, name, ref = mp[m.group(1).lower()]
                    key = (k, name.lower())
                    if key not in seen:
                        seen.add(key)
                        found.append({"kind": k, "ref": ref or name, "label": name})
            for c in x["cves"]:
                found.append({"kind": "cve", "ref": c, "label": c})
            x["entities"] = found[:14]
            x["_text"] = text
            for m in _IND_RX.findall(text)[:12]:
                cands.add(entities.normalize_indicator(m)[0].lower())
        tracked = {}
        if cands:
            cur = _dict_cur(conn)
            cur.execute("SELECT id, type, value FROM iocs WHERE LOWER(value) = ANY(%s) LIMIT 300", (list(cands)[:400],))
            tracked = {r["value"].lower(): r for r in cur.fetchall()}
        for x in items:
            if tracked:
                for m in _IND_RX.findall(x.pop("_text", "")):
                    row = tracked.get(entities.normalize_indicator(m)[0].lower())
                    if row and not any(e["kind"] == "indicator" and e["ref"].lower() == row["value"].lower() for e in x["entities"]):
                        x["entities"].append({"kind": "indicator", "ref": entities.normalize_indicator(row["value"])[0],
                                              "label": row["value"], "id": row["id"], "type": row["type"]})
            x.pop("_text", None)

    def _fetch_wall():
        seen_urls, news_feeds = set(), []
        for feeds in d.RSS_FEEDS.values():
            for url, source, cat, sev in feeds:
                if url not in seen_urls:
                    seen_urls.add(url); news_feeds.append((url, source, cat, sev))
        return news_feeds

    @app.get("/v2/intel-wall")
    async def v2_intel_wall(refresh: bool = False, entity_kind: str = "", entity_ref: str = "",
                            user=Depends(current), conn=Depends(get_db)):
        now = datetime.now(timezone.utc)
        cached = _wall_cache["payload"]
        if not refresh and cached and _wall_cache["at"] and (now - _wall_cache["at"]).total_seconds() < 900:
            payload = cached
        else:
            news_feeds = _fetch_wall()
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
                cat, sev, cves, tags = _classify(it)
                out.append({"title": it.get("title"), "summary": it.get("summary") or "",
                            # Feed URLs are third-party data: only plain http(s) may become a link.
                            "url": security.safe_http_url(it.get("url")),
                            "source": it.get("source"), "date": it.get("date"), "category": cat, "severity": sev,
                            "cves": cves, "tags": tags, "kind": it["kind"],
                            "id": uuid.uuid5(uuid.NAMESPACE_URL, it.get("url") or key).hex[:16]})
            payload = {"items": out[:150], "feeds": feeds, "fetched_at": now.isoformat()}
            _wall_cache.update(at=now, payload=payload)

        # Per-request enrichment against the analyst's own data (not cached —
        # it depends on who is asking and on what is monitored right now).
        items = [dict(x) for x in payload["items"]]
        if "data.workspace" in d.effective_caps(user, conn):
            _entities_for(conn, items)
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
        else:
            for x in items:
                x["entities"] = [{"kind": "cve", "ref": c, "label": c} for c in x["cves"]]
                x["affects"] = []
        if entity_kind and entity_ref:
            want = (entity_kind, entity_ref.lower())
            items = [x for x in items if any((e["kind"], e["ref"].lower()) == want or
                                             (e["kind"] == entity_kind and e["label"].lower() == entity_ref.lower())
                                             for e in x["entities"])]
        counts, ent_counts = {}, {}
        for x in items:
            counts[x["category"]] = counts.get(x["category"], 0) + 1
            for k in {e["kind"] for e in x["entities"]}:
                ent_counts[k] = ent_counts.get(k, 0) + 1
        return {**payload, "items": items, "counts": counts, "entity_counts": ent_counts}

    import entity_api
    helpers = {"add_item": _add_item, "event": _event, "get_investigation": _get_investigation}
    entity_api.register(app, d, helpers)

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
