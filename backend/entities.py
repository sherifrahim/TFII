"""
TFII Intelligence Core — entity, relationship, observation and timeline services.

The model, in one paragraph
---------------------------
An *entity* is a (kind, ref) pair: indicator (ref = normalised value), cve,
malware, actor, campaign, software (ref = asset id) or investigation. Most
entities already exist as rows or as values inside rows (a malware family is a
string on IOC enrichment; an actor is a string on a campaign), so the core does
not copy them into a new table. It adds only what did not exist:

* `entity_relationships` — typed edges an analyst or an importer asserted, each
  with its own source/provenance;
* `entity_observations`  — what a source told us, when, and how confident it
  was ("why does TFII believe this?");
* derived relationships and timeline events, computed on read from real columns
  (campaign_id, enrichment.malware_family, cve_findings, investigation_items,
  timestamps). Nothing is invented: if no column or row supports a link, no link
  is shown.

Modules layer as  security ← entities ← search ← intel_api ← main.  This module
never imports main; the two host helpers it needs are injected via configure().
"""
import ipaddress
import re
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

from migrations import URL_HOST_SQL

KINDS = ("indicator", "cve", "malware", "actor", "campaign", "software", "investigation")

_cfg = {"detect_type": lambda v: "Unknown", "refang": lambda v: v}


def configure(detect_type, refang):
    _cfg["detect_type"] = detect_type
    _cfg["refang"] = refang


# ── Shared SQL fragments ──────────────────────────────────────────────────────
# Where an indicator came from: connectors write enrichment.source; bulk lookup
# leaves a tag; everything else was typed in by an analyst.
SOURCE_SQL = """COALESCE(NULLIF(i.enrichment->>'source',''),
    CASE WHEN 'bulk-lookup' = ANY(i.tags) THEN 'Bulk Lookup' ELSE 'Manual' END)"""

# One status for the analyst: lifecycle states are derived (expired / false
# positive) and win over the analyst's triage verdict; NULL verdict = "active".
STATUS_SQL = """CASE WHEN i.false_positive THEN 'false_positive'
    WHEN i.valid_until IS NOT NULL AND i.valid_until <= NOW() THEN 'expired'
    WHEN i.analyst_status IS NOT NULL THEN i.analyst_status
    ELSE 'active' END"""

ACTIVE_SQL = """(i.valid_until IS NULL OR i.valid_until > NOW())
    AND (i.false_positive IS NULL OR i.false_positive = FALSE)"""

# Severity bands mirror the UI (and the v1 confidence bands): the platform's
# only score is confidence, so severity IS the confidence band — not a second,
# invented number.
SEVERITY_SQL = """CASE WHEN i.confidence >= 90 THEN 'critical' WHEN i.confidence >= 75 THEN 'high'
    WHEN i.confidence >= 50 THEN 'medium' ELSE 'low' END"""

SEV_SQL = """CASE
    WHEN UPPER(COALESCE(cf.cvss_severity,'')) IN ('CRITICAL','HIGH','MEDIUM','LOW') THEN UPPER(cf.cvss_severity)
    WHEN cf.cvss_score >= 9 THEN 'CRITICAL' WHEN cf.cvss_score >= 7 THEN 'HIGH'
    WHEN cf.cvss_score >= 4 THEN 'MEDIUM' WHEN cf.cvss_score > 0 THEN 'LOW'
    ELSE 'NONE' END"""

UNPATCHED_SQL = "(cf.patch_available = FALSE OR cf.patch_available IS NULL)"

ANALYST_STATUSES = ("suspicious", "confirmed", "unknown")
# Statuses an analyst may choose. "active" clears the verdict; false_positive
# uses the existing flag so v1 exports keep excluding those rows.
SETTABLE_STATUSES = ("active",) + ANALYST_STATUSES + ("false_positive",)

GENERIC_TAGS = {"connector", "threatfox", "malwarebazaar", "urlhaus", "bulk-lookup",
                "malicious", "suspicious", "clean", "unknown", "malware-hash", "malware-url"}

# ── Relationship vocabulary ───────────────────────────────────────────────────
# rel_type: (label when this entity is the source, label when it is the target)
REL_TYPES = {
    "resolves_to":       ("Resolves to", "Resolved by"),
    "hosts":             ("Hosts", "Hosted on"),
    "associated_with":   ("Associated with", "Associated with"),
    "used_by":           ("Used by", "Uses"),
    "uses":              ("Uses", "Used by"),
    "operates_campaign": ("Operates", "Operated by"),
    "attributed_to":     ("Attributed to", "Attributed campaigns"),
    "part_of":           ("Part of", "Includes"),
    "affects":           ("Affects", "Affected by"),
    "observed_in":       ("Observed in", "Observed here"),
    "appears_in":        ("Appears in", "Includes"),
    "related_to":        ("Related to", "Related to"),
    "communicates_with": ("Communicates with", "Contacted by"),
    "dropped_by":        ("Dropped by", "Drops"),
    "delivers":          ("Delivers", "Delivered by"),
    "variant_of":        ("Variant of", "Has variant"),
}
# Legacy ioc_relationships values that are not in the vocabulary map to it.
LEGACY_REL_ALIASES = {"indicates": "associated_with"}

GROUP_ORDER = ["resolves_to", "hosts", "communicates_with", "delivers", "dropped_by", "associated_with",
               "used_by", "uses", "operates_campaign", "attributed_to", "part_of", "affects", "related_to",
               "variant_of", "observed_in", "appears_in"]


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def q(conn, sql, params=(), one=False):
    cur = _cur(conn)
    cur.execute(sql, params)
    return cur.fetchone() if one else cur.fetchall()


def like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def utc(dt):
    """Postgres TIMESTAMP is naive UTC; return ISO with Z so browsers agree."""
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    return dt.replace(tzinfo=None).isoformat() + "Z"


# ── Indicator identity ────────────────────────────────────────────────────────
def normalize_indicator(raw: str):
    """(key, type). The key is what edges and observations are stored under."""
    v = _cfg["refang"]((raw or "").strip())
    t = _cfg["detect_type"](v)
    if t in ("IPv4", "IPv6"):
        try:
            v = str(ipaddress.ip_address(v))
        except ValueError:
            pass
    elif t == "URL":
        v = re.sub(r"^(https?://)([^/?#]*)", lambda m: m.group(1).lower() + m.group(2).lower(), v, flags=re.I)
    elif t in ("Domain", "MD5", "SHA1", "SHA256", "Email"):
        v = v.lower()
    return v, t


def url_host(url: str):
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/@?#]*@)?(\[[0-9a-fA-F:.]+\]|[^/:?#]+)", url or "")
    return m.group(1).strip("[]").lower() if m else None


def find_ioc(conn, key: str):
    """The tracked IOC row for a normalised value (or None). An exact match wins;
    a case-insensitive match is accepted only if unambiguous, so two URLs that
    differ only in path case are never conflated."""
    rows = q(conn, f"""SELECT i.*, u.username AS author, c.name AS campaign_name, c.threat_actor,
            {SOURCE_SQL} AS source, {STATUS_SQL} AS status, {SEVERITY_SQL} AS severity,
            COALESCE(i.last_seen, i.created_at) AS last_seen_at
        FROM iocs i LEFT JOIN users u ON u.id = i.created_by LEFT JOIN campaigns c ON c.id = i.campaign_id
        WHERE LOWER(i.value) = LOWER(%s) ORDER BY (i.value = %s) DESC, i.created_at ASC LIMIT 5""", (key, key))
    if not rows:
        return None
    if rows[0]["value"] == key or len(rows) == 1:
        return rows[0]
    return None


def ioc_by_id(conn, ioc_id: str):
    return q(conn, f"""SELECT i.*, u.username AS author, c.name AS campaign_name, c.threat_actor,
            {SOURCE_SQL} AS source, {STATUS_SQL} AS status, {SEVERITY_SQL} AS severity,
            COALESCE(i.last_seen, i.created_at) AS last_seen_at
        FROM iocs i LEFT JOIN users u ON u.id = i.created_by LEFT JOIN campaigns c ON c.id = i.campaign_id
        WHERE i.id = %s""", (ioc_id,), one=True)


def resolve_ref(conn, kind: str, ref: str):
    """Accept whatever a route carries. For indicators that may be an IOC row id
    (indicator--uuid), a value, or a defanged value; return the canonical ref."""
    if kind == "indicator":
        if (ref or "").startswith("indicator--"):
            r = ioc_by_id(conn, ref)
            if r:
                return normalize_indicator(r["value"])[0]
        return normalize_indicator(ref)[0]
    if kind == "cve":
        return (ref or "").upper().strip()
    return (ref or "").strip()


# ── Provenance ────────────────────────────────────────────────────────────────
def record_observation(conn, kind, ref, obs_type, source, source_type, *, source_ref=None,
                       observed_at=None, confidence=None, actor=None, summary=None, data=None):
    """Best-effort write of one observation. It must never break the caller's own
    transaction, so it runs inside a savepoint."""
    cur = conn.cursor()
    try:
        cur.execute("SAVEPOINT obs")
        cur.execute("""INSERT INTO entity_observations
            (entity_kind, entity_ref, obs_type, source, source_type, source_ref, observed_at,
             confidence, actor, summary, data)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (kind, ref, obs_type, source[:100], source_type, source_ref, observed_at, confidence,
             actor, (summary or "")[:500], psycopg2.extras.Json(data or {})))
        cur.execute("RELEASE SAVEPOINT obs")
        return True
    except Exception as e:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT obs")
        except Exception:
            pass
        print(f"[entities] observation not recorded: {str(e).splitlines()[0][:120]}")
        return False


ENRICH_SOURCES = (("virustotal", "VirusTotal"), ("abuseipdb", "AbuseIPDB"), ("urlhaus", "URLhaus"))


def enrichment_summaries(enrichment: dict):
    """One (source, summary, link, confidence) per upstream that actually answered."""
    out = []
    if not isinstance(enrichment, dict):
        return out
    vt, ab, uh = (enrichment.get(k) or {} for k, _ in ENRICH_SOURCES)
    if vt and not vt.get("skipped") and not vt.get("error") and vt.get("total") is not None:
        out.append(("VirusTotal", f"{vt.get('malicious', 0)}/{vt.get('total')} engines flagged malicious",
                    vt.get("link"), vt.get("vt_score")))
    if ab and not ab.get("skipped") and not ab.get("error") and ab.get("abuse_score") is not None:
        out.append(("AbuseIPDB", f"abuse confidence {ab.get('abuse_score')}/100, {ab.get('total_reports', 0)} reports",
                    ab.get("link"), ab.get("abuse_score")))
    if uh and not uh.get("skipped") and not uh.get("error") and uh.get("found") is not None:
        out.append(("URLhaus", (f"listed: {uh.get('threat') or 'malware distribution'}"
                                + (f" ({uh.get('url_status')})" if uh.get("url_status") else ""))
                    if uh.get("found") else "not listed", uh.get("link"), None))
    return out


def record_enrichment(conn, key, enrichment, actor=None):
    for source, summary, link, conf in enrichment_summaries(enrichment):
        record_observation(conn, "indicator", key, "enrichment", source, "enrichment", source_ref=link,
                           observed_at=datetime.now(timezone.utc).replace(tzinfo=None), confidence=conf,
                           actor=actor, summary=summary)


def touch_seen(conn, ioc_id):
    conn.cursor().execute("UPDATE iocs SET last_seen = NOW() WHERE id = %s", (ioc_id,))


# ── Item builders ─────────────────────────────────────────────────────────────
def ind_item(row, **kw):
    key = normalize_indicator(row["value"])[0]
    return {"kind": "indicator", "ref": key, "id": row["id"], "label": row.get("value_defanged") or row["value"],
            "value": row["value"], "type": row["type"], "tracked": True, "confidence": row.get("confidence"), **kw}


def untracked_item(value, type_=None, **kw):
    key, t = normalize_indicator(value)
    return {"kind": "indicator", "ref": key, "id": None, "label": value, "value": key,
            "type": type_ or t, "tracked": False, **kw}


def entity_key(item):
    k, r = item["kind"], item["ref"]
    return f"{k}:{(r or '').lower()}"


# ── Headers ───────────────────────────────────────────────────────────────────
def header(conn, kind, ref):
    """Uniform header for any entity kind, or None when it does not exist."""
    if kind == "indicator":
        row = find_ioc(conn, ref)
        key, t = normalize_indicator(ref)
        if not row:
            return {"kind": kind, "ref": key, "id": None, "tracked": False, "type": t, "title": key, "value": key,
                    "status": "untracked", "confidence": None, "first_seen": None, "last_seen": None, "tags": []}
        fam = (row.get("enrichment") or {}).get("malware_family") if isinstance(row.get("enrichment"), dict) else None
        return {"kind": kind, "ref": normalize_indicator(row["value"])[0], "id": row["id"], "tracked": True,
                "type": row["type"], "title": row["value"], "value": row["value"], "status": row["status"],
                "confidence": row["confidence"], "severity": row["severity"], "tlp": row["tlp"],
                "first_seen": utc(row["created_at"]), "last_seen": utc(row["last_seen_at"]),
                "tags": row.get("tags") or [], "source": row["source"], "author": row.get("author"),
                "campaign_id": row.get("campaign_id"), "campaign_name": row.get("campaign_name"),
                "threat_actor": row.get("threat_actor"), "malware_family": fam if fam and fam != "unknown" else None,
                "valid_until": utc(row.get("valid_until")), "defanged": row.get("value_defanged"),
                "description": row.get("description")}
    if kind == "cve":
        r = q(conn, f"""SELECT COUNT(*) AS n, MIN(cf.created_at) AS first_tracked,
                MAX(cf.cvss_score) AS cvss, BOOL_OR(cf.kev_listed) AS kev, MAX(cf.kev_date) AS kev_date,
                MAX(cf.epss_score) AS epss, MIN(cf.published_date) AS published, MAX(cf.modified_date) AS modified,
                (ARRAY_AGG(cf.title ORDER BY cf.cvss_score DESC NULLS LAST))[1] AS title,
                (ARRAY_AGG({SEV_SQL} ORDER BY cf.cvss_score DESC NULLS LAST))[1] AS severity
            FROM cve_findings cf WHERE cf.cve_id = %s""", (ref,), one=True)
        if not r or not r["n"]:
            return {"kind": kind, "ref": ref, "id": None, "tracked": False, "type": "CVE", "title": ref, "value": ref,
                    "status": "untracked", "confidence": None, "first_seen": None, "last_seen": None, "tags": []}
        return {"kind": kind, "ref": ref, "id": ref, "tracked": True, "type": "CVE", "title": ref, "value": ref,
                "status": "known_exploited" if r["kev"] else "tracked", "confidence": None,
                "severity": (r["severity"] or "none").lower(), "cvss": r["cvss"], "epss": r["epss"],
                "kev": bool(r["kev"]), "kev_date": r["kev_date"], "published": r["published"], "modified": r["modified"],
                "summary": (r["title"] or "").replace(ref + ": ", "", 1),
                "first_seen": r["published"], "last_seen": r["modified"], "tags": ["CISA KEV"] if r["kev"] else [],
                "software_count": r["n"]}
    if kind == "malware":
        r = q(conn, """SELECT COUNT(*) AS n, MIN(created_at) AS first_seen, MAX(COALESCE(last_seen, created_at)) AS last_seen,
                MODE() WITHIN GROUP (ORDER BY enrichment->>'malware_family') AS name
            FROM iocs WHERE LOWER(enrichment->>'malware_family') = LOWER(%s)""", (ref,), one=True)
        if not r or not r["n"]:
            return None
        return {"kind": kind, "ref": r["name"] or ref, "id": None, "tracked": True, "type": "Malware family",
                "title": r["name"] or ref, "value": r["name"] or ref, "status": "observed", "confidence": None,
                "first_seen": utc(r["first_seen"]), "last_seen": utc(r["last_seen"]), "tags": [], "indicator_count": r["n"]}
    if kind == "actor":
        r = q(conn, """SELECT COUNT(DISTINCT c.id) AS n, MIN(c.created_at) AS first_seen,
                (ARRAY_AGG(c.threat_actor ORDER BY c.created_at))[1] AS name
            FROM campaigns c WHERE LOWER(c.threat_actor) = LOWER(%s)""", (ref,), one=True)
        tracked = bool(r and r["n"])
        return {"kind": kind, "ref": (r["name"] if tracked else ref), "id": None, "tracked": tracked, "type": "Threat actor",
                "title": (r["name"] if tracked else ref), "value": ref, "status": "tracked" if tracked else "untracked",
                "confidence": None, "first_seen": utc(r["first_seen"]) if tracked else None, "last_seen": None,
                "tags": [], "campaign_count": r["n"] if tracked else 0}
    if kind == "campaign":
        r = q(conn, """SELECT c.*, (SELECT COUNT(*) FROM iocs i WHERE i.campaign_id = c.id) AS n,
                (SELECT MIN(created_at) FROM iocs i WHERE i.campaign_id = c.id) AS first_ioc,
                (SELECT MAX(COALESCE(last_seen, created_at)) FROM iocs i WHERE i.campaign_id = c.id) AS last_ioc
            FROM campaigns c WHERE c.id = %s""", (ref,), one=True)
        if not r:
            return None
        return {"kind": kind, "ref": r["id"], "id": r["id"], "tracked": True, "type": "Campaign", "title": r["name"],
                "value": r["name"], "status": "tracked", "confidence": None, "threat_actor": r["threat_actor"],
                "first_seen": utc(r["first_ioc"] or r["created_at"]), "last_seen": utc(r["last_ioc"]),
                "tags": r.get("industry_targets") or [], "indicator_count": r["n"], "description": r["description"]}
    if kind == "software":
        r = q(conn, f"""SELECT a.*, COUNT(cf.id) AS n, COUNT(cf.id) FILTER (WHERE cf.kev_listed) AS kev,
                COUNT(cf.id) FILTER (WHERE {UNPATCHED_SQL}) AS unpatched
            FROM assets a LEFT JOIN cve_findings cf ON cf.asset_id = a.id WHERE a.id = %s GROUP BY a.id""", (ref,), one=True)
        if not r:
            return None
        return {"kind": kind, "ref": r["id"], "id": r["id"], "tracked": True, "type": r.get("asset_type") or "Software",
                "title": r["name"], "value": r["name"], "status": "monitored" if r.get("active", True) else "inactive",
                "confidence": None, "vendor": r["vendor"], "version": r["version"], "criticality": r["criticality"],
                "first_seen": utc(r["created_at"]), "last_seen": None, "tags": [],
                "cve_count": r["n"], "kev_count": r["kev"], "unpatched": r["unpatched"], "cpe": r["cpe"]}
    if kind == "investigation":
        r = q(conn, "SELECT * FROM investigations WHERE id = %s", (ref,), one=True)
        if not r:
            return None
        return {"kind": kind, "ref": r["id"], "id": r["id"], "tracked": True, "type": "Investigation", "title": r["name"],
                "value": r["name"], "status": r["status"], "severity": r["severity"], "confidence": None,
                "first_seen": utc(r["created_at"]), "last_seen": utc(r["updated_at"]), "tags": r.get("tags") or [],
                "key": f"INV-{int(r.get('seq') or 0):04d}"}
    return None


# ── Investigations ↔ entities ─────────────────────────────────────────────────
def _item_match_sql(kind, ref, ioc_id=None):
    """WHERE fragment (on investigation_items it) that matches this entity."""
    if kind == "indicator":
        return ("it.item_type IN ('ioc','observable') AND (LOWER(COALESCE(it.value,'')) = LOWER(%s)"
                + (" OR it.ref_id = %s" if ioc_id else "") + ")",
                [ref] + ([ioc_id] if ioc_id else []))
    if kind == "cve":
        return "it.item_type = 'cve' AND UPPER(it.ref_id) = UPPER(%s)", [ref]
    if kind == "campaign":
        return "it.item_type = 'campaign' AND it.ref_id = %s", [ref]
    if kind == "software":
        return "it.item_type = 'asset' AND it.ref_id = %s", [ref]
    if kind in ("actor", "malware"):
        return "it.item_type = %s AND LOWER(COALESCE(it.ref_id, it.value)) = LOWER(%s)", [kind, ref]
    return "FALSE", []


def entity_investigations(conn, kind, ref, ioc_id=None):
    where, params = _item_match_sql(kind, ref, ioc_id)
    rows = q(conn, f"""SELECT inv.id, inv.seq, inv.name, inv.status, inv.severity, it.id AS item_id, it.reason,
            it.created_by AS added_by, it.created_at AS added_at
        FROM investigation_items it JOIN investigations inv ON inv.id = it.investigation_id
        WHERE {where} ORDER BY it.created_at DESC""", params)
    return [{"id": r["id"], "key": f"INV-{int(r['seq'] or 0):04d}", "name": r["name"], "status": r["status"],
             "severity": r["severity"], "item_id": r["item_id"], "reason": r["reason"],
             "added_by": r["added_by"], "added_at": utc(r["added_at"])} for r in rows]


def investigation_membership(conn, inv_id, kind, ref, ioc_id=None):
    where, params = _item_match_sql(kind, ref, ioc_id)
    r = q(conn, f"""SELECT inv.id, inv.seq, inv.name, inv.status, it.id AS item_id, it.reason, it.created_by AS added_by,
            it.created_at AS added_at FROM investigation_items it JOIN investigations inv ON inv.id = it.investigation_id
        WHERE it.investigation_id = %s AND {where} LIMIT 1""", [inv_id] + params, one=True)
    inv = q(conn, "SELECT id, seq, name, status, severity FROM investigations WHERE id = %s", (inv_id,), one=True)
    if not inv:
        return None
    return {"investigation": {"id": inv["id"], "key": f"INV-{int(inv['seq'] or 0):04d}", "name": inv["name"],
                              "status": inv["status"], "severity": inv["severity"]},
            "member": bool(r), "item_id": r["item_id"] if r else None, "reason": r["reason"] if r else None,
            "added_by": r["added_by"] if r else None, "added_at": utc(r["added_at"]) if r else None}


def investigation_keys(conn, inv_id):
    """Entity keys (kind:ref, lowercased) that are part of an investigation."""
    keys = set()
    for it in q(conn, "SELECT item_type, ref_id, value FROM investigation_items WHERE investigation_id = %s", (inv_id,)):
        t, ref, val = it["item_type"], it["ref_id"], it["value"]
        if t in ("ioc", "observable") and val:
            keys.add(f"indicator:{normalize_indicator(val)[0].lower()}")
        elif t == "cve" and ref:
            keys.add(f"cve:{ref.lower()}")
        elif t == "asset" and ref:
            keys.add(f"software:{ref.lower()}")
        elif t in ("campaign", "actor", "malware") and (ref or val):
            keys.add(f"{t}:{(ref or val).lower()}")
    return keys


# ── Relationship service ──────────────────────────────────────────────────────
class _Groups:
    def __init__(self, per_group):
        self.g, self.per = {}, per_group

    def add(self, rel, direction, item, total=None):
        grp = self.g.setdefault((rel, direction), {"rel": rel, "direction": direction, "items": [], "total": 0, "_seen": set()})
        k = entity_key(item)
        if k in grp["_seen"]:
            return
        grp["_seen"].add(k)
        grp["total"] += 1
        if len(grp["items"]) < self.per:
            grp["items"].append(item)

    def set_total(self, rel, direction, total):
        if (rel, direction) in self.g:
            self.g[(rel, direction)]["total"] = max(total, len(self.g[(rel, direction)]["items"]))

    def out(self, inv_keys=None):
        res = []
        for (rel, direction), grp in self.g.items():
            labels = REL_TYPES.get(rel, (rel.replace("_", " ").title(),) * 2)
            for it in grp["items"]:
                if inv_keys is not None:
                    it["in_investigation"] = entity_key(it) in inv_keys
            res.append({"rel": rel, "direction": direction, "label": labels[0] if direction == "out" else labels[1],
                        "items": grp["items"], "total": grp["total"]})
        order = {r: i for i, r in enumerate(GROUP_ORDER)}
        res.sort(key=lambda g: (order.get(g["rel"], 99), 0 if g["direction"] == "out" else 1))
        return res


def _end(kind, ref, conn, hint_type=None):
    """Item for an edge endpoint, hydrated from the database when it exists."""
    if kind == "indicator":
        row = find_ioc(conn, ref)
        return ind_item(row) if row else untracked_item(ref, hint_type)
    if kind == "cve":
        return {"kind": "cve", "ref": ref, "id": ref, "label": ref, "type": "CVE", "tracked": True}
    if kind == "software":
        r = q(conn, "SELECT id, name, version FROM assets WHERE id = %s", (ref,), one=True)
        return {"kind": "software", "ref": ref, "id": ref, "tracked": bool(r),
                "label": (f"{r['name']}" + (f" {r['version']}" if r["version"] else "")) if r else ref, "type": "Software"}
    if kind == "campaign":
        r = q(conn, "SELECT id, name FROM campaigns WHERE id = %s", (ref,), one=True)
        return {"kind": "campaign", "ref": ref, "id": ref, "tracked": bool(r), "label": r["name"] if r else ref, "type": "Campaign"}
    if kind == "investigation":
        r = q(conn, "SELECT id, seq, name FROM investigations WHERE id = %s", (ref,), one=True)
        return {"kind": "investigation", "ref": ref, "id": ref, "tracked": bool(r),
                "label": (f"INV-{int(r['seq'] or 0):04d} {r['name']}") if r else ref, "type": "Investigation"}
    return {"kind": kind, "ref": ref, "id": None, "tracked": True, "label": ref,
            "type": {"malware": "Malware family", "actor": "Threat actor", "source": "Source"}.get(kind, kind)}


def _stored_edges(conn, kind, ref):
    keys = [ref]
    return q(conn, """SELECT * FROM entity_relationships
        WHERE (src_kind = %s AND LOWER(src_ref) = LOWER(%s)) OR (dst_kind = %s AND LOWER(dst_ref) = LOWER(%s))
        ORDER BY created_at DESC LIMIT 500""", (kind, keys[0], kind, keys[0]))


def relationships(conn, kind, ref, per_group=25, inv_id=None):
    """Every relationship the data supports for one entity, grouped by type and direction.

    Sources, in order: derived from real columns (origin='derived'), edges that
    were asserted and stored with provenance (origin='stored'), and the original
    IOC↔IOC links (origin='legacy'). Each item says which one it came from.
    """
    G = _Groups(per_group)

    def D(rel, direction, item, **kw):
        G.add(rel, direction, {**item, "origin": "derived", **kw})

    if kind == "indicator":
        row = find_ioc(conn, ref)
        key, t = normalize_indicator(ref)
        if t == "Domain":
            # DOMAIN → HOSTS → URL. Real evidence: the URL's own hostname.
            urls = q(conn, f"""SELECT id, value, value_defanged, type, confidence, created_at FROM iocs
                WHERE type = 'URL' AND {URL_HOST_SQL} = %s ORDER BY created_at DESC LIMIT %s""", (key, per_group))
            for u in urls:
                D("hosts", "out", ind_item(u), source="URL hostname", source_type="derived",
                  evidence=f"hostname of {u['value'][:80]}")
            tot = q(conn, f"SELECT COUNT(*) AS n FROM iocs WHERE type = 'URL' AND {URL_HOST_SQL} = %s", (key,), one=True)["n"]
            G.set_total("hosts", "out", tot)
        if t == "IPv4" or t == "IPv6":
            urls = q(conn, f"""SELECT id, value, value_defanged, type, confidence, created_at FROM iocs
                WHERE type = 'URL' AND {URL_HOST_SQL} = %s ORDER BY created_at DESC LIMIT %s""", (key, per_group))
            for u in urls:
                D("hosts", "out", ind_item(u), source="URL hostname", source_type="derived",
                  evidence=f"hostname of {u['value'][:80]}")
        if t == "URL":
            host = url_host(key)
            if host:
                hrow = find_ioc(conn, host)
                _, ht = normalize_indicator(host)
                item = ind_item(hrow) if hrow else untracked_item(host, ht)
                D("hosts", "in", item, source="URL hostname", source_type="derived", evidence="hostname parsed from the URL")
        if row:
            enr = row.get("enrichment") if isinstance(row.get("enrichment"), dict) else {}
            fam = enr.get("malware_family")
            if fam and fam != "unknown":
                D("associated_with", "out", _end("malware", fam, conn), source=enr.get("source") or "enrichment",
                  source_type="feed" if enr.get("source") else "enrichment", evidence="malware family reported with the indicator")
            if row.get("campaign_id"):
                D("uses", "in", _end("campaign", row["campaign_id"], conn), source="campaign assignment", source_type="analyst")
            for c in q(conn, "SELECT DISTINCT cve_id FROM cve_ioc_links WHERE ioc_id = %s LIMIT %s", (row["id"], per_group)):
                D("related_to", "out", _end("cve", c["cve_id"], conn), source="CVE description", source_type="derived",
                  evidence="indicator extracted from the CVE's description")
            legacy = q(conn, """SELECT r.id, r.relationship_type, r.source_id, r.target_id, r.note, r.created_at, r.created_by,
                    s.id AS sid, s.value AS sval, s.type AS stype, s.value_defanged AS sdef, s.confidence AS sconf,
                    t.id AS tid, t.value AS tval, t.type AS ttype, t.value_defanged AS tdef, t.confidence AS tconf
                FROM ioc_relationships r JOIN iocs s ON s.id = r.source_id JOIN iocs t ON t.id = r.target_id
                WHERE r.source_id = %s OR r.target_id = %s LIMIT 200""", (row["id"], row["id"]))
            for r in legacy:
                out = r["source_id"] == row["id"]
                o = ({"id": r["tid"], "value": r["tval"], "type": r["ttype"], "value_defanged": r["tdef"], "confidence": r["tconf"]}
                     if out else {"id": r["sid"], "value": r["sval"], "type": r["stype"], "value_defanged": r["sdef"], "confidence": r["sconf"]})
                rel = LEGACY_REL_ALIASES.get(r["relationship_type"], r["relationship_type"])
                G.add(rel if rel in REL_TYPES else "related_to", "out" if out else "in",
                      {**ind_item(o), "origin": "legacy", "legacy_id": r["id"], "source": "analyst",
                       "source_type": "analyst", "observed_at": utc(r["created_at"]), "evidence": r["note"] or None})
        for inv in entity_investigations(conn, "indicator", key, row["id"] if row else None):
            D("appears_in", "out", {"kind": "investigation", "ref": inv["id"], "id": inv["id"], "tracked": True,
                                    "label": f"{inv['key']} {inv['name']}", "type": "Investigation"},
              source="workspace", source_type="analyst", observed_at=inv["added_at"], reason=inv["reason"])
        srcs = q(conn, """SELECT source, source_type, MAX(COALESCE(observed_at, ingested_at)) AS last FROM entity_observations
            WHERE entity_kind = 'indicator' AND LOWER(entity_ref) = LOWER(%s) AND source_type IN ('feed','import','enrichment')
            GROUP BY source, source_type ORDER BY last DESC LIMIT 10""", (key,))
        for s in srcs:
            D("observed_in", "out", _end("source", s["source"], conn), source=s["source"], source_type=s["source_type"],
              observed_at=utc(s["last"]))
        if row and not srcs:
            D("observed_in", "out", _end("source", row["source"], conn), source=row["source"], source_type="ingestion",
              observed_at=utc(row["created_at"]))

    elif kind == "cve":
        for r in q(conn, f"""SELECT a.id, a.name, a.version, cf.affected_versions, cf.patch_available, cf.created_at
            FROM cve_findings cf JOIN assets a ON a.id = cf.asset_id WHERE cf.cve_id = %s ORDER BY a.name LIMIT %s""", (ref, per_group)):
            D("affects", "out", _end("software", r["id"], conn), source="NVD", source_type="feed",
              observed_at=utc(r["created_at"]), evidence=(r["affected_versions"] or "version ranges not published")
              + ("; patch available" if r["patch_available"] else ""))
        for i in q(conn, """SELECT i.id, i.value, i.value_defanged, i.type, i.confidence FROM cve_ioc_links l
            JOIN iocs i ON i.id = l.ioc_id WHERE l.cve_id = %s LIMIT %s""", (ref, per_group)):
            D("related_to", "in", ind_item(i), source="CVE description", source_type="derived")
        for inv in entity_investigations(conn, "cve", ref):
            D("appears_in", "out", {"kind": "investigation", "ref": inv["id"], "id": inv["id"], "tracked": True,
                                    "label": f"{inv['key']} {inv['name']}", "type": "Investigation"},
              source="workspace", source_type="analyst", observed_at=inv["added_at"], reason=inv["reason"])

    elif kind == "malware":
        rows = q(conn, """SELECT id, value, value_defanged, type, confidence, created_at FROM iocs
            WHERE LOWER(enrichment->>'malware_family') = LOWER(%s) ORDER BY created_at DESC LIMIT %s""", (ref, per_group))
        for i in rows:
            D("associated_with", "in", ind_item(i), source="feed", source_type="feed")
        G.set_total("associated_with", "in", q(conn, "SELECT COUNT(*) AS n FROM iocs WHERE LOWER(enrichment->>'malware_family') = LOWER(%s)", (ref,), one=True)["n"])
        for c in q(conn, """SELECT c.id, c.name, COUNT(*) AS n FROM iocs i JOIN campaigns c ON c.id = i.campaign_id
            WHERE LOWER(i.enrichment->>'malware_family') = LOWER(%s) GROUP BY c.id, c.name ORDER BY n DESC LIMIT %s""", (ref, per_group)):
            D("associated_with", "out", _end("campaign", c["id"], conn), source="indicator co-occurrence", source_type="derived",
              evidence=f"{c['n']} indicator(s) tagged {ref} are assigned to this campaign")
        for inv in entity_investigations(conn, "malware", ref):
            D("appears_in", "out", {"kind": "investigation", "ref": inv["id"], "id": inv["id"], "tracked": True,
                                    "label": f"{inv['key']} {inv['name']}", "type": "Investigation"},
              source="workspace", source_type="analyst", observed_at=inv["added_at"], reason=inv["reason"])

    elif kind == "actor":
        for c in q(conn, """SELECT c.id, c.name, c.created_at FROM campaigns c WHERE LOWER(c.threat_actor) = LOWER(%s)
            ORDER BY c.created_at DESC LIMIT %s""", (ref, per_group)):
            D("operates_campaign", "out", _end("campaign", c["id"], conn), source="campaign attribution", source_type="analyst",
              observed_at=utc(c["created_at"]))
        for inv in entity_investigations(conn, "actor", ref):
            D("appears_in", "out", {"kind": "investigation", "ref": inv["id"], "id": inv["id"], "tracked": True,
                                    "label": f"{inv['key']} {inv['name']}", "type": "Investigation"},
              source="workspace", source_type="analyst", observed_at=inv["added_at"], reason=inv["reason"])

    elif kind == "campaign":
        c = q(conn, "SELECT threat_actor FROM campaigns WHERE id = %s", (ref,), one=True)
        if c and c["threat_actor"]:
            D("operates_campaign", "in", _end("actor", c["threat_actor"], conn), source="campaign attribution", source_type="analyst")
        for i in q(conn, """SELECT id, value, value_defanged, type, confidence FROM iocs WHERE campaign_id = %s
            ORDER BY confidence DESC, created_at DESC LIMIT %s""", (ref, per_group)):
            D("uses", "out", ind_item(i), source="campaign assignment", source_type="analyst")
        G.set_total("uses", "out", q(conn, "SELECT COUNT(*) AS n FROM iocs WHERE campaign_id = %s", (ref,), one=True)["n"])
        for f in q(conn, """SELECT enrichment->>'malware_family' AS fam, COUNT(*) AS n FROM iocs WHERE campaign_id = %s
            AND COALESCE(enrichment->>'malware_family','') NOT IN ('','unknown') GROUP BY 1 ORDER BY n DESC LIMIT %s""", (ref, per_group)):
            D("associated_with", "out", _end("malware", f["fam"], conn), source="indicator co-occurrence", source_type="derived",
              evidence=f"{f['n']} indicator(s) in this campaign are tagged {f['fam']}")
        for inv in entity_investigations(conn, "campaign", ref):
            D("appears_in", "out", {"kind": "investigation", "ref": inv["id"], "id": inv["id"], "tracked": True,
                                    "label": f"{inv['key']} {inv['name']}", "type": "Investigation"},
              source="workspace", source_type="analyst", observed_at=inv["added_at"], reason=inv["reason"])

    elif kind == "software":
        for r in q(conn, f"""SELECT cf.cve_id, MAX(cf.cvss_score) AS score, BOOL_OR(cf.kev_listed) AS kev, MAX(cf.created_at) AS seen
            FROM cve_findings cf WHERE cf.asset_id = %s GROUP BY cf.cve_id
            ORDER BY BOOL_OR(cf.kev_listed) DESC, MAX(cf.cvss_score) DESC NULLS LAST LIMIT %s""", (ref, per_group)):
            D("affects", "in", {**_end("cve", r["cve_id"], conn), "cvss": r["score"], "kev": r["kev"]}, source="NVD",
              source_type="feed", observed_at=utc(r["seen"]))
        G.set_total("affects", "in", q(conn, "SELECT COUNT(DISTINCT cve_id) AS n FROM cve_findings WHERE asset_id = %s", (ref,), one=True)["n"])
        for inv in entity_investigations(conn, "software", ref):
            D("appears_in", "out", {"kind": "investigation", "ref": inv["id"], "id": inv["id"], "tracked": True,
                                    "label": f"{inv['key']} {inv['name']}", "type": "Investigation"},
              source="workspace", source_type="analyst", observed_at=inv["added_at"], reason=inv["reason"])

    elif kind == "investigation":
        for it in q(conn, """SELECT it.item_type, it.ref_id, it.value, it.created_at, it.reason, it.created_by
                FROM investigation_items it WHERE it.investigation_id = %s AND it.item_type IN
                ('ioc','observable','cve','asset','campaign','actor','malware') ORDER BY it.created_at DESC LIMIT 400""", (ref,)):
            t = it["item_type"]
            if t == "ioc":
                row = ioc_by_id(conn, it["ref_id"])
                end = ind_item(row) if row else None
            elif t == "observable":
                end = untracked_item(it["value"])
            elif t == "asset":
                end = _end("software", it["ref_id"], conn)
            else:
                end = _end(t, it["ref_id"] or it["value"], conn)
            if end:
                D("appears_in", "in", end, source="workspace", source_type="analyst", observed_at=utc(it["created_at"]),
                  reason=it["reason"])

    # Stored edges (asserted with provenance): both directions.
    canonical = normalize_indicator(ref)[0] if kind == "indicator" else ref
    for e in _stored_edges(conn, kind, canonical):
        is_src = e["src_kind"] == kind and e["src_ref"].lower() == canonical.lower()
        ok, orf = (e["dst_kind"], e["dst_ref"]) if is_src else (e["src_kind"], e["src_ref"])
        item = _end(ok, orf, conn)
        rel = e["rel_type"] if e["rel_type"] in REL_TYPES else "related_to"
        G.add(rel, "out" if is_src else "in",
              {**item, "origin": "stored", "edge_id": e["id"], "source": e["source"], "source_type": e["source_type"],
               "source_ref": e["source_ref"], "confidence_edge": e["confidence"], "observed_at": utc(e["observed_at"] or e["created_at"]),
               "evidence": (e["evidence"] or {}).get("note") if isinstance(e["evidence"], dict) else None,
               "created_by": e["created_by"]})

    inv_keys = investigation_keys(conn, inv_id) if inv_id else None
    groups = G.out(inv_keys)
    return {"groups": groups, "total": sum(g["total"] for g in groups)}


def add_relationship(conn, src_kind, src_ref, rel_type, dst_kind, dst_ref, *, source="analyst", source_type="analyst",
                     source_ref=None, confidence=None, note=None, observed_at=None, created_by=None):
    if rel_type not in REL_TYPES:
        raise ValueError(f"unknown relationship type '{rel_type}'")
    if src_kind not in KINDS or dst_kind not in KINDS:
        raise ValueError("unknown entity kind")
    if src_kind == "indicator":
        src_ref = normalize_indicator(src_ref)[0]
    if dst_kind == "indicator":
        dst_ref = normalize_indicator(dst_ref)[0]
    if (src_kind, src_ref.lower()) == (dst_kind, dst_ref.lower()):
        raise ValueError("an entity cannot be related to itself")
    cur = conn.cursor()
    cur.execute("""INSERT INTO entity_relationships (src_kind, src_ref, rel_type, dst_kind, dst_ref, confidence, source,
            source_type, source_ref, evidence, observed_at, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (src_kind, src_ref, rel_type, dst_kind, dst_ref, source) DO NOTHING RETURNING id""",
        (src_kind, src_ref, rel_type, dst_kind, dst_ref, confidence, source, source_type, source_ref,
         psycopg2.extras.Json({"note": note} if note else {}), observed_at, created_by))
    row = cur.fetchone()
    return row[0] if row else None


# ── Observations ──────────────────────────────────────────────────────────────
def observations(conn, kind, ref, ioc=None, limit=100):
    """What TFII has been told about this entity, newest first. Stored rows are
    authoritative; for legacy indicators that pre-date observation tracking the
    ingestion and last enrichment are reconstructed from real columns and flagged
    derived=True."""
    out = []
    for r in q(conn, """SELECT * FROM entity_observations WHERE entity_kind = %s AND LOWER(entity_ref) = LOWER(%s)
            ORDER BY COALESCE(observed_at, ingested_at) DESC, id DESC LIMIT %s""", (kind, ref, limit)):
        out.append({"id": r["id"], "type": r["obs_type"], "source": r["source"], "source_type": r["source_type"],
                    "source_ref": r["source_ref"], "observed_at": utc(r["observed_at"]), "ingested_at": utc(r["ingested_at"]),
                    "confidence": r["confidence"], "actor": r["actor"], "summary": r["summary"], "derived": False})
    if kind == "indicator" and ioc:
        stored_ingest = any(o["type"] in ("ingested", "sighting") for o in out)
        if not stored_ingest:
            out.append({"id": None, "type": "ingested", "source": ioc["source"],
                        "source_type": "feed" if (ioc.get("enrichment") or {}).get("source") else "analyst",
                        "source_ref": (ioc.get("enrichment") or {}).get("urlhaus_reference"), "observed_at": None,
                        "ingested_at": utc(ioc["created_at"]), "confidence": None, "actor": ioc.get("author"),
                        "summary": f"Added to TFII from {ioc['source']}" + (f" by {ioc['author']}" if ioc.get("author") else ""),
                        "derived": True})
        if not any(o["type"] == "enrichment" for o in out):
            enr = ioc.get("enrichment") if isinstance(ioc.get("enrichment"), dict) else {}
            at = enr.get("enriched_at")
            for source, summary, link, conf in enrichment_summaries(enr):
                out.append({"id": None, "type": "enrichment", "source": source, "source_type": "enrichment", "source_ref": link,
                            "observed_at": at, "ingested_at": at, "confidence": conf, "actor": None, "summary": summary,
                            "derived": True})
    out.sort(key=lambda o: o["observed_at"] or o["ingested_at"] or "", reverse=True)
    return out


def sources_summary(obs):
    """Group observations by source: who says what, how often, since when."""
    g = {}
    for o in obs:
        k = (o["source"], o["source_type"])
        e = g.setdefault(k, {"source": o["source"], "source_type": o["source_type"], "count": 0, "first": None, "last": None,
                             "confidence": None, "source_ref": None, "latest_summary": None, "derived": True})
        e["count"] += 1
        ts = o["observed_at"] or o["ingested_at"]
        if ts and (e["first"] is None or ts < e["first"]):
            e["first"] = ts
        if ts and (e["last"] is None or ts > e["last"]):
            e["last"] = ts
            e["latest_summary"] = o["summary"]
            e["source_ref"] = o["source_ref"] or e["source_ref"]
            if o["confidence"] is not None:
                e["confidence"] = o["confidence"]
        if not o["derived"]:
            e["derived"] = False
    return sorted(g.values(), key=lambda e: e["last"] or "", reverse=True)


def rationale(header_, ioc, obs):
    """'Why does TFII believe this?' — every line traces to stored data."""
    lines = []
    if ioc:
        enr = ioc.get("enrichment") if isinstance(ioc.get("enrichment"), dict) else {}
        for r in (enr.get("confidence_reasons") or [])[:6]:
            lines.append(r)
        if ioc.get("source") and ioc["source"] not in ("Manual", "Bulk Lookup"):
            lines.append(f"Reported by {ioc['source']}" + (f" ({enr.get('malware_family')})" if enr.get("malware_family") not in (None, "", "unknown") else ""))
        elif ioc.get("author"):
            lines.append(f"Added by analyst {ioc['author']}")
        if ioc.get("campaign_name"):
            lines.append(f"Assigned to campaign {ioc['campaign_name']}" + (f" (attributed to {ioc['threat_actor']})" if ioc.get("threat_actor") else ""))
        st = ioc.get("analyst_status")
        if st:
            lines.append(f"Analyst verdict: {st}")
        if ioc.get("false_positive"):
            lines.append("Marked false positive" + (f": {ioc['fp_reason']}" if ioc.get("fp_reason") else ""))
    return list(dict.fromkeys(l for l in lines if l))


# ── Timeline ──────────────────────────────────────────────────────────────────
def _ts_from_date(s):
    """NVD dates are stored as 'YYYY-MM-DD' text; the timeline sorts on ISO strings."""
    if not s:
        return None
    return s if "T" in s else f"{s[:10]}T00:00:00Z"


def timeline(conn, kind, ref, limit=120):
    ev = []

    def add(ts, type_, title, detail=None, source=None, ref_kind=None, ref_id=None):
        if ts:
            ev.append({"ts": utc(ts) if not isinstance(ts, str) else ts, "type": type_, "title": title,
                       "detail": detail, "source": source, "ref_kind": ref_kind, "ref": ref_id})

    for inv in (entity_investigations(conn, kind, ref, (find_ioc(conn, ref) or {}).get("id") if kind == "indicator" else None)
                if kind != "investigation" else []):
        add(inv["added_at"], "investigation", f"Added to {inv['key']} {inv['name']}",
            inv["reason"] and f"Why: {inv['reason']}", inv["added_by"], "investigation", inv["id"])

    if kind == "indicator":
        row = find_ioc(conn, ref)
        if row:
            src = row["source"]
            add(row["created_at"], "first_seen", "First observed in TFII",
                f"Added from {src}" + (f" by {row['author']}" if row.get("author") else ""), src)
            if row["last_seen_at"] and row["created_at"] and (row["last_seen_at"] - row["created_at"]).total_seconds() > 60:
                add(row["last_seen_at"], "last_seen", "Last reported by a source", None, src)
            if row.get("valid_until"):
                expired = row["valid_until"] <= datetime.now(timezone.utc).replace(tzinfo=None)
                add(row["valid_until"], "expiry", "Expired" if expired else "Scheduled to expire",
                    "Indicators drop out of exports after expiry")
            for h in q(conn, "SELECT * FROM ioc_score_history WHERE ioc_id = %s ORDER BY created_at DESC LIMIT 30", (row["id"],)):
                add(h["created_at"], "confidence", f"Confidence {h['old_score']} → {h['new_score']}",
                    (h["reason"] or "").replace(" | ", "\n") or None, h["triggered_by"])
            for n in q(conn, "SELECT * FROM ioc_notes WHERE ioc_id = %s ORDER BY created_at DESC LIMIT 30", (row["id"],)):
                add(n["created_at"], "note", f"Note by {n['username']}", n["note"], n["username"])
            for r in q(conn, """SELECT r.relationship_type, r.created_at, r.created_by, t.value AS tv, s.value AS sv, r.source_id
                FROM ioc_relationships r JOIN iocs s ON s.id = r.source_id JOIN iocs t ON t.id = r.target_id
                WHERE r.source_id = %s OR r.target_id = %s""", (row["id"], row["id"])):
                other = r["tv"] if r["source_id"] == row["id"] else r["sv"]
                add(r["created_at"], "relationship", f"Linked ({r['relationship_type'].replace('_', ' ')}) with {other}", None, "analyst",
                    "indicator", other)
        key = normalize_indicator(ref)[0]
        for o in q(conn, """SELECT * FROM entity_observations WHERE entity_kind = 'indicator' AND LOWER(entity_ref) = LOWER(%s)
                ORDER BY COALESCE(observed_at, ingested_at) DESC LIMIT 60""", (key,)):
            add(o["observed_at"] or o["ingested_at"],
                {"status_change": "status", "dns_resolution": "resolution"}.get(o["obs_type"], "observation"),
                o["summary"] or f"{o['obs_type']} from {o['source']}", None, o["source"])
        for e in _stored_edges(conn, "indicator", key):
            add(e["observed_at"] or e["created_at"], "relationship",
                f"{REL_TYPES.get(e['rel_type'], (e['rel_type'],))[0]}: "
                f"{e['dst_ref'] if e['src_ref'].lower() == key.lower() else e['src_ref']}", None, e["source"])
    elif kind == "cve":
        rows = q(conn, """SELECT MIN(published_date) AS published, MAX(modified_date) AS modified, MAX(kev_date) AS kev_date,
                BOOL_OR(kev_listed) AS kev, MIN(created_at) AS tracked, MAX(patch_detected_at) AS patched
            FROM cve_findings WHERE cve_id = %s""", (ref,), one=True)
        if rows:
            add(_ts_from_date(rows["published"]), "first_seen", "Published to NVD", None, "NVD")
            if rows["modified"] and rows["modified"] != rows["published"]:
                add(_ts_from_date(rows["modified"]), "update", "Last modified in NVD", None, "NVD")
            if rows["kev"] and rows["kev_date"]:
                add(_ts_from_date(rows["kev_date"]), "kev", "Added to CISA Known Exploited Vulnerabilities", None, "CISA KEV")
            add(rows["tracked"], "tracked", "Started tracking in TFII", None, "TFII")
            add(rows["patched"], "patch", "Patch detected", None, "NVD")
    elif kind == "campaign":
        c = q(conn, "SELECT created_at, created_by FROM campaigns WHERE id = %s", (ref,), one=True)
        if c:
            add(c["created_at"], "created", "Campaign created", None, "analyst")
        for d in q(conn, """SELECT created_at::date AS d, COUNT(*) AS n, MIN(created_at) AS t FROM iocs WHERE campaign_id = %s
                GROUP BY 1 ORDER BY 1 DESC LIMIT 40""", (ref,)):
            add(d["t"], "ingest", f"{d['n']} indicator{'s' if d['n'] != 1 else ''} added", None, "feeds & analysts")
    elif kind == "malware":
        for d in q(conn, """SELECT date_trunc('week', created_at) AS w, COUNT(*) AS n FROM iocs
                WHERE LOWER(enrichment->>'malware_family') = LOWER(%s) GROUP BY 1 ORDER BY 1 DESC LIMIT 40""", (ref,)):
            add(d["w"], "ingest", f"{d['n']} indicator{'s' if d['n'] != 1 else ''} added (week starting {d['w'].date()})", None, "feeds")
    elif kind == "actor":
        for c in q(conn, "SELECT id, name, created_at FROM campaigns WHERE LOWER(threat_actor) = LOWER(%s)", (ref,)):
            add(c["created_at"], "campaign", f"Campaign “{c['name']}” attributed", None, "analyst", "campaign", c["id"])
    elif kind == "software":
        a = q(conn, "SELECT created_at FROM assets WHERE id = %s", (ref,), one=True)
        if a:
            add(a["created_at"], "created", "Added to software registry", None, "analyst")
        for k in q(conn, """SELECT cve_id, kev_date FROM cve_findings WHERE asset_id = %s AND kev_listed AND kev_date IS NOT NULL
                ORDER BY kev_date DESC LIMIT 20""", (ref,)):
            add(_ts_from_date(k["kev_date"]), "kev", f"{k['cve_id']} added to CISA KEV", None, "CISA KEV", "cve", k["cve_id"])
        for p in q(conn, "SELECT cve_id, patch_detected_at FROM cve_findings WHERE asset_id = %s AND patch_detected_at IS NOT NULL ORDER BY patch_detected_at DESC LIMIT 20", (ref,)):
            add(p["patch_detected_at"], "patch", f"Patch detected for {p['cve_id']}", None, "NVD", "cve", p["cve_id"])
        for d in q(conn, "SELECT created_at::date AS d, COUNT(*) AS n, MIN(created_at) AS t FROM cve_findings WHERE asset_id = %s GROUP BY 1 ORDER BY 1 DESC LIMIT 30", (ref,)):
            add(d["t"], "ingest", f"{d['n']} CVE{'s' if d['n'] != 1 else ''} started being tracked", None, "NVD")

    ev.sort(key=lambda e: e["ts"], reverse=True)
    return ev[:limit]


# ── Raw data ──────────────────────────────────────────────────────────────────
def raw(conn, kind, ref):
    if kind == "indicator":
        row = find_ioc(conn, ref)
        return dict(row) if row else None
    if kind == "cve":
        rows = q(conn, "SELECT cf.*, a.name AS asset_name FROM cve_findings cf LEFT JOIN assets a ON a.id = cf.asset_id WHERE cf.cve_id = %s", (ref,))
        return {"findings": [dict(r) for r in rows]} if rows else None
    if kind == "campaign":
        r = q(conn, "SELECT * FROM campaigns WHERE id = %s", (ref,), one=True)
        return dict(r) if r else None
    if kind == "software":
        r = q(conn, "SELECT * FROM assets WHERE id = %s", (ref,), one=True)
        return dict(r) if r else None
    return None


# ── Analyst status ────────────────────────────────────────────────────────────
def set_status(conn, ioc, status, user, reason=""):
    """Change an indicator's status. false_positive keeps using the v1 flag so
    exports keep excluding it; the rest is the triage verdict. Recorded as an
    observation so it shows on the timeline with who and why."""
    if status not in SETTABLE_STATUSES:
        raise ValueError(f"status must be one of {', '.join(SETTABLE_STATUSES)}")
    cur = conn.cursor()
    if status == "false_positive":
        cur.execute("UPDATE iocs SET false_positive = TRUE, fp_reason = %s WHERE id = %s", (reason or "", ioc["id"]))
    else:
        cur.execute("UPDATE iocs SET false_positive = FALSE, fp_reason = NULL, analyst_status = %s WHERE id = %s",
                    (None if status == "active" else status, ioc["id"]))
    key = normalize_indicator(ioc["value"])[0]
    record_observation(conn, "indicator", key, "status_change", f"analyst:{user['username']}", "analyst", actor=user["username"],
                       summary=f"Status set to {status}" + (f" — {reason}" if reason else ""))
