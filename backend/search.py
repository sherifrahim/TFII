"""
Global intelligence search.

Design: a registry of providers, one per entity kind. Each provider runs one
indexed SQL query and returns uniform hits; the service normalises the query
(defanged input, IPv6 forms, hostnames), runs the providers the caller may use,
scores, groups and returns them. Adding a new entity type later is one
`register()` call — no changes to routes or to the UI's result handling.

Scoring is deliberately simple and explainable: exact value 100, prefix 80,
hostname-of-URL 70, substring 50, tag / malware family 40-45, description 30.
"""
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

from entities import (q, like_escape, normalize_indicator, ind_item, STATUS_SQL, SEVERITY_SQL, SOURCE_SQL, SEV_SQL,
                      utc)
from migrations import URL_HOST_SQL


@dataclass
class Ctx:
    raw: str
    norm: str            # refanged / canonical form
    detected: str        # detect_type() of norm
    lower: str
    contains: str        # ILIKE pattern (escaped)
    prefix: str          # LIKE pattern on lowercase
    short: bool          # < 3 chars: no substring scans
    host: Optional[str]  # hostname-looking query (domain or IP)


@dataclass
class Provider:
    kind: str
    label: str
    cap: str                       # capability required, "" = any authenticated user
    run: Callable                  # (conn, ctx, limit) -> list[hit]


def hit(kind, ref, title, subtitle=None, type_=None, score=0, **meta):
    return {"kind": kind, "ref": ref, "title": title, "subtitle": subtitle, "type": type_, "score": score, **meta}


# ── Providers ─────────────────────────────────────────────────────────────────
def _indicators(conn, c: Ctx, limit):
    params = {"exact": c.lower, "prefix": c.prefix, "contains": c.contains, "tag": c.lower, "host": c.host,
              "lim": limit}
    contains_sql = "" if c.short else """
            OR i.value ILIKE %(contains)s ESCAPE '\\' OR i.value_defanged ILIKE %(contains)s ESCAPE '\\'
            OR i.enrichment->>'malware_family' ILIKE %(contains)s ESCAPE '\\'
            OR i.description ILIKE %(contains)s ESCAPE '\\'"""
    score_contains = "" if c.short else """
            WHEN i.value ILIKE %(contains)s ESCAPE '\\' OR i.value_defanged ILIKE %(contains)s ESCAPE '\\' THEN 50
            WHEN i.enrichment->>'malware_family' ILIKE %(contains)s ESCAPE '\\' THEN 40
            WHEN i.description ILIKE %(contains)s ESCAPE '\\' THEN 30"""
    rows = q(conn, f"""SELECT i.id, i.type, i.value, i.value_defanged, i.confidence, i.tlp, i.created_at,
            i.description, i.enrichment->>'malware_family' AS malware_family, {STATUS_SQL} AS status,
            {SEVERITY_SQL} AS severity, {SOURCE_SQL} AS source,
            CASE WHEN LOWER(i.value) = %(exact)s THEN 100
                 WHEN LOWER(i.value) LIKE %(prefix)s ESCAPE '\\' THEN 80
                 WHEN i.type = 'URL' AND {URL_HOST_SQL} = %(host)s THEN 70
                 {score_contains}
                 WHEN %(tag)s = ANY(i.tags) THEN 45
                 ELSE 20 END AS score,
            (i.type = 'URL' AND {URL_HOST_SQL} = %(host)s) AS by_host
        FROM iocs i
        WHERE LOWER(i.value) = %(exact)s OR LOWER(i.value) LIKE %(prefix)s ESCAPE '\\'
              OR (i.type = 'URL' AND {URL_HOST_SQL} = %(host)s)
              OR %(tag)s = ANY(i.tags) {contains_sql}
        ORDER BY score DESC, i.confidence DESC, i.created_at DESC LIMIT %(lim)s""", params)
    out = []
    for r in rows:
        it = ind_item(r)
        sub = r["description"][:90] if r["description"] and r["score"] <= 30 else (
            f"URL on host {c.host}" if r["by_host"] and r["score"] == 70 else r["source"])
        out.append(hit("indicator", it["ref"], r["value_defanged"] or r["value"], sub, r["type"], r["score"], id=r["id"],
                       confidence=r["confidence"], severity=r["severity"], status=r["status"], tlp=r["tlp"],
                       malware_family=r["malware_family"] if r["malware_family"] not in (None, "unknown") else None,
                       created_at=utc(r["created_at"])))
    return out


def _cves(conn, c: Ctx, limit):
    if not (c.detected == "CVE" or re.match(r"^cve-?\d{0,4}-?\d*$", c.lower) or not c.short):
        return []
    text_match = "" if c.short else (" OR cf.title ILIKE %(contains)s ESCAPE '\\'"
                                     " OR cf.description ILIKE %(contains)s ESCAPE '\\'")
    rows = q(conn, f"""SELECT cf.cve_id, MAX(cf.cvss_score) AS cvss, BOOL_OR(cf.kev_listed) AS kev,
            (ARRAY_AGG({SEV_SQL} ORDER BY cf.cvss_score DESC NULLS LAST))[1] AS severity,
            (ARRAY_AGG(cf.title ORDER BY cf.cvss_score DESC NULLS LAST))[1] AS title,
            STRING_AGG(DISTINCT a.name, ', ') AS software,
            CASE WHEN UPPER(cf.cve_id) = UPPER(%(raw)s) THEN 100 WHEN cf.cve_id ILIKE %(prefix_ci)s ESCAPE '\\' THEN 80
                 WHEN cf.cve_id ILIKE %(contains)s ESCAPE '\\' THEN 60 ELSE 35 END AS score
        FROM cve_findings cf LEFT JOIN assets a ON a.id = cf.asset_id
        WHERE cf.cve_id ILIKE %(contains)s ESCAPE '\\'{text_match}
        GROUP BY cf.cve_id ORDER BY score DESC, MAX(cf.cvss_score) DESC NULLS LAST LIMIT %(lim)s""",
        {"raw": c.norm, "prefix_ci": like_escape(c.norm) + "%", "contains": c.contains, "lim": limit})
    return [hit("cve", r["cve_id"], r["cve_id"], (r["title"] or "").replace(r["cve_id"] + ": ", "", 1)[:100], "CVE", r["score"],
                cvss=r["cvss"], severity=(r["severity"] or "none").lower(), kev=bool(r["kev"]), software=r["software"])
            for r in rows]


def _software(conn, c: Ctx, limit):
    if c.short:
        return []
    rows = q(conn, """SELECT a.id, a.name, a.vendor, a.version, COUNT(cf.id) AS n,
            CASE WHEN LOWER(a.name) = %(lower)s THEN 100 WHEN LOWER(a.name) LIKE %(prefix)s ESCAPE '\\' THEN 80 ELSE 50 END AS score
        FROM assets a LEFT JOIN cve_findings cf ON cf.asset_id = a.id
        WHERE a.active = TRUE AND (a.name ILIKE %(contains)s ESCAPE '\\' OR a.vendor ILIKE %(contains)s ESCAPE '\\'
              OR a.cpe ILIKE %(contains)s ESCAPE '\\')
        GROUP BY a.id ORDER BY score DESC, n DESC LIMIT %(lim)s""",
        {"lower": c.lower, "prefix": c.prefix, "contains": c.contains, "lim": limit})
    return [hit("software", r["id"], r["name"] + (f" {r['version']}" if r["version"] else ""),
                f"{r['vendor'] or 'unknown vendor'} · {r['n']} CVEs", "Software", r["score"], cve_count=r["n"]) for r in rows]


def _malware(conn, c: Ctx, limit):
    if c.short:
        return []
    rows = q(conn, """SELECT enrichment->>'malware_family' AS name, COUNT(*) AS n,
            CASE WHEN LOWER(enrichment->>'malware_family') = %(lower)s THEN 100
                 WHEN LOWER(enrichment->>'malware_family') LIKE %(prefix)s ESCAPE '\\' THEN 80 ELSE 50 END AS score
        FROM iocs WHERE enrichment->>'malware_family' ILIKE %(contains)s ESCAPE '\\'
              AND COALESCE(enrichment->>'malware_family','') NOT IN ('','unknown')
        GROUP BY 1 ORDER BY score DESC, n DESC LIMIT %(lim)s""",
        {"lower": c.lower, "prefix": c.prefix, "contains": c.contains, "lim": limit})
    return [hit("malware", r["name"], r["name"], f"{r['n']} indicators", "Malware family", r["score"], indicator_count=r["n"])
            for r in rows]


def _actors(conn, c: Ctx, limit):
    if c.short:
        return []
    rows = q(conn, """SELECT threat_actor AS name, COUNT(*) AS n,
            CASE WHEN LOWER(threat_actor) = %(lower)s THEN 100 WHEN LOWER(threat_actor) LIKE %(prefix)s ESCAPE '\\' THEN 80 ELSE 50 END AS score
        FROM campaigns WHERE threat_actor ILIKE %(contains)s ESCAPE '\\' AND COALESCE(threat_actor,'') <> ''
        GROUP BY threat_actor ORDER BY score DESC, n DESC LIMIT %(lim)s""",
        {"lower": c.lower, "prefix": c.prefix, "contains": c.contains, "lim": limit})
    return [hit("actor", r["name"], r["name"], f"{r['n']} campaign{'s' if r['n'] != 1 else ''}", "Threat actor", r["score"]) for r in rows]


def _campaigns(conn, c: Ctx, limit):
    if c.short:
        return []
    rows = q(conn, """SELECT c.id, c.name, c.threat_actor, COUNT(i.id) AS n,
            CASE WHEN LOWER(c.name) = %(lower)s THEN 100 WHEN LOWER(c.name) LIKE %(prefix)s ESCAPE '\\' THEN 80 ELSE 45 END AS score
        FROM campaigns c LEFT JOIN iocs i ON i.campaign_id = c.id
        WHERE c.name ILIKE %(contains)s ESCAPE '\\' OR c.description ILIKE %(contains)s ESCAPE '\\'
              OR c.threat_actor ILIKE %(contains)s ESCAPE '\\'
        GROUP BY c.id ORDER BY score DESC, n DESC LIMIT %(lim)s""",
        {"lower": c.lower, "prefix": c.prefix, "contains": c.contains, "lim": limit})
    return [hit("campaign", r["id"], r["name"], f"{r['threat_actor'] or 'unattributed'} · {r['n']} indicators", "Campaign", r["score"])
            for r in rows]


def _investigations(conn, c: Ctx, limit):
    m = re.fullmatch(r"inv-?0*(\d+)", c.lower)
    rows = q(conn, """SELECT id, seq, name, status, severity,
            CASE WHEN seq = %(seq)s THEN 100 WHEN LOWER(name) = %(lower)s THEN 100 WHEN LOWER(name) LIKE %(prefix)s ESCAPE '\\' THEN 80 ELSE 45 END AS score
        FROM investigations
        WHERE seq = %(seq)s OR name ILIKE %(contains)s ESCAPE '\\' OR description ILIKE %(contains)s ESCAPE '\\'
              OR %(lower)s = ANY(tags)
        ORDER BY score DESC, updated_at DESC LIMIT %(lim)s""",
        {"seq": int(m.group(1)) if m else -1, "lower": c.lower, "prefix": c.prefix, "contains": c.contains, "lim": limit})
    return [hit("investigation", r["id"], r["name"], f"INV-{int(r['seq'] or 0):04d} · {r['status']}", "Investigation", r["score"],
                severity=r["severity"], key=f"INV-{int(r['seq'] or 0):04d}") for r in rows]


def _notes(conn, c: Ctx, limit):
    if c.short:
        return []
    rows = q(conn, """SELECT id, title, LEFT(content, 140) AS snippet, investigation_id FROM admin_notes
        WHERE archived = FALSE AND (title ILIKE %(contains)s ESCAPE '\\' OR content ILIKE %(contains)s ESCAPE '\\')
        ORDER BY updated_at DESC LIMIT %(lim)s""", {"contains": c.contains, "lim": limit})
    return [hit("note", r["id"], r["title"] or "Untitled note", r["snippet"], "Note", 30, investigation_id=r["investigation_id"])
            for r in rows]


class SearchService:
    def __init__(self, detect_type, refang):
        self.providers = []
        self._detect, self._refang = detect_type, refang

    def register(self, provider: Provider):
        self.providers.append(provider)

    def context(self, raw: str) -> Ctx:
        raw = (raw or "").strip()
        norm = self._refang(raw)
        detected = self._detect(norm)
        key = normalize_indicator(norm)[0] if detected not in (None, "Unknown", "CVE") else norm
        lower = key.lower()
        host = None
        if detected in ("Domain", "IPv4", "IPv6"):
            host = lower
        elif detected == "URL":
            m = re.match(r"^https?://([^/:?#]+)", lower)
            host = m.group(1) if m else None
        return Ctx(raw=raw, norm=key, detected=detected or "Unknown", lower=lower, contains=f"%{like_escape(key)}%",
                   prefix=f"{like_escape(lower)}%", short=len(key) < 3, host=host)

    def search(self, conn, query: str, caps, limit=6, kinds=None):
        t0 = time.time()
        c = self.context(query)
        groups, total = {}, 0
        for p in self.providers:
            if kinds and p.kind not in kinds:
                continue
            if p.cap and p.cap not in caps:
                continue
            try:
                hits = p.run(conn, c, limit)
            except Exception as e:      # one broken provider must not blank the search
                conn.rollback()
                print(f"[search] provider {p.kind} failed: {str(e).splitlines()[0][:160]}")
                continue
            hits.sort(key=lambda h: -h["score"])
            if hits:
                groups[p.kind] = {"label": p.label, "hits": hits, "count": len(hits)}
                total += len(hits)
        allhits = [h for g in groups.values() for h in g["hits"]]
        top = max(allhits, key=lambda h: h["score"]) if allhits else None
        return {"query": c.raw, "normalized": c.norm, "detected_type": c.detected, "groups": groups, "top": top,
                "total": total, "took_ms": int((time.time() - t0) * 1000)}


def build_service(detect_type, refang) -> SearchService:
    s = SearchService(detect_type, refang)
    for p in (Provider("indicator", "Indicators", "data.workspace", _indicators),
              Provider("cve", "CVEs", "data.workspace", _cves),
              Provider("software", "Software", "data.workspace", _software),
              Provider("malware", "Malware", "data.workspace", _malware),
              Provider("actor", "Threat actors", "data.workspace", _actors),
              Provider("campaign", "Campaigns", "data.workspace", _campaigns),
              Provider("investigation", "Investigations", "data.workspace", _investigations),
              Provider("note", "Notes", "admin.panel", _notes)):
        s.register(p)
    return s
