"""
Entity Intelligence API.

One consistent surface for every entity kind, addressed by (kind, ref) query
parameters rather than path segments: indicator values are URLs and IPv6
addresses, and slashes or colons in a path are a routing and proxy-decoding
hazard that a query string simply does not have.

    GET  /v2/entity                    envelope: header, relationships, timeline,
                                       observations, sources, investigations
    GET  /v2/entity/relationships      (re-fetch with a larger per-group limit)
    GET  /v2/entity/timeline | observations | raw | membership
    POST /v2/entity/status             triage status of an indicator
    POST /v2/entity/resolve-dns        domain → A/AAAA, recorded with provenance
    POST /v2/entity/sync-mitre         materialise ATT&CK associations for an actor
    POST /v2/relationships             assert a typed relationship (with provenance)
    DELETE /v2/relationships/{id}
    POST /v2/investigations/{id}/entities   add any entity to an investigation
    GET  /v2/search                    global search (see search.py)
"""
from datetime import datetime, timezone
from typing import List, Optional
from types import SimpleNamespace

import httpx
import psycopg2.extras
from fastapi import Depends, HTTPException
from pydantic import BaseModel

import entities as E
import search as S
import security


class StatusIn(BaseModel):
    ref: str
    status: str
    reason: Optional[str] = ""


class RelIn(BaseModel):
    src_kind: str
    src_ref: str
    rel_type: str
    dst_kind: str
    dst_ref: str
    note: Optional[str] = None
    source_ref: Optional[str] = None
    confidence: Optional[int] = None


class EntityAdd(BaseModel):
    kind: str
    ref: str
    reason: Optional[str] = None


class ReasonIn(BaseModel):
    reason: Optional[str] = None


class RefIn(BaseModel):
    ref: str


def _check_kind(kind):
    if kind not in E.KINDS:
        raise HTTPException(400, f"kind must be one of {', '.join(E.KINDS)}")


def register(app, d, h):
    """`h` carries the investigation helpers owned by intel_api (add_item, event, get_investigation)."""
    get_db, full, current = d.get_db, d.require_full_access, d.get_current_user
    svc = S.build_service(d.detect_type, d.refang)

    # ── Search ────────────────────────────────────────────────────────────────
    @app.get("/v2/search")
    def v2_search(q: str, limit: int = 6, kinds: str = "", user=Depends(current), conn=Depends(get_db)):
        if not (q or "").strip():
            return {"query": "", "normalized": "", "detected_type": None, "groups": {}, "top": None, "total": 0}
        caps = d.effective_caps(user, conn)
        out = svc.search(conn, q[:200], caps, limit=max(1, min(limit, 25)),
                         kinds=set(k for k in kinds.split(",") if k) or None)
        out["limited"] = "data.workspace" not in caps
        return out

    # ── Envelope ──────────────────────────────────────────────────────────────
    def _indicator_overview(conn, hd, ioc):
        if not ioc:
            return None
        key = hd["ref"]
        related = {"campaign": [], "malware": [], "subnet": [], "tags": []}
        cols = "id, type, value, value_defanged, confidence, created_at"
        if ioc.get("campaign_id"):
            related["campaign"] = E.q(conn, f"SELECT {cols} FROM iocs WHERE campaign_id=%s AND id<>%s ORDER BY created_at DESC LIMIT 25",
                                      (ioc["campaign_id"], ioc["id"]))
        if hd.get("malware_family"):
            related["malware"] = E.q(conn, f"SELECT {cols} FROM iocs WHERE LOWER(enrichment->>'malware_family')=LOWER(%s) AND id<>%s ORDER BY created_at DESC LIMIT 25",
                                     (hd["malware_family"], ioc["id"]))
        if ioc["type"] == "IPv4" and ioc["value"].count(".") == 3:
            related["subnet"] = E.q(conn, f"SELECT {cols} FROM iocs WHERE type='IPv4' AND value LIKE %s AND id<>%s ORDER BY created_at DESC LIMIT 25",
                                    (".".join(ioc["value"].split(".")[:3]) + ".%", ioc["id"]))
        specific = [t for t in (ioc.get("tags") or []) if t and t.lower() not in E.GENERIC_TAGS][:6]
        if specific:
            related["tags"] = E.q(conn, f"SELECT {cols}, tags FROM iocs WHERE tags && %s AND id<>%s ORDER BY created_at DESC LIMIT 25",
                                  (specific, ioc["id"]))
        enr = ioc.get("enrichment") if isinstance(ioc.get("enrichment"), dict) else {}
        ab, vt = enr.get("abuseipdb") or {}, enr.get("virustotal") or {}
        geo = {k: v for k, v in {"country": ab.get("country") or vt.get("country"), "isp": ab.get("isp"),
                                 "asn": vt.get("asn"), "as_owner": vt.get("as_owner"), "usage_type": ab.get("usage_type"),
                                 "domain": ab.get("domain")}.items() if v and v != "?"}
        cves = E.q(conn, f"""SELECT DISTINCT ON (cf.cve_id) cf.cve_id, cf.title, cf.cvss_score, {E.SEV_SQL} AS severity,
                cf.kev_listed, cf.patch_available, a.name AS asset_name
            FROM cve_ioc_links l JOIN cve_findings cf ON cf.cve_id = l.cve_id LEFT JOIN assets a ON a.id = cf.asset_id
            WHERE l.ioc_id = %s""", (ioc["id"],))
        notes = E.q(conn, "SELECT * FROM ioc_notes WHERE ioc_id=%s ORDER BY created_at DESC", (ioc["id"],))
        history = E.q(conn, "SELECT * FROM ioc_score_history WHERE ioc_id=%s ORDER BY created_at DESC LIMIT 50", (ioc["id"],))
        row = dict(ioc)
        row["enrichment"] = enr
        return {"ioc": row, "related": related, "geo": geo, "cves": cves, "notes": notes, "score_history": history}

    def _cve_overview(conn, cve_id):
        rows = E.q(conn, f"""SELECT cf.*, a.name AS asset_name, a.vendor AS asset_vendor, a.version AS asset_version,
                {E.SEV_SQL} AS sev FROM cve_findings cf LEFT JOIN assets a ON a.id = cf.asset_id
            WHERE cf.cve_id = %s ORDER BY cf.cvss_score DESC NULLS LAST""", (cve_id,))
        if not rows:
            return None
        first = rows[0]
        refs, seen = [], set()
        for r in rows:
            for ref in (r.get("references") or []):
                url = security.safe_http_url(ref.get("url") if isinstance(ref, dict) else ref)
                if url and url not in seen:
                    seen.add(url)
                    refs.append({"url": url, "tags": (ref.get("tags") if isinstance(ref, dict) else []) or []})
        def by_tag(*tags):
            return [x for x in refs if any(t in x["tags"] for t in tags)][:12]
        software = [{"asset_id": r["asset_id"], "name": r["asset_name"], "vendor": r["asset_vendor"],
                     "monitored_version": r["asset_version"], "affected_versions": r["affected_versions"],
                     "patch_available": r["patch_available"], "patch_url": security.safe_http_url(r["patch_url"]),
                     "patch_detected_at": E.utc(r["patch_detected_at"]), "cvss_score": r["cvss_score"]} for r in rows]
        linked = E.q(conn, """SELECT i.id, i.type, i.value, i.value_defanged, i.confidence FROM cve_ioc_links l
            JOIN iocs i ON i.id = l.ioc_id WHERE l.cve_id = %s LIMIT 25""", (cve_id,))
        return {"description": first["description"], "title": first["title"],
                "cvss": {"score": first["cvss_score"], "vector": first["cvss_vector"], "severity": (first["sev"] or "").lower()},
                "epss": {"score": max([r["epss_score"] for r in rows if r["epss_score"] is not None], default=None),
                         "percentile": max([r["epss_percentile"] for r in rows if r["epss_percentile"] is not None], default=None)},
                "kev": {"listed": any(r["kev_listed"] for r in rows),
                        "date": max([r["kev_date"] for r in rows if r["kev_date"]], default=None)},
                "cwe": first["cwe"], "published": first["published_date"], "modified": first["modified_date"],
                "software": software, "references": refs[:60],
                "remediation": {"patches": by_tag("Patch"), "advisories": by_tag("Vendor Advisory", "Third Party Advisory"),
                                "mitigations": by_tag("Mitigation"),
                                "patched_on": sum(1 for r in rows if r["patch_available"]), "software_count": len(rows)},
                "linked_iocs": linked}

    def envelope(conn, kind, ref, inv_id=None):
        _check_kind(kind)
        ref = E.resolve_ref(conn, kind, ref)
        hd = E.header(conn, kind, ref)
        if hd is None:
            raise HTTPException(404, f"{kind} not found")
        ioc = E.find_ioc(conn, hd["ref"]) if kind == "indicator" and hd["tracked"] else None
        obs = E.observations(conn, kind, hd["ref"], ioc)
        rel = E.relationships(conn, kind, hd["ref"], inv_id=inv_id)
        tl = E.timeline(conn, kind, hd["ref"])
        invs = E.entity_investigations(conn, kind, hd["ref"], ioc["id"] if ioc else None) if kind != "investigation" else []
        out = {"entity": hd, "relationships": rel, "timeline": tl, "observations": obs,
               "sources": E.sources_summary(obs), "investigations": invs, "rationale": E.rationale(hd, ioc, obs),
               "counts": {"relationships": rel["total"], "timeline": len(tl), "observations": len(obs),
                          "sources": len(E.sources_summary(obs)), "investigations": len(invs)}}
        if kind == "indicator":
            out["overview"] = _indicator_overview(conn, hd, ioc)
        elif kind == "cve":
            out["overview"] = _cve_overview(conn, hd["ref"])
        if inv_id:
            out["membership"] = E.investigation_membership(conn, inv_id, kind, hd["ref"], ioc["id"] if ioc else None)
        return out

    @app.get("/v2/entity")
    def v2_entity(kind: str, ref: str, inv: str = "", user=Depends(full), conn=Depends(get_db)):
        return envelope(conn, kind, ref, inv or None)

    @app.get("/v2/entity/relationships")
    def v2_entity_relationships(kind: str, ref: str, per_group: int = 100, inv: str = "",
                                user=Depends(full), conn=Depends(get_db)):
        _check_kind(kind)
        return E.relationships(conn, kind, E.resolve_ref(conn, kind, ref), per_group=max(1, min(per_group, 500)), inv_id=inv or None)

    @app.get("/v2/entity/timeline")
    def v2_entity_timeline(kind: str, ref: str, limit: int = 300, user=Depends(full), conn=Depends(get_db)):
        _check_kind(kind)
        return {"events": E.timeline(conn, kind, E.resolve_ref(conn, kind, ref), limit=max(1, min(limit, 1000)))}

    @app.get("/v2/entity/raw")
    def v2_entity_raw(kind: str, ref: str, user=Depends(full), conn=Depends(get_db)):
        _check_kind(kind)
        data = E.raw(conn, kind, E.resolve_ref(conn, kind, ref))
        if data is None:
            raise HTTPException(404, "No stored record for this entity")
        return {"data": data}

    @app.get("/v2/entity/membership")
    def v2_entity_membership(kind: str, ref: str, inv: str, user=Depends(full), conn=Depends(get_db)):
        _check_kind(kind)
        ref = E.resolve_ref(conn, kind, ref)
        ioc = E.find_ioc(conn, ref) if kind == "indicator" else None
        m = E.investigation_membership(conn, inv, kind, ref, ioc["id"] if ioc else None)
        if m is None:
            raise HTTPException(404, "Investigation not found")
        return m

    # ── Graph (drawn from the same relationship service as the tabs) ──────────
    def _gnode(it):
        """Graph node for a relationship item. Tracked indicators keep the legacy
        'ioc' kind (ref = row id) so the existing graph component routes them."""
        if it["kind"] == "indicator":
            tracked = bool(it.get("tracked") and it.get("id"))
            return {"id": f"indicator:{it['ref'].lower()}", "kind": "ioc" if tracked else "observable",
                    "label": it.get("label") or it["ref"], "ref": it["id"] if tracked else it["ref"],
                    "ioc_type": it.get("type"), "confidence": it.get("confidence")}
        return {"id": f"{it['kind']}:{str(it['ref']).lower()}", "kind": it["kind"], "label": it.get("label") or str(it["ref"]),
                "ref": it["ref"]}

    @app.get("/v2/entity/graph")
    def v2_entity_graph(kind: str, ref: str, depth: int = 1, user=Depends(full), conn=Depends(get_db)):
        _check_kind(kind)
        depth = max(1, min(depth, 2))
        cap, per = 120, 20
        root_ref = E.resolve_ref(conn, kind, ref)
        hd = E.header(conn, kind, root_ref)
        if hd is None:
            raise HTTPException(404, f"{kind} not found")
        root = _gnode({**hd, "label": hd["title"], "type": hd.get("type")})
        nodes, edges, seen = {root["id"]: root}, [], set()
        frontier, truncated = [(kind, hd["ref"], root["id"])], False
        for level in range(depth):
            nxt = []
            for k, r, nid in frontier:
                rel = E.relationships(conn, k, r, per_group=cap if level == 0 else per)
                for g in rel["groups"]:
                    # Provenance is not graph structure; workspace links only count from the
                    # investigation's own side (what it contains), not from every member's.
                    if g["rel"] == "observed_in" or (g["rel"] == "appears_in" and g["direction"] == "out"):
                        continue
                    for it in g["items"]:
                        n = _gnode(it)
                        if n["id"] not in nodes:
                            if len(nodes) >= cap:
                                truncated = True
                                continue
                            nodes[n["id"]] = n
                            nxt.append((it["kind"], it["ref"], n["id"]))
                        a, b = (nid, n["id"]) if g["direction"] == "out" else (n["id"], nid)
                        key = (a, b, g["rel"])
                        if key not in seen and a in nodes and b in nodes:
                            seen.add(key)
                            edges.append({"source": a, "target": b, "type": g["rel"]})
            frontier = nxt[:25]
        return {"nodes": list(nodes.values()), "edges": edges, "truncated": truncated, "center": root["id"]}

    @app.get("/v2/relationship-types")
    def v2_relationship_types(user=Depends(full)):
        return {"types": [{"id": k, "out": v[0], "in": v[1]} for k, v in E.REL_TYPES.items()], "kinds": list(E.KINDS)}

    # ── Status ────────────────────────────────────────────────────────────────
    @app.post("/v2/entity/status")
    def v2_set_status(body: StatusIn, user=Depends(full), conn=Depends(get_db)):
        ref = E.resolve_ref(conn, "indicator", body.ref)
        ioc = E.find_ioc(conn, ref)
        if not ioc:
            raise HTTPException(404, "Only tracked indicators have a status — add it as an IOC first")
        owner_or_admin = user["role"] == "admin" or ioc["created_by"] == user["id"]
        if body.status == "false_positive" and not owner_or_admin:
            raise HTTPException(403, "You can only mark your own IOCs as false positive")
        if ioc["false_positive"] and body.status != "false_positive" and not owner_or_admin:
            raise HTTPException(403, "Only the analyst who flagged it (or an admin) can lift a false-positive flag")
        try:
            E.set_status(conn, ioc, body.status, user, body.reason or "")
        except ValueError as e:
            raise HTTPException(400, str(e))
        d.audit(conn, "STATUS", ioc["id"], ioc["value"], ioc["type"], user)
        conn.commit()
        return {"status": body.status}

    # ── DNS resolution (recorded, not inferred) ───────────────────────────────
    @app.post("/v2/entity/resolve-dns")
    async def v2_resolve_dns(body: RefIn, user=Depends(full), conn=Depends(get_db)):
        key, t = E.normalize_indicator(body.ref)
        if t != "Domain" or not security.is_valid_domain(key):
            raise HTTPException(400, "DNS resolution applies to domains")
        answers = {}
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                for rtype in ("A", "AAAA"):
                    r = await c.get("https://dns.google/resolve", params={"name": key, "type": rtype},
                                    headers={"Accept": "application/json"})
                    if r.status_code == 200:
                        for a in r.json().get("Answer", []) or []:
                            ip = (a.get("data") or "").strip()
                            if security.is_valid_ip(ip):
                                answers.setdefault(rtype, []).append(ip)
        except Exception as e:
            print(f"[dns] resolution failed: {type(e).__name__}")
            raise HTTPException(502, "DNS resolver unreachable")
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        added = 0
        for rtype, ips in answers.items():
            for ip in dict.fromkeys(ips):
                if E.add_relationship(conn, "indicator", key, "resolves_to", "indicator", ip, source="dns.google",
                                      source_type="dns", source_ref=f"https://dns.google/resolve?name={key}&type={rtype}",
                                      observed_at=now, created_by=user["username"], note=f"{rtype} record"):
                    added += 1
        summary = ("; ".join(f"{k} → {', '.join(v)}" for k, v in answers.items())) or "no A/AAAA records returned"
        E.record_observation(conn, "indicator", key, "dns_resolution", "dns.google", "dns", observed_at=now,
                             actor=user["username"], summary=f"Resolved: {summary}", data=answers)
        conn.commit()
        return {"resolved": answers, "new_relationships": added}

    # ── MITRE ATT&CK associations ─────────────────────────────────────────────
    @app.post("/v2/entity/sync-mitre")
    async def v2_sync_mitre(body: RefIn, user=Depends(full), conn=Depends(get_db)):
        name = body.ref.strip()
        data = await d.mitre_lookup(name, conn)
        if not data.get("found"):
            raise HTTPException(404, f"No MITRE ATT&CK group matches '{name}'")
        added = 0
        for m in (data.get("malware_used") or [])[:25]:
            if E.add_relationship(conn, "malware", m, "used_by", "actor", name, source="MITRE ATT&CK", source_type="feed",
                                  source_ref=security.safe_http_url(data.get("mitre_url")), created_by=user["username"],
                                  note=f"ATT&CK lists {m} as software used by {data.get('name')}"):
                added += 1
        E.record_observation(conn, "actor", name, "ingested", "MITRE ATT&CK", "feed", source_ref=security.safe_http_url(data.get("mitre_url")),
                             actor=user["username"], summary=f"Imported {added} malware association(s) from ATT&CK group {data.get('name')}")
        conn.commit()
        return {"group": data.get("name"), "new_relationships": added, "malware_seen": len(data.get("malware_used") or [])}

    # ── Relationships ─────────────────────────────────────────────────────────
    @app.post("/v2/relationships", status_code=201)
    def v2_add_relationship(body: RelIn, user=Depends(full), conn=Depends(get_db)):
        try:
            rid = E.add_relationship(conn, body.src_kind, body.src_ref, body.rel_type, body.dst_kind, body.dst_ref,
                                     source=f"analyst:{user['username']}", source_type="analyst",
                                     source_ref=security.safe_http_url(body.source_ref), confidence=body.confidence,
                                     note=(body.note or None), created_by=user["username"])
        except ValueError as e:
            raise HTTPException(400, str(e))
        if rid is None:
            raise HTTPException(409, "That relationship already exists")
        conn.commit()
        return {"id": rid}

    @app.delete("/v2/relationships/{rel_id}")
    def v2_delete_relationship(rel_id: int, user=Depends(full), conn=Depends(get_db)):
        r = E.q(conn, "SELECT created_by FROM entity_relationships WHERE id = %s", (rel_id,), one=True)
        if not r:
            raise HTTPException(404, "Relationship not found")
        if user["role"] != "admin" and r["created_by"] != user["username"]:
            raise HTTPException(403, "You can only remove relationships you created")
        conn.cursor().execute("DELETE FROM entity_relationships WHERE id = %s", (rel_id,))
        conn.commit()
        return {"status": "deleted"}

    # ── Workspace ↔ entity ────────────────────────────────────────────────────
    @app.post("/v2/investigations/{inv_id}/entities", status_code=201)
    def v2_add_entity(inv_id: str, body: EntityAdd, user=Depends(full), conn=Depends(get_db)):
        h["get_investigation"](conn, inv_id)
        _check_kind(body.kind)
        if body.kind == "investigation":
            raise HTTPException(400, "An investigation cannot contain another investigation")
        ref = E.resolve_ref(conn, body.kind, body.ref)
        hd = E.header(conn, body.kind, ref)
        if hd is None:
            raise HTTPException(404, f"{body.kind} not found")
        reason = (body.reason or "").strip() or None
        if body.kind == "indicator":
            if hd["tracked"]:
                item = ("ioc", hd["id"], hd["value"], hd["type"], {})
            else:
                item = ("observable", None, hd["ref"], hd["type"], {"type": hd["type"]})
        elif body.kind == "cve":
            item = ("cve", hd["ref"], hd["ref"], hd["ref"], {})
        elif body.kind == "software":
            item = ("asset", hd["id"], hd["title"], hd["title"], {})
        else:
            item = (body.kind, hd["ref"], hd["title"], hd["title"], {})
        added = h["add_item"](conn, inv_id, item[0], item[1], item[2], item[3], item[4], user, reason=reason)
        if not added:
            if reason:
                conn.cursor().execute("""UPDATE investigation_items SET reason = %s WHERE investigation_id = %s
                    AND item_type = %s AND COALESCE(ref_id, value) = %s""", (reason, inv_id, item[0], item[1] or item[2]))
                conn.commit()
                return {"status": "updated"}
            raise HTTPException(409, "Already part of this investigation")
        noun = {"indicator": "Indicator", "cve": "CVE", "campaign": "Campaign", "actor": "Threat actor",
                "malware": "Malware", "software": "Software"}[body.kind]
        h["event"](conn, inv_id, f"{item[0]}_added", f"{noun} added: {hd['title']}" + (f" — {reason}" if reason else ""),
                   None, item[0], item[1] or item[2], user)
        conn.commit()
        return {"status": "added"}

    @app.patch("/v2/investigations/{inv_id}/items/{item_id}")
    def v2_item_reason(inv_id: str, item_id: int, body: ReasonIn, user=Depends(full), conn=Depends(get_db)):
        cur = conn.cursor()
        cur.execute("UPDATE investigation_items SET reason = %s WHERE id = %s AND investigation_id = %s",
                    ((body.reason or "").strip() or None, item_id, inv_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Item not found")
        cur.execute("UPDATE investigations SET updated_at = NOW() WHERE id = %s", (inv_id,))
        conn.commit()
        return {"status": "updated"}
