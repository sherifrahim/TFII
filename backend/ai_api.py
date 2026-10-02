"""AI assistant endpoints. Each one gathers the facts, hands them to ai.py, and returns a labelled, bounded answer.

Who may call them: the "AI tools" permission (the same one the query builder needs). The ones that read tracked
data (an indicator, an investigation) also need full workspace access, like the screens they sit on. Whose key pays:
the caller's own Groq key, then their own CodeCraft key, then the platform's Groq key, which is capped per person
per day so one account cannot spend everyone's quota.
"""
from datetime import datetime, timezone
from typing import List, Optional

import httpx
import psycopg2.extras
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

import ai
from dnsintel import UserLimiter

AI_LIMIT = UserLimiter(limit=10)            # per user per minute
PLATFORM_DAILY = 40                          # platform-key AI answers per non-admin user per day


class ReportBody(BaseModel):
    values: List[str] = Field(..., min_length=1, max_length=10)


class TriageBody(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=500)


class DigestRow(BaseModel):
    value: str = Field("", max_length=300)
    type: Optional[str] = Field(None, max_length=20)
    verdict: Optional[str] = Field(None, max_length=20)
    score: Optional[int] = None
    reason: Optional[str] = Field(None, max_length=400)
    country: Optional[str] = Field(None, max_length=80)
    owner: Optional[str] = Field(None, max_length=120)


class DigestBody(BaseModel):
    rows: List[DigestRow] = Field(..., min_length=1, max_length=150)


class InvestigationBody(BaseModel):
    id: str = Field(..., min_length=1, max_length=100)


class SearchBody(BaseModel):
    q: str = Field(..., min_length=2, max_length=300)


class ModelBody(BaseModel):
    model: str = Field(..., min_length=1, max_length=100)


class MailBody(BaseModel):
    address: str = Field(..., min_length=3, max_length=320)
    analysis: dict = Field(default_factory=dict)


def register(app, d):
    get_db, full, current = d.get_db, d.require_full_access, d.get_current_user
    ai_cap = d.require_cap("tools.ai")

    def _full_ai(user=Depends(ai_cap), conn=Depends(get_db)):
        if "data.workspace" not in d.effective_caps(user, conn):
            raise HTTPException(status_code=403, detail="This needs full workspace access.")
        return user

    def _rows(conn, sql, params=()):
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(sql, params)
            return cur.fetchall()
        except Exception:                                   # a missing optional table must not break the answer
            conn.rollback()
            return []

    def _chosen_model(conn, user):
        rows = _rows(conn, "SELECT codecraft_model FROM user_ai_prefs WHERE user_id=%s", (user["id"],))
        return (rows[0]["codecraft_model"] if rows and rows[0].get("codecraft_model") else None) or d.CODECRAFT_MODEL

    def _provider(conn, user):
        return ai.choose_provider(d.get_own_key(conn, user["id"], "groq"), d.get_own_key(conn, user["id"], "codecraft"),
                                  d.PLATFORM_KEYS.get("groq", ""), d.GROQ_MODEL, _chosen_model(conn, user))

    async def _run(task, user, conn, context, ask="", system=None, max_tokens=900, clean=ai.clean_answer):
        if not AI_LIMIT.allow(user["id"]):
            raise HTTPException(status_code=429, detail="Too many AI requests. Wait a minute.")
        prov = _provider(conn, user)
        if not prov:
            raise HTTPException(status_code=503, detail="No AI key is available. Add a Groq or CodeCraft key in Settings → API keys.")
        if not prov.personal and user.get("role") != "admin":
            if d.get_user_daily_usage(conn, user["id"], "groq") >= PLATFORM_DAILY:
                raise HTTPException(status_code=429, detail=f"Daily limit of {PLATFORM_DAILY} AI answers on the shared key reached. "
                                                            "Add your own Groq or CodeCraft key in Settings to continue.")
        info = {}
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                text = await ai.complete(client, prov, system or ai.system_prompt(task), ai.user_prompt(context, ask), max_tokens, info=info)
            result = clean(ai.parse_json(text))
        except ai.AiError as e:
            raise HTTPException(status_code=e.status, detail=e.message)
        if not prov.personal:
            d.log_api_call(conn, "groq", f"ai:{task}", False, user["id"])
            conn.commit()
        return {"kind": task, "result": result, "ai_generated": True, "provider": prov.label, "model": prov.model,
                "usage": info.get("usage"), "generated_at": datetime.now(timezone.utc).isoformat()}

    @app.get("/v2/ai/status")
    def ai_status(user=Depends(current), conn=Depends(get_db)):
        caps = d.effective_caps(user, conn)
        prov = _provider(conn, user)
        return {"allowed": "tools.ai" in caps, "available": bool(prov) and "tools.ai" in caps,
                "provider": prov.label if prov else None, "personal": bool(prov and prov.personal)}

    @app.post("/v2/ai/report-summary")
    async def ai_report(body: ReportBody, user=Depends(ai_cap), conn=Depends(get_db)):
        items = []
        for v in dict.fromkeys(x.strip() for x in body.values if x.strip()):
            data = d.load_detail_report(conn, user["id"], v)
            if data:
                items.append(data)
        if not items:
            raise HTTPException(status_code=404, detail="No report data to summarise. Run the lookup again, then open the report.")
        return await _run("report", user, conn, ai.report_context(items), max_tokens=1100)

    @app.post("/v2/ai/triage")
    async def ai_triage(body: TriageBody, user=Depends(_full_ai), conn=Depends(get_db)):
        ref = body.ioc.strip()
        rows = _rows(conn, """SELECT i.id, i.type, i.value, i.tlp, i.confidence, i.description, i.tags, i.valid_until, i.false_positive,
                   i.fp_reason, i.enrichment, i.created_at, c.name AS campaign, c.threat_actor
                FROM iocs i LEFT JOIN campaigns c ON c.id=i.campaign_id WHERE i.id=%s OR i.value=%s LIMIT 1""", (ref, d.refang(ref)))
        if not rows:
            raise HTTPException(status_code=404, detail="Indicator not found.")
        r = rows[0]
        enr = r.get("enrichment") if isinstance(r.get("enrichment"), dict) else {}
        sources = {name: {k: ai.clip(v, 120) for k, v in list(val.items())[:14] if isinstance(v, (str, int, float, bool))}
                   for name, val in enr.items() if isinstance(val, dict)}
        rels = _rows(conn, """SELECT r.relationship_type, CASE WHEN r.source_id=%s THEN t.value ELSE s.value END AS other
                FROM ioc_relationships r LEFT JOIN iocs s ON s.id=r.source_id LEFT JOIN iocs t ON t.id=r.target_id
                WHERE r.source_id=%s OR r.target_id=%s LIMIT 10""", (r["id"], r["id"], r["id"]))
        notes = _rows(conn, "SELECT note FROM ioc_notes WHERE ioc_id=%s ORDER BY created_at DESC LIMIT 5", (r["id"],))
        hist = _rows(conn, "SELECT old_score, new_score, reason FROM ioc_score_history WHERE ioc_id=%s ORDER BY created_at DESC LIMIT 5", (r["id"],))
        prov = _rows(conn, "SELECT source_type, source_ref, confidence_label, context FROM ioc_provenance WHERE ioc_id=%s LIMIT 8", (r["id"],))
        ctx = {"indicator": ai.clip(r["value"], 300), "type": r["type"], "tlp": r["tlp"], "confidence": r["confidence"],
               "first_seen": str(r["created_at"])[:10], "expires": str(r["valid_until"])[:10] if r.get("valid_until") else None,
               "marked_false_positive": bool(r.get("false_positive")), "false_positive_reason": ai.clip(r.get("fp_reason"), 200),
               "description": ai.clip(r.get("description"), 400), "tags": [ai.clip(t, 40) for t in (r.get("tags") or [])[:15]],
               "campaign": ai.clip(r.get("campaign"), 80), "threat_actor": ai.clip(r.get("threat_actor"), 80),
               "provider_enrichment": sources,
               "related_indicators": [{"relation": x["relationship_type"], "indicator": ai.clip(x["other"], 120)} for x in rels if x.get("other")],
               "analyst_notes": [ai.clip(n["note"], 300) for n in notes],
               "score_history": [{"from": h["old_score"], "to": h["new_score"], "why": ai.clip(h["reason"], 160)} for h in hist],
               "where_it_came_from": [{k: ai.clip(v, 120) for k, v in p.items()} for p in prov]}
        return await _run("triage", user, conn, ctx, max_tokens=1000)

    @app.post("/v2/ai/bulk-digest")
    async def ai_digest(body: DigestBody, user=Depends(ai_cap), conn=Depends(get_db)):
        return await _run("digest", user, conn, ai.digest_context([r.model_dump() for r in body.rows]), max_tokens=1100)

    @app.post("/v2/ai/investigation")
    async def ai_investigation(body: InvestigationBody, user=Depends(_full_ai), conn=Depends(get_db)):
        inv = _rows(conn, "SELECT name, description, status, severity, tags, owner_name, created_at FROM investigations WHERE id=%s", (body.id,))
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        items = _rows(conn, """SELECT it.item_type, it.value, it.label, i.type AS ioc_type, i.value AS ioc_value, i.confidence,
                   i.enrichment->>'malware_family' AS malware_family
                FROM investigation_items it LEFT JOIN iocs i ON it.item_type='ioc' AND i.id=it.ref_id
                WHERE it.investigation_id=%s ORDER BY it.created_at DESC LIMIT 60""", (body.id,))
        events = _rows(conn, """SELECT event_type, title, body, occurred_at FROM investigation_events
                WHERE investigation_id=%s ORDER BY occurred_at DESC, id DESC LIMIT 25""", (body.id,))
        notes = _rows(conn, """SELECT title, content FROM admin_notes WHERE investigation_id=%s AND COALESCE(archived, FALSE)=FALSE
                ORDER BY pinned DESC, updated_at DESC LIMIT 8""", (body.id,))
        i0 = inv[0]
        ctx = {"investigation": {"name": ai.clip(i0["name"], 160), "description": ai.clip(i0.get("description"), 600), "status": i0["status"],
                                 "severity": i0["severity"], "tags": [ai.clip(t, 40) for t in (i0.get("tags") or [])[:12]],
                                 "opened": str(i0["created_at"])[:10]},
               "items": [{"kind": x["item_type"], "value": ai.clip(x.get("ioc_value") or x.get("value") or x.get("label"), 140),
                          "indicator_type": x.get("ioc_type"), "confidence": x.get("confidence"),
                          "malware_family": ai.clip(x.get("malware_family"), 60)} for x in items],
               "timeline": [{"when": str(e["occurred_at"])[:16], "type": e["event_type"], "title": ai.clip(e["title"], 140),
                             "detail": ai.clip(e.get("body"), 240)} for e in events],
               "notes": [{"title": ai.clip(n.get("title"), 80), "text": ai.clip(n.get("content"), 400)} for n in notes]}
        return await _run("investigation", user, conn, ctx, max_tokens=1400)

    @app.post("/v2/ai/search")
    async def ai_search(body: SearchBody, user=Depends(_full_ai), conn=Depends(get_db)):
        out = await _run("search", user, conn, {"request": ai.clip(body.q, 300)}, system=ai.SEARCH_SYSTEM, max_tokens=300,
                         clean=ai.clean_filters)
        r = out["result"]
        if not r["filters"]:
            raise HTTPException(status_code=422, detail=r["explanation"] or "That could not be turned into filters. Try describing type, severity, age or source.")
        return out

    @app.post("/v2/ai/mail")
    async def ai_mail(body: MailBody, user=Depends(ai_cap), conn=Depends(get_db)):
        ctx = {"address": ai.clip(body.address, 200), "analysis": body.analysis}
        return await _run("mail", user, conn, ctx, max_tokens=900)


    # ── CodeCraft: is the key working, which models does it offer, how much room is left ──────────────────
    QUOTA_NOTE = ("CodeCraft does not report your remaining monthly tokens through its API, so TFII cannot show that number. "
                  "The limits above are your per-minute allowance; the monthly balance is on your CodeCraft dashboard. "
                  "When it runs out, AI buttons say the account is out of balance.")

    def _codecraft(conn, user):
        key = d.get_own_key(conn, user["id"], "codecraft")
        if not key:
            raise HTTPException(status_code=404, detail="Save your CodeCraft key first (Settings → API keys).")
        return ai.Provider("codecraft", key, ai.CODECRAFT_BASE, _chosen_model(conn, user), True, False)

    @app.get("/v2/ai/codecraft")
    async def codecraft_models(user=Depends(current), conn=Depends(get_db)):
        """The models this person's key can use, the one their AI buttons use, and the per-minute limits."""
        if not d.get_own_key(conn, user["id"], "codecraft"):
            return {"has_key": False}
        prov = _codecraft(conn, user)
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                models, rate = await ai.list_models(client, prov)
        except ai.AiError as e:
            return {"has_key": True, "ok": False, "message": e.message, "selected": prov.model, "default": d.CODECRAFT_MODEL}
        ids = {m["id"] for m in models}
        return {"has_key": True, "ok": True, "models": models, "selected": prov.model, "selected_available": prov.model in ids if ids else None,
                "default": d.CODECRAFT_MODEL, "rate": rate, "quota_note": QUOTA_NOTE}

    @app.put("/v2/ai/codecraft/model")
    async def codecraft_choose_model(body: ModelBody, user=Depends(current), conn=Depends(get_db)):
        model = body.model.strip()
        if not ai.MODEL_ID.match(model):
            raise HTTPException(status_code=422, detail="That is not a valid model name.")
        prov = _codecraft(conn, user)
        try:                                                # only a model the key can actually use may be chosen
            async with httpx.AsyncClient(timeout=20) as client:
                models, _ = await ai.list_models(client, prov)
        except ai.AiError as e:
            raise HTTPException(status_code=e.status, detail=e.message)
        if models and model not in {m["id"] for m in models}:
            raise HTTPException(status_code=422, detail="Your key does not offer that model.")
        cur = conn.cursor()
        cur.execute("""INSERT INTO user_ai_prefs (user_id, codecraft_model, updated_at) VALUES (%s,%s,NOW())
                       ON CONFLICT (user_id) DO UPDATE SET codecraft_model=EXCLUDED.codecraft_model, updated_at=NOW()""", (user["id"], model))
        conn.commit()
        return {"selected": model}

    @app.post("/v2/ai/codecraft/test")
    async def codecraft_test(user=Depends(current), conn=Depends(get_db)):
        """One tiny real request with the chosen model: proves the key, the model and the account all work, and reports
        what it cost in tokens and what is left of the per-minute limits."""
        import time
        if not AI_LIMIT.allow(user["id"]):
            raise HTTPException(status_code=429, detail="Too many AI requests. Wait a minute.")
        prov = _codecraft(conn, user)
        model_row, listed = None, True
        async with httpx.AsyncClient(timeout=60) as client:
            try:
                models, _ = await ai.list_models(client, prov)
                model_row = next((m for m in models if m["id"] == prov.model), None)
            except ai.AiError:
                listed = False                              # a key without the models:read scope can still chat
            info, started = {}, time.monotonic()
            try:
                text = await ai.complete(client, prov, "Reply with exactly one word.", "Say: ok", 16, info=info)
            except ai.AiError as e:
                return {"ok": False, "model": prov.model, "message": e.message, "rate": info.get("rate")}
        usage = info.get("usage") or {}
        return {"ok": True, "model": prov.model, "model_name": model_row["name"] if model_row else None, "listed": listed and model_row is not None,
                "reply": ai.clip(text, 60), "latency_ms": int((time.monotonic() - started) * 1000), "usage": usage, "rate": info.get("rate"),
                "cost_usd": ai.estimate_cost(model_row, usage), "quota_note": QUOTA_NOTE}
