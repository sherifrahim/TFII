"""VirusSign threat intelligence (https://intel.virussign.com): indicator lookups and the event feed.

Documented API (v1): base https://api.virussign.com, key in the `x-api-key` header.
  * GET /v1/ioc/files/{hash} | /domains/{domain} | /ips/{ip} | /urls?q={url}   (view=compact|full)
  * GET /v1/feed/events  (mode, types=file,host,url, since, until, cursor, limit, format, view)
A 404 means "no record", never "safe". Quota is charged per accepted lookup, and per started block of 50 feed events,
so the feed reader is bounded: it stops after a configurable number of events and resumes from its cursor next time.

Everything here is pure or takes an httpx client, so it can be tested without a network. The key is only ever sent to
BASE, a fixed host.
"""
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional
from urllib.parse import quote

import httpx

import security

BASE = "https://api.virussign.com"
SOURCE = "VirusSign"
HOME = "https://intel.virussign.com/"
DEFAULT_RELIABILITY = 0.80          # a vendor-curated feed; an event's own confidence replaces it when present
MAX_BACKFILL_DAYS = 7               # never ask for more than a week of events in one go, however long the feed was off
PAGE_LIMIT = 50                     # their documented block size: one quota token per started block
_HASH_LEN = {32: "MD5", 40: "SHA1", 64: "SHA256"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def client_factory(**kw):
    """The HTTP client for the feed reader (the fixed VirusSign host); tests replace it with one that has a mock transport."""
    return security.safe_client(**kw)


class VirusSignError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ── Requests ──────────────────────────────────────────────────────────────────
def headers(key: str) -> dict:
    return {"x-api-key": key, "Accept": "application/json", "User-Agent": "TFII-ThreatIntel/2.0"}


def lookup_request(ioc_type: str, value: str, view: str = "full") -> Optional[tuple]:
    """(path, params) for one indicator, or None when VirusSign has no endpoint for that type."""
    if ioc_type in ("IPv4", "IPv6"):
        return f"/v1/ioc/ips/{quote(value, safe='')}", {"view": view}
    if ioc_type == "Domain":
        return f"/v1/ioc/domains/{quote(value, safe='')}", {"view": view}
    if ioc_type in ("MD5", "SHA1", "SHA256"):
        return f"/v1/ioc/files/{quote(value, safe='')}", {"view": view}
    if ioc_type == "URL":
        return "/v1/ioc/urls", {"q": value, "view": view}
    return None


def _error_code(body) -> Optional[int]:
    try:
        return int(((body or {}).get("detail") or {}).get("error", {}).get("code"))
    except (AttributeError, TypeError, ValueError):
        return None


def explain(status: int, body=None) -> Optional[str]:
    """A plain message for a failure status, or None for 200 and 404 (404 is a normal 'no record')."""
    if status in (200, 404):
        return None
    if status == 401:
        return "VirusSign rejected the API key (missing, invalid or expired)."
    if status == 403:
        if _error_code(body) == 7:
            return "VirusSign says the quota is used up."
        return "VirusSign refused the request: the quota is used up, the account is disabled, or the key lacks permission for this."
    if status == 429:
        return "VirusSign is rate limiting requests. Try again shortly."
    if status in (400, 422):
        return "VirusSign did not accept this indicator."
    return f"VirusSign returned an error (HTTP {status})."


# ── One indicator ─────────────────────────────────────────────────────────────
def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def interpret(status: int, body, headers_in=None) -> dict:
    """The enrichment answer TFII stores for one lookup. Never raises; failures become {"error": ...}."""
    msg = explain(status, body)
    if msg:
        return {"source": SOURCE, "error": msg}
    if status == 404:
        return {"source": SOURCE, "found": False, "note": "VirusSign has no record of this indicator. That is not evidence that it is safe."}
    ind = body.get("indicator") if isinstance(body, dict) and isinstance(body.get("indicator"), dict) else {}
    an = ind.get("analysis") if isinstance(ind.get("analysis"), dict) else {}
    meta = body.get("meta") if isinstance(body, dict) and isinstance(body.get("meta"), dict) else {}
    out = {"source": SOURCE, "found": True, "malicious": an.get("malicious") if isinstance(an.get("malicious"), bool) else None,
           "severity": _short(an.get("severity")), "confidence": _num(an.get("confidence")), "family": _short(an.get("family")),
           "detections": _num(an.get("detections")) if not isinstance(an.get("detections"), (list, dict)) else None,
           "first_seen": _short(ind.get("first_seen")), "last_seen": _short(ind.get("last_seen")), "link": HOME,
           "quota_remaining": _num(meta.get("quota_remaining"))}
    return {k: v for k, v in out.items() if v is not None}


def _short(v, n: int = 120) -> Optional[str]:
    if v is None or isinstance(v, (dict, list)):
        return None
    s = " ".join(str(v).split())
    return s[:n] if s else None


async def lookup(client: httpx.AsyncClient, key: str, ioc_type: str, value: str, view: str = "full") -> dict:
    """Ask VirusSign about one indicator; returns the stored answer plus the raw indicator for the report."""
    req = lookup_request(ioc_type, value, view)
    if not req:
        return {"source": SOURCE, "skipped": True}
    path, params = req
    try:
        r = await client.get(BASE + path, params=params, headers=headers(key))
    except httpx.TimeoutException:
        return {"source": SOURCE, "error": "VirusSign took too long to answer."}
    except httpx.HTTPError:
        return {"source": SOURCE, "error": "VirusSign could not be reached."}
    try:
        body = r.json()
    except ValueError:
        body = None
    out = interpret(r.status_code, body)
    if out.get("found"):
        out["_raw"] = body.get("indicator") if isinstance(body, dict) else None
    return out


# ── The feed ──────────────────────────────────────────────────────────────────
def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def plan_window(state: dict, now: datetime, backfill_days: float = 1) -> dict:
    """What to ask for this run. A saved cursor continues the previous window (the cursor remembers it); otherwise the
    window starts where the last run ended (at most MAX_BACKFILL_DAYS ago) and ends now."""
    state = state or {}
    if state.get("cursor") and state.get("since") and state.get("until"):
        return {"since": state["since"], "until": state["until"], "cursor": state["cursor"]}
    floor = now - timedelta(days=MAX_BACKFILL_DAYS)
    start = _parse_iso(state.get("until")) or (now - timedelta(days=max(0.1, min(backfill_days, MAX_BACKFILL_DAYS))))
    start = max(start, floor)
    return {"since": iso(start), "until": iso(now), "cursor": None}


async def fetch_events(client: httpx.AsyncClient, key: str, state: dict, *, max_events: int, types: str = "file,host,url",
                       now: Optional[datetime] = None, backfill_days: float = 1) -> tuple:
    """Read up to `max_events` feed events. Returns (items, new_state, meta). `new_state` is what the next run should
    start from: the same window with a cursor if there is more, else the end of this window. If a page fails after
    some succeeded, what was read is kept and the state stays at the last good cursor."""
    now = now or datetime.now(timezone.utc)
    win = plan_window(state, now, backfill_days)
    cursor, items, meta, more = win["cursor"], [], {}, False
    pages = 0
    while len(items) < max_events:
        params = {"mode": "events", "types": types, "since": win["since"], "until": win["until"], "view": "full",
                  "limit": max(1, min(PAGE_LIMIT, max_events - len(items))), "format": "native"}
        if cursor:
            params["cursor"] = cursor
        try:
            r = await client.get(BASE + "/v1/feed/events", params=params, headers=headers(key))
        except httpx.TimeoutException:
            err = VirusSignError(504, "VirusSign took too long to answer.")
        except httpx.HTTPError:
            err = VirusSignError(502, "VirusSign could not be reached.")
        else:
            try:
                body = r.json()
            except ValueError:
                body = None
            msg = explain(r.status_code, body)
            err = VirusSignError(r.status_code, msg) if msg else (None if isinstance(body, dict) else VirusSignError(502, "VirusSign sent an answer TFII could not read."))
        if err:
            if not pages:
                raise err
            meta["stopped"] = err.message                    # keep what was read; the state below resumes at the last good cursor
            break
        pages += 1
        m = body.get("meta") if isinstance(body.get("meta"), dict) else {}
        meta = {**meta, "quota_remaining": _num(m.get("quota_remaining")), "returned": (meta.get("returned") or 0) + len(body.get("items") or [])}
        items.extend(i for i in (body.get("items") or []) if isinstance(i, dict))
        more = bool(m.get("has_next")) and bool(m.get("next_cursor"))
        cursor = m.get("next_cursor") or cursor
        if not more:
            break
    meta["pages"] = pages
    if more or meta.get("stopped"):
        new_state = {"since": win["since"], "until": win["until"], "cursor": cursor}
    else:
        new_state = {"until": win["until"]}
    return items, new_state, meta


# ── Events into candidates ────────────────────────────────────────────────────
def classify(value: str, hint: str = "") -> Optional[str]:
    """TFII's type for a feed value: IPv4 | IPv6 | Domain | URL | MD5 | SHA1 | SHA256, or None."""
    v = (value or "").strip()
    if not v:
        return None
    if re.match(r"^https?://", v, re.I) or (hint or "").lower() == "url":
        return "URL"
    if _HEX.match(v) and len(v) in _HASH_LEN:
        return _HASH_LEN[len(v)]
    if security.is_valid_ip(v):
        return "IPv6" if ":" in v else "IPv4"
    return "Domain" if security.is_valid_domain(v.lower().rstrip(".")) else None


def reliability(analysis: dict) -> float:
    c = _num((analysis or {}).get("confidence"))
    if c is None:
        return DEFAULT_RELIABILITY
    return max(0.30, min(0.95, c / 100.0))


def parse_events(items: list) -> dict:
    """Feed items into what TFII ingests. `upserts` are malicious indicators; `revocations` are withdrawals; items VirusSign
    assessed as not malicious, or that cannot be typed, are counted and dropped. Duplicate event ids are ignored."""
    upserts, revocations, seen, not_malicious, untyped = [], [], set(), 0, 0
    for it in items or []:
        if not isinstance(it, dict):
            continue
        eid = it.get("id")
        if eid:
            if eid in seen:
                continue
            seen.add(eid)
        ind = it.get("indicator") if isinstance(it.get("indicator"), dict) else {}
        an = it.get("analysis") if isinstance(it.get("analysis"), dict) else {}
        typ = classify(str(ind.get("value") or ""), str(ind.get("type") or ""))
        if not typ:
            untyped += 1
            continue
        revoked = str(it.get("action") or "").lower() == "revoke"
        if not revoked and an.get("malicious") is False:
            not_malicious += 1
            continue
        val = ind.get("value")
        validity = it.get("validity") if isinstance(it.get("validity"), dict) else {}
        tags = [str(t).lower()[:30] for t in (it.get("tags") or []) if isinstance(t, (str, int))][:4]
        fam = _short(an.get("family"), 60)
        row = {"type": typ, "value": str(val).strip(), "revoked": revoked, "reliability": reliability(an), "family": fam,
               "tags": list(dict.fromkeys(["virussign"] + ([fam.lower()] if fam else []) + tags))[:6],
               "first_seen": _parse_iso(validity.get("first_seen")), "event_id": eid,
               "confidence": _num(an.get("confidence")),
               "context": {k: v for k, v in {"severity": _short(an.get("severity")), "reason": _short(it.get("reason"), 40)}.items() if v}}
        (revocations if revoked else upserts).append(row)
    return {"upserts": upserts, "revocations": revocations, "not_malicious": not_malicious, "untyped": untyped}
