"""Richer DNS records for a domain, from the public NSLookup.io API.

No API key: the API is public and limited to 30 requests a minute *per IP address*, so every TFII user shares
that budget. Three things follow: results are cached (see the dns_intel_cache table), requests are paced
below the limit (`Throttle`), and each user is limited separately so one person cannot use it all up.

One lookup is three requests: the common records (A, AAAA, NS, MX, TXT, CNAME, SOA), CAA, and the `_dmarc`
TXT record. SPF is parsed from the TXT records here (the API's SPF endpoint returns raw TXT, not parsed data).

Record TTLs are deliberately not reported: through a caching resolver they are the *remaining* cache time, not
the value the zone publishes.
"""
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

BASE = "https://www.nslookup.io"
HEADERS = {"User-Agent": "TFII-threat-intel/1.0", "Accept": "application/json"}
RESOLVER = "cloudflare"          # a public recursive resolver; "authoritative" would query the zone's own servers
CACHE_HOURS = 6
REFRESH_COOLDOWN_MINUTES = 10


class DnsApiError(Exception):
    """`kind`: rate_limited | busy | invalid | unavailable."""
    def __init__(self, kind, message=""):
        super().__init__(message or kind)
        self.kind = kind


class Throttle:
    """Keeps TFII under NSLookup.io's per-IP limit. Each request reserves the next free slot; a caller that would
    wait longer than `max_wait` is refused (better than a UI that hangs)."""
    def __init__(self, per_minute: int = 24, max_wait: float = 25.0):
        self.gap, self.max_wait, self._next = 60.0 / per_minute, max_wait, 0.0

    async def wait(self, n: int = 1):
        import asyncio
        now = time.monotonic()
        start = max(now, self._next)
        if start - now > self.max_wait:
            raise DnsApiError("busy", f"DNS lookups are busy; try again in {int(start - now)}s")
        self._next = start + self.gap * n
        if start > now:
            await asyncio.sleep(start - now)

    def backoff(self, seconds: float):
        self._next = max(self._next, time.monotonic() + max(0.0, seconds))


THROTTLE = Throttle()


class UserLimiter:
    """At most `limit` lookups per user per minute (in memory; a restart clears it)."""
    def __init__(self, limit: int = 6, window: float = 60.0):
        self.limit, self.window, self._hits = limit, window, defaultdict(deque)

    def allow(self, user_id: str) -> bool:
        now = time.monotonic()
        q = self._hits[user_id]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


USER_LIMIT = UserLimiter()


async def _get(client: httpx.AsyncClient, path: str, params: dict, throttle: Throttle) -> dict:
    await throttle.wait()
    try:
        r = await client.get(BASE + path, params=params, headers=HEADERS)
    except (httpx.TimeoutException, httpx.TransportError):
        raise DnsApiError("unavailable", "NSLookup.io could not be reached")
    try:                                                    # the API says how long until its window resets
        if int(r.headers.get("x-ratelimit-remaining", "1")) <= 0:
            throttle.backoff(float(r.headers.get("x-ratelimit-reset", "30")))
    except ValueError:
        pass
    if r.status_code == 429:
        throttle.backoff(30)
        raise DnsApiError("rate_limited", "NSLookup.io is rate limiting requests; try again in a minute")
    if r.status_code in (400, 422):
        raise DnsApiError("invalid", "NSLookup.io rejected that domain name")
    if r.status_code != 200:
        raise DnsApiError("unavailable", f"NSLookup.io answered HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise DnsApiError("unavailable", "NSLookup.io sent an unreadable answer")


# ── parsing (pure) ───────────────────────────────────────────────────────────
def _answers(section) -> List[dict]:
    resp = (section or {}).get("response") or {}
    return [a for a in (resp.get("answer") or []) if isinstance(a, dict) and isinstance(a.get("record"), dict)]


def _rcode(section) -> Optional[str]:
    return ((section or {}).get("response") or {}).get("rCode")


def _s(v, n=300) -> str:
    return str(v)[:n] if v is not None else ""


def _ipinfo(info) -> Optional[dict]:
    if not isinstance(info, dict):
        return None
    out = {"country": info.get("country"), "region": info.get("regionName"), "city": info.get("city"),
           "org": info.get("org"), "asn": info.get("as"), "asname": info.get("asname")}
    return {k: v for k, v in out.items() if v} or None


def _txt(rec) -> str:
    strings = rec.get("strings")
    return "".join(str(x) for x in strings) if isinstance(strings, list) and strings else _s(rec.get("raw")).strip('"')


def parse_spf(txts: List[str]) -> Optional[dict]:
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        return None
    rec = spf[0]
    terms = rec.split()[1:]
    all_term = next((t for t in terms if t.lower().lstrip("+-~?") == "all"), None)
    q = (all_term or "")[:1] if (all_term or "")[:1] in "+-~?" else ("+" if all_term else "")
    return {"record": rec[:600], "all": {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass"}.get(q, "none"),
            "includes": [t.split(":", 1)[1] for t in terms if t.lower().startswith("include:")][:12],
            "ip_mechanisms": sum(1 for t in terms if re.match(r"^[+\-~?]?ip[46]:", t.lower())),
            "duplicates": len(spf) > 1}


def parse_dmarc(txts: List[str]) -> Optional[dict]:
    rec = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
    if not rec:
        return None
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return {"record": rec[:600], "policy": (tags.get("p") or "").lower() or None, "subdomain_policy": (tags.get("sp") or "").lower() or None,
            "pct": tags.get("pct"), "rua": [x.strip() for x in tags.get("rua", "").split(",") if x.strip()][:4]}


def parse_records(common: dict, caa: Optional[dict] = None, dmarc: Optional[dict] = None) -> dict:
    recs = (common or {}).get("records") or {}
    out: Dict[str, object] = {"domain": (common or {}).get("unicodeDomain") or (common or {}).get("punycodeDomain")}

    def rows(key):
        return [a["record"] for a in _answers(recs.get(key))]

    a_rows = []
    for a in _answers(recs.get("a")) + _answers(recs.get("aaaa")):
        r = a["record"]
        ip = r.get("ipv4") or r.get("ipv6") or _s(r.get("raw"))
        a_rows.append({"ip": ip, "geo": _ipinfo(a.get("ipInfo"))})
    out["addresses"] = a_rows[:25]
    out["cname"] = [_s(r.get("target") or r.get("raw")) for r in rows("cname")][:5]
    out["ns"] = sorted({_s(r.get("target") or r.get("raw")).rstrip(".").lower() for r in rows("ns")})[:20]
    out["mx"] = sorted(({"priority": r.get("priority"), "host": _s(r.get("target") or r.get("raw")).rstrip(".").lower()} for r in rows("mx")),
                       key=lambda m: (m["priority"] if isinstance(m["priority"], int) else 99, m["host"]))[:10]
    txts = [_txt(r) for r in rows("txt")]
    out["txt"] = [t[:400] for t in txts][:40]
    soa = next(iter(rows("soa")), None)
    out["soa"] = ({k: soa.get(k) for k in ("host", "admin", "serial", "refresh", "retry", "expire", "minimum")} if soa else None)
    out["caa"] = [{"flags": r.get("flags"), "tag": r.get("tag"), "value": _s(r.get("value"))} for r in [a["record"] for a in _answers(((caa or {}).get("queryResult")))]][:12]
    out["spf"] = parse_spf(txts)
    dm = [_txt(a["record"]) for a in _answers((dmarc or {}).get("queryResult"))]
    out["dmarc"] = parse_dmarc(dm)
    out["rcode"] = _rcode(recs.get("a"))
    return out


def signals(d: dict) -> List[dict]:
    """Plain-language observations. Each is a fact about the published records, not a verdict on the domain."""
    out: List[dict] = []
    add = lambda level, text: out.append({"level": level, "text": text})  # noqa: E731
    if not d["addresses"] and not d["cname"]:
        add("info", "The name does not resolve (no A, AAAA or CNAME record).")
    nets = {(a["geo"] or {}).get("asn") for a in d["addresses"] if a.get("geo")}
    nets.discard(None)
    if len(nets) >= 3:
        add("info", f"Resolves to addresses in {len(nets)} different networks.")
    spf, dmarc = d.get("spf"), d.get("dmarc")
    null_mail = bool(spf) and spf["all"] == "fail" and not d["mx"] and not spf["includes"] and not spf["ip_mechanisms"]
    if null_mail:
        add("ok", "Publishes 'v=spf1 -all' and no MX: the domain is set up to send and receive no mail.")
    else:
        if not spf:
            add("warn", "No SPF record: nothing says which servers may send mail as this domain, so it is easy to spoof.")
        elif spf["duplicates"]:
            add("warn", "More than one SPF record: receivers treat that as an error, so SPF does not protect the domain.")
        elif spf["all"] in ("pass", "neutral"):
            add("warn", "SPF ends in a permissive rule (+all or ?all): any server is allowed to send as this domain.")
        elif spf["all"] == "none":
            add("info", "SPF has no final 'all' rule, so receivers apply no policy to other senders.")
        if not dmarc:
            add("warn", "No DMARC record: receivers are not told what to do with mail that fails authentication.")
        elif dmarc["policy"] == "none":
            add("info", "DMARC policy is 'none': it only monitors, and spoofed mail is still delivered.")
        elif dmarc["policy"] in ("quarantine", "reject"):
            add("ok", f"DMARC policy is '{dmarc['policy']}'.")
    if not d["caa"]:
        add("info", "No CAA record: any certificate authority may issue certificates for this domain.")
    return out


def summarize(common, caa, dmarc, resolver=RESOLVER) -> dict:
    d = parse_records(common, caa, dmarc)
    d["signals"] = signals(d)
    d["resolver"] = resolver
    d["source"] = "nslookup.io"
    d["fetched_at"] = datetime.now(timezone.utc).isoformat()
    return d


async def lookup(domain: str, client: Optional[httpx.AsyncClient] = None, throttle: Throttle = THROTTLE) -> dict:
    """Fetch and summarise. Raises DnsApiError. A missing CAA or _dmarc answer degrades the result instead of failing it."""
    own = client is None
    c = client or httpx.AsyncClient(timeout=20)
    try:
        common = await _get(c, "/api/v1/records", {"domain": domain, "server": RESOLVER}, throttle)
        extra = []
        for params in ({"domain": domain, "type": "CAA", "server": RESOLVER}, {"domain": "_dmarc." + domain, "type": "TXT", "server": RESOLVER}):
            try:
                extra.append(await _get(c, "/api/v1/records/other", params, throttle))
            except DnsApiError as e:
                if e.kind in ("busy", "rate_limited"):
                    extra.append(None)              # keep what we have rather than lose the whole answer
                else:
                    raise
        return summarize(common, extra[0], extra[1])
    finally:
        if own:
            await c.aclose()
