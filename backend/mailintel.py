"""What can honestly be said about an email address, a mailbox, or a mail domain.

No public service rates an individual mailbox for free (HaveIBeenPwned is paid, EmailRep stopped issuing keys),
so TFII judges the part that can be checked:

  * the DOMAIN behind the address: VirusTotal / URLhaus reputation, how new it is (registration date), and how
    it is set up for mail (MX, SPF, DMARC), which is what makes a sender easy or hard to spoof;
  * the kind of provider: a free mailbox service (the domain tells you nothing about the person) or a known
    disposable-mail service;
  * the address itself, only where a source actually answers for it (AlienVault OTX, when it has the address in
    a pulse).

Everything returned is a labelled fact or observation. A clean domain never turns an address "clean": for free
mailbox providers the verdict stays "unknown" because anyone can open an account there.
"""
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import httpx

import dnsintel
import security

# Free mailbox providers: the domain's reputation says nothing about the person behind the address.
FREE_MAIL = frozenset((
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
    "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com", "126.com", "web.de",
    "fastmail.com", "tutanota.com", "tuta.com", "tutanota.de", "hey.com", "duck.com",
))

# A short, well-known set of disposable / temporary mail services. Deliberately small and not exhaustive:
# a miss means "not on this list", never "not disposable".
DISPOSABLE = frozenset((
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org", "guerrillamail.biz", "sharklasers.com",
    "grr.la", "10minutemail.com", "10minutemail.net", "temp-mail.org", "tempmail.com", "tempmail.net", "yopmail.com",
    "yopmail.fr", "throwawaymail.com", "trashmail.com", "trashmail.net", "getnada.com", "maildrop.cc", "dispostable.com",
    "fakeinbox.com", "mailnesia.com", "mintemail.com", "mytemp.email", "tempail.com", "moakt.com", "emailondeck.com",
    "burnermail.io", "discard.email", "spamgourmet.com", "mohmal.com", "tempr.email", "temp-mail.io", "fakemail.net",
))

# Names that attackers pick to look official, or that are shared role mailboxes.
ROLE_NAMES = frozenset((
    "support", "helpdesk", "billing", "invoice", "invoices", "payroll", "accounts", "accounting", "security", "admin",
    "administrator", "noreply", "no-reply", "service", "verify", "verification", "postmaster", "webmaster", "abuse",
    "hr", "it", "itsupport", "notification", "notifications", "alert", "alerts", "recovery",
))

DOH = "https://dns.google/resolve"


def split_email(value: str) -> Optional[Tuple[str, str]]:
    """(local part, ASCII domain) of a plausible address, else None. Takes one '@'; IP literals are rejected."""
    v = (value or "").strip()
    if v.count("@") != 1 or any(c.isspace() for c in v):
        return None
    local, domain = v.split("@")
    if not local or len(local) > 64:
        return None
    domain = domain.strip().lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if "." not in domain or security.is_valid_ip(domain) or not security.is_valid_domain(domain):
        return None
    return local, domain


def provider_kind(domain: str) -> Optional[str]:
    d = (domain or "").lower()
    if d in DISPOSABLE:
        return "disposable"
    if d in FREE_MAIL:
        return "free"
    return None


def role_name(local: str) -> Optional[str]:
    base = re.split(r"[+]", (local or "").lower(), 1)[0]
    return base if base in ROLE_NAMES else None


# ── DNS posture (public DNS-over-HTTPS; no key, no per-user quota) ─────────────
def _txt_value(data: str) -> str:
    """dns.google returns TXT data as one or more quoted chunks: join them."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data or "")
    return "".join(parts) if parts else (data or "").strip('"')


async def _doh(client: httpx.AsyncClient, name: str, rtype: str) -> Tuple[Optional[int], List[dict]]:
    try:
        r = await client.get(DOH, params={"name": name, "type": rtype}, headers={"Accept": "application/json"})
    except (httpx.HTTPError, ValueError):
        return None, []
    if r.status_code != 200:
        return None, []
    try:
        j = r.json()
    except ValueError:
        return None, []
    return j.get("Status"), [a for a in (j.get("Answer") or []) if isinstance(a, dict)]


async def mail_posture(domain: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    """MX, SPF and DMARC for a domain. `exists` is False only when the resolver says the name does not exist
    (NXDOMAIN); `checked` is False when the resolver could not be asked at all, so nothing is claimed."""
    own = client is None
    c = client or httpx.AsyncClient(timeout=6)
    try:
        mx_status, mx_ans = await _doh(c, domain, "MX")
        txt_status, txt_ans = await _doh(c, domain, "TXT")
        _ds, dmarc_ans = await _doh(c, "_dmarc." + domain, "TXT")
    finally:
        if own:
            await c.aclose()
    if mx_status is None and txt_status is None:
        return {"checked": False}
    mx = []
    for a in mx_ans:
        if a.get("type") == 15:
            parts = str(a.get("data", "")).split()
            if len(parts) == 2:
                mx.append({"priority": int(parts[0]) if parts[0].isdigit() else None, "host": parts[1].rstrip(".")})
    mx.sort(key=lambda m: (m["priority"] is None, m["priority"] or 0))
    txts = [_txt_value(a.get("data", "")) for a in txt_ans if a.get("type") == 16]
    dtxts = [_txt_value(a.get("data", "")) for a in dmarc_ans if a.get("type") == 16]
    return {
        "checked": True, "exists": mx_status != 3 and txt_status != 3,
        "mx": mx[:8], "null_mx": bool(mx) and all(m["host"] == "" for m in mx),
        "spf": dnsintel.parse_spf(txts), "dmarc": dnsintel.parse_dmarc(dtxts),
    }


def registration_age_days(registration: Optional[dict], now: Optional[datetime] = None) -> Optional[int]:
    created = (registration or {}).get("created")
    if not created:
        return None
    try:
        d = datetime.strptime(created[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    days = ((now or datetime.now(timezone.utc)) - d).days
    return days if days >= 0 else None


def signals(local: str, domain: str, kind: Optional[str], posture: Optional[dict], registration: Optional[dict] = None,
            now: Optional[datetime] = None) -> List[dict]:
    """Plain-language observations. Each is a fact about the address or its domain, not a verdict on the person."""
    out: List[dict] = []
    add = lambda level, text, code: out.append({"level": level, "text": text, "code": code})  # noqa: E731
    if kind == "free":
        add("info", f"{domain} is a free mailbox service: anyone can register an address there, so the domain says nothing about this person.", "free_mail")
    elif kind == "disposable":
        add("warn", f"{domain} is a known disposable / temporary mail service.", "disposable")
    role = role_name(local)
    if role:
        add("info", f"'{role}' is a role-style name: shared mailboxes use it, and so do attackers posing as support, billing or security.", "role_name")
    if kind == "free":
        return out
    age = registration_age_days(registration, now)
    if age is not None:
        if age <= 30:
            add("warn", f"The domain was registered {age} day{'s' if age != 1 else ''} ago. Very new domains are a common sign of throwaway phishing infrastructure.", "new_domain")
        elif age <= 180:
            add("info", f"The domain was registered {age} days ago.", "recent_domain")
    p = posture or {}
    if not p.get("checked"):
        return out
    if not p.get("exists", True):
        add("warn", "The domain does not exist (NXDOMAIN): mail cannot be delivered to it, and a sender using it is forged or the domain has been taken down.", "nxdomain")
        return out
    if p.get("null_mx"):
        add("info", "The domain publishes a null MX: it declares that it accepts no mail.", "null_mx")
    elif not p.get("mx"):
        add("info", "No MX record: mail falls back to the domain's address record, which is unusual for a domain that really handles mail.", "no_mx")
    spf, dmarc = p.get("spf"), p.get("dmarc")
    if not spf:
        add("warn", "No SPF record: nothing says which servers may send as this domain, so it is easy to spoof.", "no_spf")
    elif spf.get("duplicates"):
        add("warn", "More than one SPF record: receivers treat that as an error, so SPF does not protect the domain.", "dup_spf")
    elif spf.get("all") in ("pass", "neutral"):
        add("warn", "SPF ends in a permissive rule (+all or ?all): any server may send as this domain.", "open_spf")
    if not dmarc:
        add("warn", "No DMARC record: receivers are not told what to do with mail that fails authentication.", "no_dmarc")
    elif dmarc.get("policy") == "none":
        add("info", "DMARC policy is 'none': it only monitors, so spoofed mail is still delivered.", "dmarc_none")
    elif dmarc.get("policy") in ("quarantine", "reject"):
        add("ok", f"DMARC policy is '{dmarc['policy']}': spoofing this domain is harder.", "dmarc_enforced")
    return out


def verdict(mail: dict, enrichment: dict) -> dict:
    """Verdict for an email indicator. Domain reputation counts; a free-mail domain never makes an address clean."""
    vt = enrichment.get("virustotal") or {}
    uh = enrichment.get("urlhaus") or {}
    otx = (mail or {}).get("otx_address") or {}
    reasons, level = [], 0          # 0 unknown/clean, 1 suspicious, 2 malicious
    mal = vt.get("malicious", 0) or 0
    if mal:
        reasons.append(f"VirusTotal: {mal}/{vt.get('total', 0)} engines flag the domain {mail['domain']}")
        level = max(level, 2 if mal >= 3 else 1)
    if uh.get("found"):
        reasons.append("URLhaus: the domain hosts or served malware")
        level = max(level, 2)
    if otx.get("found"):
        reasons.append(f"AlienVault OTX: this address appears in {otx.get('pulse_count', 1)} community pulse(s)")
        level = max(level, 1)
    codes = {x.get("code") for x in mail.get("signals", [])}
    if "disposable" in codes:
        reasons.append("the domain is a known disposable-mail service"); level = max(level, 1)
    if "nxdomain" in codes:
        reasons.append("the domain does not exist"); level = max(level, 1)
    if "new_domain" in codes:
        reasons.append("the domain was registered within the last 30 days"); level = max(level, 1)
    kind = mail.get("provider_kind")
    if level == 2:
        return {"verdict": "malicious", "score": 90, "reason": " | ".join(reasons)}
    if level == 1:
        return {"verdict": "suspicious", "score": 50, "reason": " | ".join(reasons)}
    if kind == "free":
        return {"verdict": "unknown", "score": 0,
                "reason": f"{mail['domain']} is a free mailbox service, so the domain says nothing about this address."}
    checked = [v for v in (vt, uh) if v and not v.get("skipped") and not v.get("error")]
    if checked:
        return {"verdict": "clean", "score": 0, "reason": "No reputation source flags the domain. This does not vouch for the individual address."}
    return {"verdict": "unknown", "score": 0,
            "reason": "No domain reputation source could be asked (keys missing or quota used); only the domain's mail setup was checked."}


# ── Breach exposure of the mailbox (XposedOrNot public API) ────────────────────
# The one free, key-less source that speaks about an individual address. Its free tier allows 2 requests/second,
# 25/hour and 100/day *per source IP*, so every user of this server shares that budget: TFII stays under it,
# remembers answers, and only asks when a person presses the button (the full address is sent to a third party).
XON_URL = "https://api.xposedornot.com/v1/check-email/"
EXPOSURE_CACHE_HOURS = 24


class MailApiError(Exception):
    """`kind`: rate_limited | busy | invalid | unavailable."""
    def __init__(self, kind, message=""):
        super().__init__(message or kind)
        self.kind = kind


class Budget:
    """Instance-wide request budget (hourly and daily), kept a little under the provider's published limits."""
    def __init__(self, hourly: int = 20, daily: int = 80):
        import time
        from collections import deque
        self._time, self.hourly, self.daily, self._hits = time.monotonic, hourly, daily, deque()

    def take(self) -> bool:
        now = self._time()
        while self._hits and now - self._hits[0] > 86400:
            self._hits.popleft()
        last_hour = sum(1 for t in self._hits if now - t <= 3600)
        if last_hour >= self.hourly or len(self._hits) >= self.daily:
            return False
        self._hits.append(now)
        return True


BUDGET = Budget()
_EXPOSURE_CACHE: dict = {}


def parse_exposure(status: int, body) -> dict:
    """Interpret the provider's answer. Not-found is a real answer ('no known breach'), reported as found=False."""
    if status == 429:
        raise MailApiError("rate_limited", "XposedOrNot is rate limiting this server; try again later")
    if status not in (200, 404):
        raise MailApiError("unavailable", f"XposedOrNot answered HTTP {status}")
    names: List[str] = []
    if isinstance(body, dict) and isinstance(body.get("breaches"), list):
        for item in body["breaches"]:
            names.extend(str(x)[:80] for x in (item if isinstance(item, list) else [item]))
    names = list(dict.fromkeys(n for n in names if n))
    return {"source": "XposedOrNot", "found": bool(names), "count": len(names), "breaches": names[:40],
            "link": "https://xposedornot.com/"}


async def breach_exposure(address: str, client: Optional[httpx.AsyncClient] = None, refresh: bool = False) -> dict:
    """Known data-breach exposure of one mailbox. Raises MailApiError. Answers are cached for a day."""
    parts = split_email(address)
    if not parts:
        raise MailApiError("invalid", "Enter a valid email address")
    key = f"{parts[0].lower()}@{parts[1]}"
    hit = _EXPOSURE_CACHE.get(key)
    now = datetime.now(timezone.utc)
    if hit and not refresh and (now - hit["fetched"]).total_seconds() < EXPOSURE_CACHE_HOURS * 3600:
        return {**hit["data"], "cached": True, "checked_at": hit["fetched"].isoformat()}
    if not BUDGET.take():
        if hit:
            return {**hit["data"], "cached": True, "stale": True, "checked_at": hit["fetched"].isoformat(),
                    "warning": "The shared request limit for this service is used up; showing the saved answer."}
        raise MailApiError("busy", "The shared request limit for the breach-exposure service is used up; try again later")
    own = client is None
    c = client or httpx.AsyncClient(timeout=12)
    try:
        r = await c.get(XON_URL + key, headers={"User-Agent": "TFII-threat-intel/1.0", "Accept": "application/json"})
    except httpx.HTTPError:
        raise MailApiError("unavailable", "XposedOrNot could not be reached")
    finally:
        if own:
            await c.aclose()
    try:
        body = r.json()
    except ValueError:
        body = None
    data = parse_exposure(r.status_code, body)
    if len(_EXPOSURE_CACHE) > 500:
        _EXPOSURE_CACHE.clear()
    _EXPOSURE_CACHE[key] = {"data": data, "fetched": now}
    return {**data, "cached": False, "checked_at": now.isoformat()}


# ── Address risk (IPQualityScore email validation), on request, with the caller's own key ───────────────────
# Free plan: 1,000 lookups a month, so it is never run automatically (not in bulk, not on every page view).
# The provider only takes the key in the URL path: the URL is never logged or put in an error message.
IPQS_URL = "https://www.ipqualityscore.com/api/json/email/{key}/{email}"
RISK_CACHE_HOURS = 24
_RISK_CACHE: dict = {}


def parse_risk(status: int, body) -> dict:
    """Reduce IPQualityScore's answer to the fields that matter. Raises MailApiError for provider-side problems."""
    if status == 429:
        raise MailApiError("rate_limited", "IPQualityScore is rate limiting requests; try again in a minute")
    if status != 200 or not isinstance(body, dict):
        raise MailApiError("unavailable", f"IPQualityScore answered HTTP {status}")
    if body.get("success") is not True:
        msg = str(body.get("message", "")).lower()
        if "insufficient credits" in msg or "quota" in msg or "credits" in msg:
            raise MailApiError("rate_limited", "Your IPQualityScore credits are used up for this period")
        if "invalid" in msg and "key" in msg:
            raise MailApiError("invalid", "IPQualityScore rejected the key: check it in Settings")
        raise MailApiError("unavailable", "IPQualityScore could not process this address")
    human = lambda v: (v.get("human") if isinstance(v, dict) else None)  # noqa: E731
    fraud = body.get("fraud_score")
    return {
        "source": "IPQualityScore",
        "fraud_score": fraud if isinstance(fraud, int) else None,
        "valid": body.get("valid"), "deliverability": body.get("deliverability"), "dns_valid": body.get("dns_valid"),
        "disposable": body.get("disposable"), "recent_abuse": body.get("recent_abuse"), "leaked": body.get("leaked"),
        "honeypot": body.get("honeypot"), "spam_trap": body.get("spam_trap_score"), "suspect": body.get("suspect"),
        "catch_all": body.get("catch_all"), "first_seen": human(body.get("first_seen")), "domain_age": human(body.get("domain_age")),
        "link": "https://www.ipqualityscore.com/",
    }


async def ipqs_email(address: str, key: str, client: Optional[httpx.AsyncClient] = None, refresh: bool = False) -> dict:
    """Risk of one address from IPQualityScore. Raises MailApiError. Answers are cached for a day to save credits."""
    parts = split_email(address)
    if not parts:
        raise MailApiError("invalid", "Enter a valid email address")
    norm = f"{parts[0].lower()}@{parts[1]}"
    now = datetime.now(timezone.utc)
    hit = _RISK_CACHE.get(norm)
    if hit and not refresh and (now - hit["fetched"]).total_seconds() < RISK_CACHE_HOURS * 3600:
        return {**hit["data"], "cached": True, "checked_at": hit["fetched"].isoformat()}
    from urllib.parse import quote
    own = client is None
    c = client or httpx.AsyncClient(timeout=15)
    try:
        r = await c.get(IPQS_URL.format(key=quote(key, safe=""), email=quote(norm, safe="@")))
    except httpx.HTTPError:
        raise MailApiError("unavailable", "IPQualityScore could not be reached")
    finally:
        if own:
            await c.aclose()
    try:
        body = r.json()
    except ValueError:
        body = None
    data = parse_risk(r.status_code, body)
    if len(_RISK_CACHE) > 500:
        _RISK_CACHE.clear()
    _RISK_CACHE[norm] = {"data": data, "fetched": now}
    return {**data, "cached": False, "checked_at": now.isoformat()}
