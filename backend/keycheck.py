"""Does this API key actually work?  One cheap, read-only request per provider.

The hosts are fixed (never user-supplied), so no SSRF surface.  A key is only ever sent to the provider
it belongs to, and it is never returned, logged or included in an error: provider/transport errors are
reduced to a status word before they leave this module.

Result: {"status": "valid" | "invalid" | "rate_limited" | "unreachable" | "unexpected", "ok": bool | None, "message": str}
`ok` is True/False only when the provider gave a definite answer; None means "could not tell".
"""
import logging
import re
from urllib.parse import quote
from typing import Callable, Dict, NamedTuple, Optional

import httpx

# httpx logs each request URL at INFO, and Shodan takes its key in the query string.
logging.getLogger("httpx").setLevel(logging.WARNING)


class Probe(NamedTuple):
    method: str
    url: str
    headers: Callable[[str], Dict[str, str]]
    params: Callable[[str], Dict[str, str]]
    invalid: tuple = (401, 403)            # statuses that mean "this key was rejected"
    judge: Optional[Callable[[dict], Optional[str]]] = None   # reads a 200 body for providers that answer 200 either way


def _h(name: str, prefix: str = ""):
    return lambda k: {name: prefix + k}


_NONE = lambda k: {}  # noqa: E731


def _ipqs_judge(body: dict) -> Optional[str]:
    """IPQualityScore answers 200 with {"success": false, "message": ...} for a bad key."""
    if not isinstance(body, dict):
        return None
    if body.get("success") is True:
        return "valid"
    msg = str(body.get("message", "")).lower()
    return "invalid" if ("invalid" in msg and "key" in msg) or "unauthorized" in msg else None

PROBES: Dict[str, Probe] = {
    # A well-known public address keeps the request free of anything sensitive.
    "virustotal": Probe("GET", "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1", _h("x-apikey"), _NONE),
    "abuseipdb":  Probe("GET", "https://api.abuseipdb.com/api/v2/check", lambda k: {"Key": k, "Accept": "application/json"},
                        lambda k: {"ipAddress": "1.1.1.1", "maxAgeInDays": "1"}),
    # api-info costs no query credits.  Shodan only accepts the key as a query parameter.
    "shodan":     Probe("GET", "https://api.shodan.io/api-info", _NONE, lambda k: {"key": k}),
    "groq":       Probe("GET", "https://api.groq.com/openai/v1/models", _h("Authorization", "Bearer "), _NONE),
    # NVD answers a rejected key with 404 (and 200 for the very same request without one).
    "nvd":        Probe("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0", _h("apiKey"),
                        lambda k: {"resultsPerPage": "1"}, invalid=(401, 403, 404)),
    "urlhaus":    Probe("GET", "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/", _h("Auth-Key"), _NONE),
    "otx":        Probe("GET", "https://otx.alienvault.com/api/v1/user/me", _h("X-OTX-API-KEY"), _NONE),
    # The credit-usage endpoint costs no lookup. The provider only takes the key in the URL path.
    "ipqs":       Probe("GET", "https://www.ipqualityscore.com/api/json/account/{key}", _NONE, _NONE, judge=_ipqs_judge),
}

NAMES = {"virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "shodan": "Shodan", "groq": "Groq", "nvd": "NVD",
         "urlhaus": "abuse.ch", "otx": "AlienVault OTX", "ipqs": "IPQualityScore"}


def _result(status: str, message: str) -> dict:
    return {"status": status, "ok": {"valid": True, "invalid": False}.get(status), "message": message}


async def check_key(service: str, key: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    probe = PROBES.get(service)
    if not probe:
        return _result("unexpected", "This service has no key check.")
    key = (key or "").strip()
    if not key:
        return _result("invalid", "No key to test.")
    name = NAMES.get(service, service)
    if len(key) > 512 or re.search(r"[\s\x00-\x1f\x7f-\uffff]", key):
        return _result("invalid", f"That does not look like a {name} key (spaces, line breaks or unusual characters).")
    own = client is None
    c = client or httpx.AsyncClient(timeout=12, follow_redirects=False)
    try:
        url = probe.url.replace("{key}", quote(key, safe=""))
        r = await c.request(probe.method, url, headers=probe.headers(key), params=probe.params(key))
    except (httpx.TimeoutException, httpx.TransportError):
        return _result("unreachable", f"Could not reach {name} to check the key. Try again shortly.")
    except (httpx.InvalidURL, ValueError):
        # e.g. a key containing characters that cannot be sent in a header
        return _result("invalid", f"{name} key contains characters that are not valid in a key.")
    finally:
        if own:
            await c.aclose()
    code = r.status_code
    if code == 200 and probe.judge:
        try:
            verdict = probe.judge(r.json())
        except ValueError:
            verdict = None
        if verdict == "valid":
            return _result("valid", f"{name} accepted the key.")
        if verdict == "invalid":
            return _result("invalid", f"{name} rejected the key. Check that you copied all of it.")
        return _result("unexpected", f"{name} answered, but not in a way that confirms the key.")
    if code == 200:
        return _result("valid", f"{name} accepted the key.")
    if code in probe.invalid:
        return _result("invalid", f"{name} rejected the key. Check that you copied all of it.")
    if code == 429:
        return _result("rate_limited", f"{name} is rate limiting requests right now, so the key could not be confirmed. Try again in a minute.")
    if code >= 500:
        return _result("unreachable", f"{name} is having problems (HTTP {code}). Try again later.")
    return _result("unexpected", f"{name} answered HTTP {code}, so the key could not be confirmed.")
