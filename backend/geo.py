"""Where an indicator "is", as an honest, labelled answer.

A country next to a domain is easy to misread as "where it comes from". What TFII can actually establish is:

  * for an IP address     - the GeoIP location of that address (`kind: "ip"`);
  * for a domain / URL    - where the web host its name currently resolves to is located (`kind: "hosting"`);
  * behind a CDN          - nothing about the origin: the answer is the CDN edge nearest to whoever asked, so the
                            country is withheld and reported as `edge_country` (`kind: "cdn_edge"`);
  * for a country-code TLD - the registry country (`.mu` -> MU), shown separately and only as a hint, never as a
                            location (registrants and hosts are routinely elsewhere).

Nothing here can prove where an attacker sits; the labels say what each fact is.
"""
import ipaddress
import logging
import socket
from typing import Dict, List, Optional

import httpx

# httpx logs request URLs at INFO; nothing sensitive is in these, but keep the log quiet.
logging.getLogger("httpx").setLevel(logging.WARNING)

# Anycast / CDN operators: an address here answers from the point of presence nearest the resolver.
CDN_MARKERS = (
    ("cloudflare", "Cloudflare"), ("akamai", "Akamai"), ("fastly", "Fastly"), ("incapsula", "Imperva"),
    ("imperva", "Imperva"), ("stackpath", "StackPath"), ("sucuri", "Sucuri"), ("edgecast", "Edgio"),
    ("edgio", "Edgio"), ("cdn77", "CDN77"), ("bunnycdn", "Bunny CDN"), ("bunny.net", "Bunny CDN"),
    ("limelight", "Limelight"), ("cloudfront", "Amazon CloudFront"), ("cachefly", "CacheFly"), ("keycdn", "KeyCDN"),
)

# Two-letter TLDs that are sold worldwide and say nothing about the country.
GENERIC_USE_CCTLDS = frozenset((
    "io", "co", "tv", "me", "cc", "ai", "ly", "fm", "to", "ws", "sh", "ac", "ms", "nu", "vc", "st", "tk", "ml", "ga",
    "cf", "gq", "cx", "la", "pw", "ag", "gd", "gs", "mn", "tl", "bz", "gg", "gl", "im", "je",
))
IP_TYPES = ("IPv4", "IPv6")


def cdn_provider(*texts) -> Optional[str]:
    hay = " ".join(str(t) for t in texts if t).lower()
    for marker, label in CDN_MARKERS:
        if marker in hay:
            return label
    return None


def cctld_country_code(host: str) -> Optional[str]:
    """ISO 3166 code for a real country-code TLD, else None (generic TLDs, generic-use ccTLDs, IPs)."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or "." not in h:
        return None
    tld = h.rsplit(".", 1)[1]
    if len(tld) != 2 or not tld.isalpha() or tld in GENERIC_USE_CCTLDS:
        return None
    return "GB" if tld == "uk" else tld.upper()


async def resolve_ips(host: str, client: Optional[httpx.AsyncClient] = None, limit: int = 4) -> List[str]:
    """Every public A/AAAA answer for a name, via dns.google, falling back to the OS resolver.
    (One `gethostbyname` answer from the local resolver is a single arbitrary record.)"""
    host = (host or "").strip().rstrip(".")
    if not host:
        return []
    out: List[str] = []
    own = client is None
    c = client or httpx.AsyncClient(timeout=6)
    try:
        for rtype in ("A", "AAAA"):
            try:
                r = await c.get("https://dns.google/resolve", params={"name": host, "type": rtype}, headers={"Accept": "application/json"})
                if r.status_code == 200:
                    for a in (r.json().get("Answer") or []):
                        if a.get("type") in (1, 28):
                            out.append(str(a.get("data", "")))
            except Exception:
                continue
    finally:
        if own:
            await c.aclose()
    if not out:
        try:
            import asyncio
            info = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, socket.gethostbyname_ex, host), timeout=4)
            out = list(info[2])
        except Exception:
            out = []
    seen, ips = set(), []
    for x in out:
        try:
            ip = ipaddress.ip_address(x)
        except ValueError:
            continue
        if ip.is_global and str(ip) not in seen:
            seen.add(str(ip))
            ips.append(str(ip))
    return ips[:limit]


def describe_location(value_type: str, host: str, ips: List[str], geo_by_ip: Dict[str, dict], cloud_provider=None) -> Optional[dict]:
    """The labelled location facts for one indicator. `geo_by_ip` is ip-api's answer per address."""
    recs = [(ip, geo_by_ip.get(ip)) for ip in ips]
    recs = [(ip, r) for ip, r in recs if r and r.get("status") != "fail"]
    cc = cctld_country_code(host) if value_type not in IP_TYPES else None
    if not recs:
        return {"kind": "unknown", "cctld_country_code": cc, "resolved_ips": ips,
                "note": "No location could be determined."} if cc else None
    ip0, r0 = recs[0]
    org = r0.get("org") or r0.get("isp") or ""
    cdn = next((p for _ip, r in recs if (p := cdn_provider(r.get("org"), r.get("isp"), r.get("as")))), None)
    countries, seen = [], set()
    for _ip, r in recs:
        code = r.get("countryCode")
        if code and code not in seen:
            seen.add(code)
            countries.append({"code": code, "name": r.get("country")})
    is_ip = value_type in IP_TYPES
    kind = "ip" if is_ip else ("cdn_edge" if cdn else "hosting")
    geo = {
        "kind": kind, "country": None if kind == "cdn_edge" else r0.get("country"),
        "country_code": None if kind == "cdn_edge" else r0.get("countryCode"),
        "countries": [] if kind == "cdn_edge" else countries,
        "org": org, "isp": r0.get("isp"), "asn": r0.get("as"), "cloud_provider": cloud_provider,
        "resolved_ip": None if is_ip else ip0, "resolved_ips": [] if is_ip else ips,
        "cdn": cdn, "cctld_country_code": cc,
    }
    if kind == "cdn_edge":
        geo["edge_country"] = r0.get("country")
        geo["edge_country_code"] = r0.get("countryCode")
        geo["note"] = (f"Behind {cdn}. The address is a CDN edge that answers from the location nearest to the asker, "
                       f"so it says nothing about where the site is hosted or originates.")
    elif kind == "hosting":
        geo["note"] = f"Where the web host this name resolves to ({ip0}) is located. It is not necessarily where the operators are."
        if len(countries) > 1:
            geo["note"] += " The name resolves to servers in several countries."
    else:
        geo["note"] = f"GeoIP location of this address ({org or 'owner unknown'})."
    return geo


def cross_check(geo: Optional[dict], enrichment: Optional[dict]) -> Optional[dict]:
    """For an IP: compare the GeoIP country with what AbuseIPDB and VirusTotal already reported.
    Sets `other_sources` and `agreement` ('agree' | 'differ'); says nothing when nobody else answered."""
    if not geo or geo.get("kind") != "ip" or not isinstance(enrichment, dict):
        return geo
    mine = (geo.get("country_code") or "").upper()
    others = {}
    for src, key in (("AbuseIPDB", "abuseipdb"), ("VirusTotal", "virustotal")):
        c = ((enrichment.get(key) or {}).get("country") or "").strip().upper()
        if len(c) == 2 and c.isalpha():
            others[src] = c
    if others and mine:
        geo["other_sources"] = others
        geo["agreement"] = "agree" if all(c == mine for c in others.values()) else "differ"
    return geo
