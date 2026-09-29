"""
Open-source indicator feeds and how TFII decides to trust them.

Two ideas, both aimed at "more, fresher and more confident indicators":

* **Reliability per source.** Every source has a reliability (0-1) that reflects how
  often its entries are real and current — a vendor-curated botnet-C2 tracker is not a
  crowd-sourced blocklist. Some sources carry per-entry evidence (IPsum reports how many
  independent blocklists list an address); that overrides the source default.

* **Corroboration.** Confidence is the noisy-OR of the *distinct* sources that reported an
  indicator: 1 - Π(1 - rᵢ). Two mediocre lists that agree beat one mediocre list; the same
  source repeating itself adds nothing. Weak, unordered blocklists therefore only create a
  NEW indicator when the combined confidence clears the configured floor, but every sighting
  of an indicator TFII already holds is recorded (provenance) and refreshes its expiry.

Feeds are declared in `FEEDS`; a feed is a URL, a parser and a reliability. Parsers are pure
functions over the downloaded text so they can be tested without a network. Nothing in this
module imports `main`; the writer functions it needs are passed in.
"""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

import security

# ── Reliability ───────────────────────────────────────────────────────────────
# What TFII believes about a source before looking at a single entry.
SOURCE_RELIABILITY = {
    "ThreatFox": 0.85, "MalwareBazaar": 0.85, "URLhaus": 0.85,
    "Feodo Tracker": 0.92, "OpenPhish": 0.80, "AlienVault OTX": 0.72,
    "IPsum": 0.60, "CINS Army": 0.62, "Emerging Threats": 0.66, "blocklist.de": 0.55,
    "Phishing Database": 0.70,
}
DEFAULT_RELIABILITY = 0.5
CONF_CAP = 97          # nothing automated is ever 100% certain


# Meta-sources: IPsum is itself built from other blocklists. Counting IPsum AND a list it already
# contains as two independent confirmations double-counts the same evidence, so when the aggregate is
# present its members add nothing (its own per-entry list count already reflects them).
AGGREGATES = {"IPsum": {"CINS Army", "Emerging Threats", "blocklist.de"}}


def independent_scores(scores: Dict[str, float]) -> Dict[str, float]:
    out = dict(scores)
    for meta, members in AGGREGATES.items():
        if meta in out:
            for m in members:
                out.pop(m, None)
    return out


def noisy_or(reliabilities) -> float:
    p = 1.0
    for r in reliabilities:
        p *= 1.0 - max(0.0, min(0.99, r))
    return 1.0 - p


def ipsum_reliability(level: int) -> float:
    """IPsum's number is how many of ~30 independent blocklists carry the address."""
    return {1: 0.30, 2: 0.50, 3: 0.62, 4: 0.72, 5: 0.80, 6: 0.86}.get(level, 0.90 if level >= 7 else 0.30)


# ── Candidates ────────────────────────────────────────────────────────────────
@dataclass
class Candidate:
    value: str
    type: str                                  # IPv4 | IPv6 | Domain | URL | MD5 | SHA1 | SHA256
    reliability: float                         # 0-1, this entry
    family: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    reference: Optional[str] = None
    first_seen: Optional[datetime] = None
    description: str = ""
    context: dict = field(default_factory=dict)   # ASN, country, port … kept as enrichment


_HASH = {32: "MD5", 40: "SHA1", 64: "SHA256"}
_HEX = re.compile(r"^[a-fA-F0-9]+$")


def clean_candidate(c: Candidate, trusted_domains=()) -> Optional[Candidate]:
    """Server-side validation of feed data: feeds are third-party input."""
    v = (c.value or "").strip()
    if not v or len(v) > 2048:
        return None
    if c.type in ("IPv4", "IPv6"):
        if not security.is_valid_ip(v) or not security.is_public_ip(v):
            return None
    elif c.type == "Domain":
        v = v.lower().rstrip(".")
        if not security.is_valid_domain(v) or any(v == t or v.endswith("." + t) for t in trusted_domains):
            return None
    elif c.type == "URL":
        u = security.safe_http_url(v)
        if not u:
            return None
        host = re.match(r"^https?://(?:[^/@?#]*@)?(\[[0-9a-fA-F:.]+\]|[^/:?#]+)", u)
        h = (host.group(1).strip("[]").lower() if host else "")
        if not h or (security.is_valid_ip(h) and not security.is_public_ip(h)):
            return None
        if any(h == t or h.endswith("." + t) for t in trusted_domains):
            return None
        v = u
    elif c.type in ("MD5", "SHA1", "SHA256"):
        if not _HEX.match(v) or _HASH.get(len(v)) != c.type:
            return None
        v = v.lower()
    else:
        return None
    c.value = v
    return c


def _dt(s) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(s)[:19], fmt)
        except ValueError:
            continue
    return None


# ── Parsers (pure) ────────────────────────────────────────────────────────────
def _lines(text):
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith(("#", ";", "//")):
            yield ln


def parse_feodo(text) -> List[Candidate]:
    """abuse.ch Feodo Tracker recommended C2 blocklist (JSON array)."""
    try:
        rows = json.loads(text)
    except ValueError:
        return []
    if isinstance(rows, dict):
        rows = rows.get("blocklist") or rows.get("data") or []
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        online = str(r.get("status", "")).lower() == "online"
        fam = (r.get("malware") or "").strip() or None
        ctx = {k: r.get(k) for k in ("port", "as_number", "as_name", "country", "hostname", "last_online") if r.get(k) not in (None, "")}
        out.append(Candidate(
            value=str(r.get("ip_address") or ""), type="IPv4", reliability=0.92 if online else 0.80, family=fam,
            tags=["botnet-c2", "feodo"] + ([fam.lower()] if fam else []), reference="https://feodotracker.abuse.ch/browse/host/%s/" % r.get("ip_address"),
            first_seen=_dt(r.get("first_seen")), context=ctx,
            description=f"Feodo Tracker: {fam or 'botnet'} C2" + (f" on port {r['port']}" if r.get("port") else "") + (" (online)" if online else " (offline)")))
    return out


def parse_ipsum(text, min_level=3) -> List[Candidate]:
    out = []
    for ln in _lines(text):
        parts = ln.split()
        if len(parts) < 2 or not parts[1].isdigit():
            continue
        lvl = int(parts[1])
        if lvl < min_level:
            continue
        out.append(Candidate(value=parts[0], type="IPv4", reliability=ipsum_reliability(lvl), tags=["blocklist", "ipsum", f"lists-{lvl}"],
                             reference="https://github.com/stamparm/ipsum", description=f"Listed by {lvl} independent blocklists (IPsum)",
                             context={"blocklists": lvl}))
    out.sort(key=lambda c: -c.context["blocklists"])      # strongest evidence first, so a cap keeps the best
    return out


def _ip_list(source_tag, reference, reliability, what):
    def parse(text) -> List[Candidate]:
        out = []
        for ln in _lines(text):
            ip = re.split(r"[\s,;#]", ln, 1)[0]
            out.append(Candidate(value=ip, type="IPv6" if ":" in ip else "IPv4", reliability=reliability, tags=["blocklist", source_tag],
                                 reference=reference, description=what))
        return out
    return parse


parse_cins = _ip_list("cins-army", "https://cinsscore.com/", 0.62, "Listed on the CINS Army bad-actor list")
parse_et_compromised = _ip_list("emerging-threats", "https://rules.emergingthreats.net/", 0.66, "Listed as a compromised host by Emerging Threats")
parse_blocklist_de = _ip_list("blocklist-de", "https://www.blocklist.de/", 0.55, "Reported for attacks against honeypots/servers (blocklist.de)")


def parse_openphish(text) -> List[Candidate]:
    return [Candidate(value=u, type="URL", reliability=0.80, tags=["phishing", "openphish"], reference="https://openphish.com/",
                      description="Active phishing URL (OpenPhish community feed)") for u in _lines(text)]


def parse_phishing_domains(text) -> List[Candidate]:
    return [Candidate(value=d, type="Domain", reliability=0.70, tags=["phishing", "phishing-database"],
                      reference="https://github.com/mitchellkrogza/Phishing.Database", description="Active phishing domain (Phishing.Database)")
            for d in _lines(text)]


_OTX_TYPES = {"IPv4": "IPv4", "IPv6": "IPv6", "domain": "Domain", "hostname": "Domain", "URL": "URL",
              "FileHash-MD5": "MD5", "FileHash-SHA1": "SHA1", "FileHash-SHA256": "SHA256"}


def parse_otx(text) -> List[Candidate]:
    """AlienVault OTX subscribed pulses. Reliability is trimmed for TLP-less/untagged pulses, raised when a
    named adversary or malware family is attached (an analyst did work on it)."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for p in data.get("results", []) if isinstance(data, dict) else []:
        fams = [f.get("display_name") or f.get("id") for f in (p.get("malware_families") or []) if isinstance(f, dict)]
        fam = next((f for f in fams if f), None)
        adv = (p.get("adversary") or "").strip()
        rel = 0.72 + (0.06 if (fam or adv) else 0.0)
        ref = f"https://otx.alienvault.com/pulse/{p.get('id')}" if p.get("id") else None
        tags = ["otx"] + [str(t).lower()[:30] for t in (p.get("tags") or [])[:4]]
        for ind in p.get("indicators", []) or []:
            t = _OTX_TYPES.get(ind.get("type"))
            if not t:
                continue
            out.append(Candidate(value=str(ind.get("indicator") or ""), type=t, reliability=rel, family=fam, tags=tags, reference=ref,
                                 first_seen=_dt(ind.get("created")), context={k: v for k, v in {"adversary": adv, "pulse": p.get("name")}.items() if v},
                                 description=f"OTX pulse: {(p.get('name') or '')[:120]}"))
    return out


# ── Registry ──────────────────────────────────────────────────────────────────
@dataclass
class Feed:
    id: str
    name: str
    url: str
    parser: Callable
    group: str = "direct"             # direct: entries stand alone; consensus: weak lists merged and corroborated
    ttl_days: int = 30
    interval_hours: int = 12
    default_limit: int = 1000
    key_env: Optional[str] = None     # platform key required
    key_header: Optional[str] = None
    homepage: str = ""
    about: str = ""
    kinds: str = ""                   # shown in the UI, e.g. "IPv4 · botnet C2"


FEEDS: Dict[str, Feed] = {f.id: f for f in [
    Feed("feodo", "Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", parse_feodo, ttl_days=14, interval_hours=6,
         homepage="https://feodotracker.abuse.ch/", kinds="IPv4 · botnet C2", about="Curated command-and-control servers for Emotet, Dridex, TrickBot, QakBot and similar loaders. Highest-signal IP feed available without a key."),
    Feed("openphish", "OpenPhish community", "https://openphish.com/feed.txt", parse_openphish, ttl_days=7, interval_hours=6,
         homepage="https://openphish.com/", kinds="URL · phishing", about="Verified live phishing URLs, refreshed every few hours. Short expiry: phishing pages die quickly."),
    Feed("otx", "AlienVault OTX", "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50", parse_otx, ttl_days=45, interval_hours=12,
         key_env="OTX_API_KEY", key_header="X-OTX-API-KEY", homepage="https://otx.alienvault.com/", kinds="IP · domain · URL · hash",
         about="Community pulses with adversary and malware-family context. Needs a free OTX key (OTX_API_KEY in .env)."),
    Feed("phishdb", "Phishing.Database (active domains)", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
         parse_phishing_domains, group="consensus", ttl_days=14, interval_hours=24, default_limit=500, homepage="https://github.com/mitchellkrogza/Phishing.Database",
         kinds="Domain · phishing", about="Large aggregated list of active phishing domains. Unordered, so only entries that another source also reports are created."),
    Feed("ipsum", "IPsum (multi-blocklist consensus)", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", parse_ipsum, group="consensus",
         ttl_days=14, interval_hours=24, default_limit=1500, homepage="https://github.com/stamparm/ipsum", kinds="IPv4 · consensus",
         about="Aggregates ~30 public blocklists and reports how many list each IP; TFII uses that count as the evidence (3 lists ≈ 62%, 7+ ≈ 90%)."),
    Feed("cins", "CINS Army", "https://cinsscore.com/list/ci-badguys.txt", parse_cins, group="consensus", ttl_days=14, interval_hours=24,
         default_limit=2000, homepage="https://cinsscore.com/", kinds="IPv4 · scanners/attackers", about="Sentinel-network bad-actor IPs. Used for corroboration."),
    Feed("et_compromised", "Emerging Threats compromised IPs", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", parse_et_compromised,
         group="consensus", ttl_days=14, interval_hours=24, default_limit=2000, homepage="https://rules.emergingthreats.net/", kinds="IPv4 · compromised hosts",
         about="Proofpoint ET list of hosts observed attacking or compromised. Used for corroboration."),
    Feed("blocklist_de", "blocklist.de", "https://lists.blocklist.de/lists/all.txt", parse_blocklist_de, group="consensus", ttl_days=7, interval_hours=24,
         default_limit=3000, homepage="https://www.blocklist.de/", kinds="IPv4 · attack sources", about="Attack reports from honeypots and volunteer servers. Noisy alone; useful as a second opinion."),
]}
SOURCE_NAME = {"feodo": "Feodo Tracker", "openphish": "OpenPhish", "otx": "AlienVault OTX", "phishdb": "Phishing Database", "ipsum": "IPsum",
               "cins": "CINS Army", "et_compromised": "Emerging Threats", "blocklist_de": "blocklist.de"}
MAX_BODY = 40 * 1024 * 1024


async def fetch_text(feed: Feed, key: Optional[str] = None) -> str:
    headers = {"User-Agent": "TFII-ThreatIntel/2.0 (+feed-fetcher)"}
    if feed.key_header and key:
        headers[feed.key_header] = key
    async with security.safe_client(timeout=60, follow_redirects=True, headers=headers) as c:
        async with c.stream("GET", feed.url) as r:
            if r.status_code == 401 or r.status_code == 403:
                raise RuntimeError(f"HTTP {r.status_code} — check the API key" if feed.key_env else f"HTTP {r.status_code}")
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            buf, size = [], 0
            async for chunk in r.aiter_bytes():
                size += len(chunk)
                if size > MAX_BODY:
                    raise RuntimeError("response too large")
                buf.append(chunk)
    return b"".join(buf).decode("utf-8", "replace")


# ── Confidence ────────────────────────────────────────────────────────────────
def corroborated_confidence(source_scores: Dict[str, float]) -> int:
    """source_scores: source -> best reliability (0-1) reported by that source."""
    source_scores = independent_scores(source_scores)
    return int(round(100 * min(CONF_CAP / 100.0, noisy_or(source_scores.values()))))


def corroborate(conn, ioc_id: str, key: str, record_score: Callable, actor: str = "feed corroboration") -> Optional[int]:
    """Raise an indicator's confidence to what its distinct feed sources justify (never lowers it).
    Returns the new confidence when it changed."""
    cur = conn.cursor()
    cur.execute("""SELECT source, MAX(COALESCE(confidence, 0)) FROM entity_observations
        WHERE entity_kind = 'indicator' AND LOWER(entity_ref) = LOWER(%s) AND obs_type IN ('ingested','sighting')
              AND source_type = 'feed' GROUP BY source""", (key,))
    scores = {}
    for src, conf in cur.fetchall():
        scores[src] = (conf / 100.0) if conf else SOURCE_RELIABILITY.get(src, DEFAULT_RELIABILITY)
    scores = independent_scores(scores)
    if len(scores) < 2:
        return None
    new = corroborated_confidence(scores)
    cur.execute("SELECT confidence, false_positive, enrichment FROM iocs WHERE id = %s", (ioc_id,))
    row = cur.fetchone()
    if not row or row[1] or new <= (row[0] or 0):
        return None
    reason = f"Corroborated by {len(scores)} independent feeds ({', '.join(sorted(scores))}): {row[0]} → {new}"
    enr = row[2] if isinstance(row[2], dict) else {}
    reasons = [r for r in (enr.get("confidence_reasons") or []) if not str(r).startswith("Corroborated by")] + [reason]
    enr = {**enr, "confidence_reasons": reasons, "corroborated_by": sorted(scores)}
    import psycopg2.extras
    cur.execute("UPDATE iocs SET confidence = %s, enrichment = %s WHERE id = %s", (new, psycopg2.extras.Json(enr), ioc_id))
    try:
        record_score(conn, ioc_id, row[0], new, [reason], actor)
    except Exception as e:                                       # history is best-effort
        print(f"[feeds] score history not written: {type(e).__name__}")
    return new


# ── Runner ────────────────────────────────────────────────────────────────────
async def run_feed(conn, feed_id: str, cfg: dict, *, ingest: Callable, record_score: Callable, defang: Callable, key: Optional[str] = None,
                   trusted_domains=(), texts: Optional[dict] = None) -> dict:
    """Run one direct feed, or a whole consensus group when given a consensus feed id.

    `ingest(cur, conn, **kw)` is main._ingest_feed_ioc and returns (created, ioc_id).
    `texts` lets tests hand in downloaded content instead of hitting the network.
    """
    feed = FEEDS[feed_id]
    fcfg = (cfg.get("feeds") or {}).get(feed_id, {})
    limit = int(fcfg.get("limit") or feed.default_limit)
    floor = int(cfg.get("min_confidence") or 70)
    members = [f for f in FEEDS.values() if f.group == "consensus" and (cfg.get("feeds") or {}).get(f.id, {}).get("enabled")] \
        if feed.group == "consensus" else [feed]
    if feed.group == "consensus" and feed not in members:
        members.append(feed)

    pool: Dict[str, dict] = {}
    errors, received = [], 0
    for f in members:
        try:
            text = (texts or {}).get(f.id)
            if text is None:
                k = key if f.id == feed_id else None
                text = await fetch_text(f, k)
            cands = f.parser(text)
        except Exception as e:
            errors.append(f"{f.name}: {str(e)[:120] or type(e).__name__}")
            continue
        received += len(cands)
        src = SOURCE_NAME[f.id]
        kept = 0
        for c in cands:
            if kept >= int(((cfg.get("feeds") or {}).get(f.id, {}) or {}).get("limit") or f.default_limit):
                break
            c = clean_candidate(c, trusted_domains)
            if not c:
                continue
            kept += 1
            slot = pool.setdefault((c.type, c.value), {"cand": c, "sources": {}, "feeds": {}})
            slot["sources"][src] = max(slot["sources"].get(src, 0), c.reliability)
            slot["feeds"][src] = f

    if not pool and errors:
        return {"ok": False, "error": "; ".join(errors)[:300], "added": 0, "skipped": 0, "total_received": received, "errors": errors}

    cur = conn.cursor()
    existing = set()
    vals = [v for (_t, v) in pool]
    for i in range(0, len(vals), 500):
        cur.execute("SELECT value FROM iocs WHERE value = ANY(%s)", (vals[i:i + 500],))
        existing.update(r[0] for r in cur.fetchall())

    added = sightings = below = 0
    created_rows = []
    for (typ, value), slot in pool.items():
        conf = corroborated_confidence(slot["sources"])
        if value not in existing and conf < floor:
            below += 1
            continue
        c: Candidate = slot["cand"]
        created_any, ioc_id = False, None
        for src, f in slot["feeds"].items():
            evidence = int(round(slot["sources"][src] * 100))
            created, ioc_id = ingest(
                cur, conn, type_=typ, value=value, defanged=defang(value, typ), tlp="AMBER" if evidence < 80 else "RED",
                confidence=evidence, description=c.description, tags=list(dict.fromkeys(["feed"] + c.tags))[:8],
                enrichment={"source": src, "malware_family": c.family or "", **({"feed_context": c.context} if c.context else {}),
                            "enriched_at": datetime.now(timezone.utc).isoformat()},
                valid_days=f.ttl_days, source=src, source_ref=c.reference, observed_at=c.first_seen)
            created_any = created_any or created
        if created_any:
            added += 1
            created_rows.append({"id": ioc_id, "type": typ, "value": value, "confidence": conf})
        else:
            sightings += 1
        if ioc_id and len(slot["sources"]) >= 1:
            corroborate(conn, ioc_id, value, record_score)
    conn.commit()
    res = {"ok": not (errors and added + sightings == 0), "added": added, "skipped": sightings, "total_received": received,
           "below_floor": below, "errors": errors,
           "created": sorted(created_rows, key=lambda r: -r["confidence"])[:200]}
    if errors and added + sightings == 0:
        res["error"] = "; ".join(errors)[:300]
    return res



def repair_overcounted(conn, record_score: Callable, floor: int = 70) -> dict:
    """One-off correction for indicators scored while IPsum and the lists it aggregates were counted as
    independent. Recomputes confidence from the distinct-source evidence; feed-corroborated confidence only.
    Indicators that fall below the floor, were created by a consensus run and were never touched by an
    analyst are expired (they were only ever admitted by the double count)."""
    import psycopg2.extras
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT id, value, confidence, enrichment, analyst_status, created_by FROM iocs
        WHERE enrichment ? 'corroborated_by' AND enrichment->'corroborated_by' ? 'IPsum' AND NOT COALESCE(false_positive, FALSE)""")
    fixed = expired = 0
    for r in cur.fetchall():
        c2 = conn.cursor()
        c2.execute("""SELECT source, MAX(COALESCE(confidence, 0)) FROM entity_observations
            WHERE entity_kind = 'indicator' AND LOWER(entity_ref) = LOWER(%s) AND obs_type IN ('ingested','sighting')
                  AND source_type = 'feed' GROUP BY source""", (r["value"],))
        scores = {src: ((conf / 100.0) if conf else SOURCE_RELIABILITY.get(src, DEFAULT_RELIABILITY)) for src, conf in c2.fetchall()}
        ind = independent_scores(scores)
        new = corroborated_confidence(scores) if len(ind) >= 1 else r["confidence"]
        if new >= r["confidence"]:
            continue
        enr = dict(r["enrichment"] or {})
        reason = f"Corrected: IPsum already aggregates the other lists, so they are not independent confirmation ({r['confidence']} → {new})"
        enr["confidence_reasons"] = [x for x in (enr.get("confidence_reasons") or []) if not str(x).startswith("Corroborated by")] + [reason]
        enr["corroborated_by"] = sorted(ind)
        c2.execute("UPDATE iocs SET confidence = %s, enrichment = %s WHERE id = %s", (new, psycopg2.extras.Json(enr), r["id"]))
        try:
            record_score(conn, r["id"], r["confidence"], new, [reason], "feed correction")
        except Exception:
            pass
        fixed += 1
        only_consensus_feeds = set(ind) <= {"IPsum", "CINS Army", "Emerging Threats", "blocklist.de", "Phishing Database"}
        if new < floor and only_consensus_feeds and not r["analyst_status"] and not r["created_by"]:
            c2.execute("UPDATE iocs SET valid_until = NOW() WHERE id = %s", (r["id"],))
            expired += 1
    conn.commit()
    return {"corrected": fixed, "expired": expired}
