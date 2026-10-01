# TFII Intelligence Core

How TFII models what it knows, and why it believes it. Written for whoever extends it next.
The code lives in `backend/` as a modular monolith — flat modules, one direction of dependency:

```
security ← entities ← search ← intel_api (+ entity_api) ← main
```

`main.py` owns auth, the original v1 endpoints and the deploy-time wiring; it hands the v2 modules the
few functions they need (`INTEL_DEPS`) so nothing imports `main` (no cycles, testable in isolation).

| Module | Responsibility |
|---|---|
| `security.py` | SSRF-safe HTTP client (`safe_client`), `safe_http_url`, domain/IP validators, API security headers |
| `migrations.py` | Numbered, additive, idempotent schema migrations (`schema_migrations` table) |
| `entities.py` | Entity headers, **relationship service**, observations/provenance, timelines, status model, workspace membership |
| `search.py` | Provider-based global search (`SearchService`) |
| `entity_api.py` | `/v2/entity*`, `/v2/search`, relationship + workspace-bridge endpoints |
| `intel_api.py` | IOC list/facets, investigations (workspace), Command Center, Intel Wall, software/CVE summaries |

## Entity model

An **entity is a `(kind, ref)` pair**. Nothing is copied into an "entities" table: most entities already exist as rows
or as values inside rows.

| kind | `ref` | Backed by |
|---|---|---|
| `indicator` | normalised value (lower-cased domain/hash, canonical IP, scheme+host-lowered URL) — *not* the row id | `iocs` (may be **untracked**: TFII has never stored it) |
| `cve` | `CVE-YYYY-N` | `cve_findings` (one row per monitored software) |
| `malware` | family name | `iocs.enrichment->>'malware_family'` |
| `actor` | actor name | `campaigns.threat_actor` (+ MITRE ATT&CK on demand) |
| `campaign` | campaign id | `campaigns` |
| `software` | asset id | `assets` |
| `investigation` | investigation id | `investigations` |

`GET /v2/entity?kind=&ref=` returns one envelope for every kind: `entity` (uniform header), `relationships`, `timeline`,
`observations`, `sources`, `rationale`, `investigations`, `counts`, plus `overview` (indicator, CVE) and `membership`
when `?inv=` says the analyst arrived from an investigation. Unknown indicators return an *untracked* header rather than 404;
unknown malware/campaign/software/investigation return 404. Addressing is by query string, never path segments —
indicator values contain `/` and `:`.

### Status model (indicators)

One vocabulary: `active · suspicious · confirmed · unknown · expired · false_positive`.
`expired` (past `valid_until`) and `false_positive` are **derived** from existing columns and win over the analyst verdict
stored in `iocs.analyst_status` (NULL = active). Existing confidence scoring is untouched; **severity is the confidence band**
(≥90 critical, ≥75 high, ≥50 medium, else low) — there is no second, invented score. Only the analyst who flagged a false positive
(or an admin) can lift it.

## Relationship model

Every relationship a page shows is one of three things, and says which (`origin`):

* **derived** — computed on read from a real column: `campaign_id`, `enrichment.malware_family`, the hostname of a URL,
  `cve_findings`, `cve_ioc_links`, `investigation_items`. Nothing is inferred; no column → no edge.
* **stored** — asserted and saved in `entity_relationships` with its own `source`, `source_type`, `source_ref`, `confidence`,
  `observed_at`, `created_by`. Written by analysts (`POST /v2/relationships`) or importers (DNS resolution, MITRE ATT&CK).
  Unique on `(src, rel_type, dst, source)` — the same fact from two sources is two rows.
* **legacy** — the original IOC↔IOC links in `ioc_relationships`, merged in unchanged.

Vocabulary (`entities.REL_TYPES`, served at `/v2/relationship-types`): `resolves_to hosts associated_with used_by uses
operates_campaign attributed_to part_of affects observed_in appears_in related_to communicates_with dropped_by delivers variant_of`,
each with an outgoing and an incoming label. Adding a type is one dictionary entry.

Examples that exist today: domain →hosts→ URL (URL hostname), URL/hash →associated_with→ malware, campaign →uses→ indicators,
actor →operates_campaign→ campaign, CVE →affects→ software, indicator →observed_in→ source, entity →appears_in→ investigation
(with the analyst's reason), domain →resolves_to→ IP (only after *Resolve DNS* is run; recorded with `dns.google` as the source).

`/v2/entity/graph` draws the same relationships (1–2 hops, 120-node cap); it is not a separate model.

## Provenance — "why does TFII believe this?"

`entity_observations` records what a source told TFII: `obs_type` (`ingested`, `sighting`, `enrichment`, `status_change`,
`dns_resolution`…), `source`, `source_type`, `source_ref` (URL), `observed_at` (when the **source** says it happened — NULL if
unknown, never guessed), `ingested_at`, `confidence`, `actor`, `summary`.

* Feed connectors (ThreatFox, MalwareBazaar, URLhaus) write `ingested` on first sight and `sighting` (and bump `iocs.last_seen`)
  when a feed reports a value TFII already holds — instead of silently dropping the duplicate.
* Rows that pre-date this table get **reconstructed** observations from real columns, flagged `derived: true` (shown with `*`).
* `rationale` lists the confidence reasons stored with the indicator, the reporting source, campaign assignment and analyst
  verdict. Every line traces to stored data.
* Timelines contain only events with a recorded timestamp; NVD dates are dates, and are shown as dates.

## Search architecture

`GET /v2/search?q=&limit=&kinds=` → `{query, normalized, detected_type, groups:{kind:{label,hits,count}}, top, total, took_ms, limited}`.

* Input is normalised first (defanged `hxxp://x[.]y`, IPv6 forms, hostnames) and LIKE wildcards are escaped.
* A **provider** per kind (`search.Provider(kind, label, cap, run)`) runs one indexed query and returns uniform hits
  (`kind, ref, title, subtitle, type, score, …`). The service filters by the caller's capabilities, isolates a failing provider,
  sorts and groups. **A new entity type is one `register()` call** — the palette and search page render groups generically;
  the only UI touch is an entry in `frontend/src/lib/entity.js`.
* Scoring is explainable: exact 100, prefix 80, URL-on-this-host 70, substring 50, tag 45, family 40, description 30.
* Indexes: `LOWER(value)`, URL-host expression, `pg_trgm` GIN on `iocs.value` and `cve_findings.title` (optional — skipped if the
  extension is unavailable), family/actor expression indexes.
* Explorer accounts get `limited: true` and zero database hits.

## Key endpoints (all require a bearer token; `full` = capability `data.workspace`)

| Endpoint | Notes |
|---|---|
| `GET /v2/search` | any user; limited for explorers |
| `GET /v2/entity`, `/v2/entity/{relationships,timeline,raw,membership,graph}` | full |
| `POST /v2/entity/status` | set indicator status (ownership rule for false positives) |
| `POST /v2/entity/resolve-dns`, `/v2/entity/sync-mitre` | record DNS / ATT&CK associations with provenance |
| `POST /v2/relationships`, `DELETE /v2/relationships/{id}` | author or admin may delete |
| `POST /v2/investigations/{id}/entities` | add **any** entity kind with a `reason`; `PATCH …/items/{item}` edits the reason |
| `GET /v2/iocs` (+`/facets`, `/filter-options`) | filters: q, type, tlp, source, tag, campaign, min_conf, **status, severity, enrichment, since/last_seen/expiring days, analyst**; facets are a separate call |
| `POST /v2/iocs/bulk-action` | assign_campaign, add_tag, mark_fp/unmark_fp, **set_status**, add_to_investigation |
| `GET /v2/intel-wall` | items carry `entities` (only ones TFII actually holds), `tags`, `affects`; `?entity_kind=&entity_ref=` filters |
| `GET /v2/cve/summary`, `/v2/software[/{id}]` | lightweight CVE/software views |
| `POST /users/me/api-keys/{service}/test` | asks the provider whether a key works (`keycheck.py`): tests the pasted key (not saved) or, with no body, the caller's saved key; returns `valid`/`invalid`/`rate_limited`/`unreachable`, never the key |

Everything else (v1: `/iocs`, `/cves/*`, TAXII/STIX, OSINT, admin) is unchanged.

## Where an indicator "is" (`geo.py`)

Bulk lookup and the observable page label every location by what it is, because a country beside a domain reads as "where it comes from" and TFII cannot establish that:

| `geo.kind` | Meaning |
|---|---|
| `ip` | GeoIP location of that address; compared with AbuseIPDB and VirusTotal (`agreement`: agree / differ) |
| `hosting` | where the web host its name resolves to is located; every public A/AAAA is resolved, all countries listed |
| `cdn_edge` | the address belongs to a CDN (Cloudflare, Akamai, Fastly, ...), which answers from the location nearest the asker, so **no country is claimed** (`edge_country` is kept separately) |
| `unknown` | unresolvable; only the registry hint may be present |

Behind a CDN the edge node's country is still shown, labelled **CDN edge node** (it follows the asker, so it is not the site's location). For domains the VirusTotal answer TFII already fetches adds `registration`: registrar, creation date (a very recent one is a signal) and the registrant country when the WHOIS text is not redacted (self-declared). `GET /v2/dns/history?domain=` (on request, uses the caller's VirusTotal key or quota) returns what the name resolved to before (passive DNS), each located and marked CDN or not: earlier non-CDN addresses are the best clue to the real host of a site that moved behind a CDN.

`cctld_country_code` is the registry country of a real country-code TLD (`.mu` -> MU); it is a hint shown separately, never a location, and generic-use ccTLDs (`.io`, `.tv`, ...) are ignored.

## DNS records (`dnsintel.py`)

`GET /v2/dns?domain=` (any signed-in user) returns richer DNS records for a domain or a URL's host, from the public [NSLookup.io](https://www.nslookup.io) API: addresses with network owner and location, name servers, mail servers, TXT, CAA and SOA, plus SPF (parsed from TXT) and DMARC (`_dmarc.<domain>`), and plain-language observations (no SPF/DMARC, permissive SPF, DMARC `p=none`, no CAA, null-mail domain, many networks). The indicator page shows it as a **DNS records** panel for Domain and URL indicators.

* **No API key.** The API is public and allows **30 requests a minute per IP**, shared by every TFII user. One lookup is three requests, so answers are cached per domain for 6 hours (`dns_intel_cache`), requests are paced to 24 a minute, each user gets 6 lookups a minute, and a refresh is ignored within 10 minutes of the last fetch. After a 429 the client backs off. If NSLookup.io is unavailable a saved answer is returned, marked `stale`.
* **Looked up on request, not automatically**, and the domain name is sent to NSLookup.io.
* Record TTLs are not shown: through a caching resolver they are the remaining cache time, not the published value.
* `dns-lookup.yml` (manual) runs the client against the live API from the server and prints what it parsed.

## Indicator feeds and confidence (`feeds.py`)

Sources are declared in `feeds.FEEDS` (URL + pure parser + reliability + expiry + interval); the three abuse.ch connectors
(ThreatFox, MalwareBazaar, URLhaus) keep their own runners but share the catalog, provenance and corroboration.
Keyless today: **Feodo Tracker** (botnet C2), **OpenPhish**, **IPsum**, **CINS Army**, **Emerging Threats**, **blocklist.de**,
**Phishing.Database**; **AlienVault OTX** needs `OTX_API_KEY` (or a key saved in Settings).
Platform keys: every platform-level call (scheduled feeds, the NVD poller, shared/quota enrichment, LLM features) uses the key saved on an **admin** account first and the `.env` key second (`refresh_platform_keys()`: at startup, whenever an admin saves or removes a key, and every 5 minutes). abuse.ch runs also move on to the next key when one is rejected. A run started by an admin then tries their own key and, as the admin fallback, other users' saved keys. A non-admin's key is never a platform key. Keys are used server-side and never returned.

* **Reliability + corroboration.** Each source has a reliability; some entries carry their own evidence (IPsum's blocklist count).
  Confidence = noisy-OR over the *distinct* sources that reported the indicator (`1 − Π(1 − rᵢ)`, capped at 97). It only ever
  rises; false positives are never touched or renewed.
* **Two modes.** *Direct* feeds create an indicator when their own reliability clears the floor (`min_confidence`, default 70).
  *Consensus* lists (weak, unordered) are pooled in one run and only create indicators that several lists agree on; anything TFII
  already holds gets a recorded sighting, corroboration, and a refreshed expiry.
* **Fresh by construction.** Short TTLs (7–45 days) that every sighting extends; feed `first_seen` is kept as `observed_at`.
* **Hostile input.** Every entry is validated server-side (public IPs only, valid domains/hashes, http(s) URLs, trusted domains
  dropped); feed bodies are size-capped and fetched through the SSRF-safe client.
* **Enrichment.** After a run the newest, highest-confidence indicators are enriched (VirusTotal/AbuseIPDB/URLhaus, platform keys,
  spaced for free-tier limits, `enrich_per_run` default 8). Auto-enrichment may raise confidence but never lower it — a fresh C2 that
  VirusTotal has not seen yet is not evidence of innocence.
* **Operation.** `/admin/connectors/catalog|config` and `POST /admin/connectors/feeds/{id}/run` (background job); an hourly tick runs
  whatever is enabled and due. Results and failures show on **Platform → Connectors** and raise a System notification.

## Migrations

`migrations.MIGRATIONS` is an ordered list of `(version, name, [statements])` applied at startup under an advisory lock and
recorded in `schema_migrations`. Rules: **additive and idempotent** (so rolling the code back leaves a working DB); optional
statements (extensions, expression indexes) may fail without blocking; a failing required statement is logged, retried next
boot, and never stops the app from starting. The original v1 tables are still created by `main.py`.

* `1 phase1_workspace_and_indexes` — investigations, items, events, `ioc_provenance`, `iocs.last_seen`, core indexes
* `2 phase2_intelligence_core` — `iocs.analyst_status`, `entity_relationships`, `entity_observations`,
  `investigation_items.reason`, `mitre_cache`, lookup/trigram indexes

## Local development and tests

```bash
# backend (needs PostgreSQL; DB_HOST/DB_NAME/DB_USER/DB_PASS as in .env)
cd backend && python -m venv venv && . venv/bin/activate && pip install -r requirements-dev.txt
ADMIN_INITIAL_PASSWORD='choose-one' SECRET_KEY=$(openssl rand -hex 32) uvicorn main:app --reload
python -m pytest              # creates and drops its own throwaway database (role needs CREATEDB)

# frontend
cd frontend && npm ci --legacy-peer-deps
npm start                     # dev server; set the API origin in src/config.js
npx eslint src --ext .js --max-warnings 0 && CI=true npm test
```

The UI ships with a strict CSP (`connect-src 'self'`): it expects to be served from the same origin as the API, as nginx/Caddy do
in production. A separately-hosted dev UI must relax that meta tag in its own build.

## Security baseline (what is enforced server-side)

* Every route needs a bearer token except `/health`, `/auth/login`, `/auth/signup`, `/public/search`; a test walks the route table
  to keep it that way. Capabilities (`require_cap`) gate admin, import/export, TAXII and the indicator database.
* Outbound fetches on user-supplied URLs (redirect tracer, TAXII/MISP import, OSINT) go through `security.safe_client`: DNS is
  resolved **at connect time**, any non-public answer blocks the request, the connection is made to the vetted IP (no DNS
  rebinding), redirects are re-checked, `trust_env` is off.
* Stored and third-party text (feed titles, descriptions, notes, references) is rendered as text by React; links are only ever
  built from `safe_http_url`/`safeUrl` (http/https, no control characters), and a global link guard blocks anything else.
* No CORS by default, API docs disabled, `nosniff`/frame/referrer headers, `no-store` on API responses, upstream failures are
  502 with no URL echo, uniform login errors, per-endpoint rate limits (signup 5/h, login 10/min).
* Server-side validation never depends on the UI: enrichment/OSINT targets, import sizes (1 000), password/username policy.

### Known limitations (honest list)

* Roles are coarse: any full-access analyst can edit another analyst's IOC description/tags/campaign (false-positive flags are
  owner-or-admin only). Per-object ownership beyond that is a Phase-3 topic.
* JWTs live in `localStorage` (XSS would expose them) — mitigated by the strict CSP and no inline script, not eliminated.
  Moving to `HttpOnly` cookies needs CSRF protection and a same-site deployment assumption.
* `GET /iocs` (v1) is unbounded and kept for API compatibility; the UI uses `/v2/iocs` (paged).
* In-process caches (Intel Wall, MITRE, CVE summaries) and the rate limiter are per worker; run a single worker or move them to Redis.
* MITRE ATT&CK profiles are fetched on demand and cached per group (`mitre_cache`); the first request for a group can take seconds.
* Certificate and hostname entity kinds are not modelled: TFII stores no certificate or passive-DNS data to support them.

## Extending

* **New entity kind** — add to `entities.KINDS`, a `header()` branch, a `relationships()` branch (derived edges), optionally a
  `timeline()` branch; add a search `Provider`; add an entry to `frontend/src/lib/entity.js` and (if it needs a custom overview) a
  component registered in `frontend/src/pages/EntityPage.js`.
* **New relationship type** — one entry in `entities.REL_TYPES` (+ `GROUP_ORDER` if order matters).
* **New feed** — write to `iocs` through `main._ingest_feed_ioc` so provenance and sightings are recorded.

## Email addresses and mail domains

No free source rates an individual mailbox, so TFII judges the part that can be checked (`backend/mailintel.py`):

- **The domain.** VirusTotal and URLhaus reputation, registration age (very new domains are flagged), and how it is set up for mail: MX, SPF and DMARC read over DNS-over-HTTPS. These are reported as labelled observations ("No SPF record: easy to spoof"), not as a verdict on the person.
- **The provider.** Free mailbox services (gmail.com, outlook.com, ...) and a short list of disposable-mail services are recognised. A free-mail domain's good name never makes an address `clean`: the verdict stays `unknown`. No reputation lookups are spent on free-mail or disposable domains.
- **Role-style names** (`support@`, `billing@`, ...) are noted, since attackers pick them to look official.
- **Breach exposure** of the mailbox itself is asked only on request (`GET /v2/mail/exposure`), through XposedOrNot's public API, because the full address leaves the server and the free allowance is small and shared. A "not found" answer is not proof the address was never exposed.

Bulk lookup accepts email addresses, looks each domain up once however many addresses use it, and shows the observations on each row. AlienVault OTX was evaluated for address lookups and not used: its own SDK lists email as unsupported by its API.

