# Data flows: what leaves your TFII server

TFII is self-hosted and has **no telemetry**. It never sends anything to the project's authors. It does call third-party services, because that is how it gets feeds and enrichment. This page lists every outbound call so you can decide what is acceptable for your environment and check each provider's terms for your use.

"Sent" below means the value that leaves your server. Nothing is sent until the relevant feature runs (a scheduled feed, or someone using a lookup).

## Feeds and reference data (pulled on a schedule, nothing about your data is sent)

| Service | What TFII fetches | Key |
|---|---|---|
| abuse.ch — Feodo Tracker, URLhaus, ThreatFox, MalwareBazaar | Indicator lists | Free abuse.ch Auth-Key (`URLHAUS_AUTH_KEY` or Settings) |
| OpenPhish community feed | Phishing URLs | none |
| Phishing.Database (GitHub raw) | Active phishing domains | none |
| IPsum, CINS Army, Emerging Threats, blocklist.de | IP blocklists | none |
| AlienVault OTX | Subscribed pulses | your OTX key |
| NVD, CVE.org, CISA KEV, FIRST EPSS, OSV | CVE data | optional NVD key |
| MITRE ATT&CK (GitHub) | Actor and technique data | none |
| News and advisory RSS (e.g. CISA, Krebs, BleepingComputer, Talos, Securelist) | Headlines | none |

## Lookups (triggered by a user)

| Service | Sent | When | Notes |
|---|---|---|---|
| **VirusTotal** | The indicator (IP, domain, URL, hash; for an email address, only its domain, and not for free-mail or disposable domains) | Enrichment, bulk lookup, "Show past addresses" | Uses the requesting user's key, falling back to a key the admin saved. Query lookups are visible to VirusTotal under that key. |
| **AbuseIPDB** | The IP | Enrichment of IPs | Same key handling. |
| **URLhaus (abuse.ch)** | The URL / host / hash | Enrichment | Auth-Key. |
| **Shodan** | The IP or domain | OSINT lookup, if a key is set | Optional. |
| **Groq** | The text of a query-builder or report prompt | Only when someone uses the KQL/SPL builder or AI features | Optional; no key, no call. Do not paste sensitive data into it. |
| **dns.google** (Google Public DNS over HTTPS) | Domain name being looked up (for an email address: its domain) | Resolving domains to addresses for location context; MX, SPF and DMARC of an email's domain | Also used as a fallback to the OS resolver. |
| **XposedOrNot** | The full email address | Only when someone presses "Check breach exposure" on an email indicator | Public breach database, no key. Its free tier is small (about 25 requests an hour and 100 a day per IP), shared by everyone on your server, so TFII stays under it and caches answers for a day. Check their terms, especially for commercial use. |
| **NSLookup.io** | Domain name | When a user presses "Look up DNS records" | Public API, no key. Results are cached for 6 hours; TFII throttles itself well under their limit. |
| **RDAP** (IANA, ARIN) | Domain or IP | OSINT lookup | Public registries. |
| **ip-api.com** | The IP addresses (an IP indicator, or the addresses a domain resolves to) | Location and network owner for bulk lookup and indicator pages | **See "Things to review before you rely on this" below.** |

## Notifications (only if you configure them)

| Service | Sent |
|---|---|
| ntfy (ntfy.sh or your own server) | Notification text (e.g. new critical item) |
| Telegram | Notification text |

## The browser

The web app loads the **Inter** and **JetBrains Mono** fonts from Google Fonts. That means a visitor's browser contacts `fonts.googleapis.com` / `fonts.gstatic.com` when the page loads. If that matters to you (privacy rules, air-gapped networks), self-host the fonts by replacing the `@import` at the top of `frontend/src/design/tfii.css` and tightening the Content-Security-Policy in `frontend/public/index.html`.

## What is stored, and where

- Everything is in your PostgreSQL database and the local file store.
- Users' API keys are encrypted at rest (Fernet, `ENCRYPTION_KEY`). A key is decrypted only to make a request for its owner; the UI shows only the last four characters.
- Passwords are stored as hashes.
- Usage is recorded in your own database (API usage and an audit log) for the admin's benefit; none of it leaves your server.

## Things to review before you rely on this

These are honest caveats from the maintainers, not legal advice. Provider terms change; check the current terms yourself for how you use TFII, especially if it is used commercially or by an organisation.

1. **ip-api.com (free tier).** TFII currently uses ip-api's free endpoint for GeoIP and network-owner data. As published at the time of writing, the free tier is for **non-commercial use**, is limited per minute, and is served over plain **HTTP** (so the queried IPs cross the network unencrypted). For commercial or company use, either buy an ip-api plan (HTTPS, commercial licence) or replace the source. An offline GeoIP database is the better long-term fix and is a welcome contribution; see `geo_org_lookup_batch` in `backend/main.py`.
2. **VirusTotal.** The free public API is intended for personal, non-commercial use and has a low request quota. Using it inside a product or a team service can require a paid licence. TFII uses each user's own key, so the terms that apply are the ones that key was issued under.
3. **abuse.ch data** is published under their own terms (generally CC0 for the platform data, with the Auth-Key required). Check the current terms on abuse.ch.
4. **OpenPhish community feed** is free for non-commercial use; commercial use needs a subscription.
5. **Other blocklists** (CINS, Emerging Threats, blocklist.de, IPsum, Phishing.Database) each have their own licence or usage notes. Read the linked homepages in the feed table (Platform → Connectors) before redistributing any of that data.
6. **NVD.** This product uses data from the NVD API but is not endorsed or certified by the NVD.
7. **MITRE ATT&CK®** is a registered trademark of The MITRE Corporation; TFII is not affiliated with or endorsed by MITRE.
8. **NSLookup.io** public API is offered with a shared rate limit; be a good neighbour and do not run bulk automated lookups through it.

If any of these do not fit your situation, the fix is normally to turn the feature off (feeds can be disabled individually) or swap the source. Issues and pull requests that add permissively licensed alternatives are very welcome.
