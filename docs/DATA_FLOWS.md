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
| **Groq** | The text of a query-builder or report prompt; for the AI assistants, a compact summary of what is on screen (see below) | Only when someone uses the KQL/SPL builder or an AI button | Optional; no key, no call. Do not paste sensitive data into it. |
| **CodeCraft** (codecraftapi.com) | The same compact summaries as Groq, when the person has saved their own CodeCraft key and no Groq key | Only when someone presses an AI button | Optional. Third-party gateway: check its terms before sending it anything sensitive. |
| **dns.google** (Google Public DNS over HTTPS) | Domain name being looked up (for an email address: its domain) | Resolving domains to addresses for location context; MX, SPF and DMARC of an email's domain | Also used as a fallback to the OS resolver. |
| **MxToolbox** | The mail domain (for the SMTP test, also its primary mail server's name) | Only when someone presses "Run MxToolbox tests" on an email indicator, with their own MxToolbox key | Optional. A free MxToolbox account allows 64 DNS lookups a day and no network lookups; one report uses about 6 DNS lookups, so reports are cached for 6 hours. Blocklist and SMTP tests need a paid plan and are an explicit option. Check their terms for your use. |
| **IPQualityScore** | The full email address (the key travels in the URL path, which TFII never logs) | Only when someone presses "Check address risk" on an email indicator, with their own IPQualityScore key | Optional. Their free plan is about 1,000 checks a month, so it is never run in bulk; answers are cached for a day. Check their terms for your use. |
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

## AI assistants

Buttons marked **AI** (report summary, indicator triage, bulk digest, investigation write-up, plain-English IOC search, mail explanation) send a
compact, text-only summary of what is on that screen to the AI provider, and nothing else:

* **Report summary**: the indicator, TFII's verdict and reason, and each provider's headline and first few detail rows.
* **Indicator triage**: the indicator, its score and reasoning, tags, campaign and actor, a subset of enrichment fields, up to 10 related
  indicators, 5 analyst notes and the last score changes.
* **Bulk digest**: for each result (up to 150), the value, type, verdict, score, reason, country and network owner.
* **Investigation write-up**: the investigation's name, description, up to 60 items, 25 timeline events and 8 notes.
* **Plain-English search**: only the sentence the person typed.
* **Mail explanation**: the address and the domain checks shown on the page.

Which key pays: the person's own Groq key, then their own CodeCraft key, then the platform's Groq key (limited to 40 answers per person per day).
Indicators, notes and descriptions can contain text written by third parties, so the model is told to treat everything as untrusted data; its answer is
shown as plain text only, labelled AI-generated, and the underlying data stays on the page. An AI answer is never saved as a fact. Without any key the
buttons are replaced by a prompt to add one, and nothing is sent. The "AI tools" permission (analyst and admin by default) controls who can use them.
