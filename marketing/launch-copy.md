# Launch copy (paste-ready, edit to sound like you)

Replace `<PAGES>` with your landing URL and keep the repo link. Disclose that you are the author everywhere. Do not post until the Phase 0 gate in [gtm-plan.md](gtm-plan.md) passes.

---

## Show HN

**Title** (≤80 chars, no hype):
`Show HN: TFII – self-hosted threat intel that shows its work`

**URL:** https://github.com/sherifrahim/TFII

**First comment (post it yourself right after submitting):**

> I built TFII because the free threat feeds I used were either lists of things to block or platforms too heavy for a small team. It pulls public IOC feeds (Feodo, OpenPhish, IPsum, CINS, Emerging Threats, blocklist.de, abuse.ch, OTX) and CVE data (NVD, KEV, EPSS) into one workspace.
>
> Two things I cared about:
>
> 1. **Confidence you can audit.** Each source has a reliability; independent sources combine; an aggregator like IPsum isn't counted twice against the lists it aggregates. The indicator page shows the reasoning.
> 2. **Honest location.** I searched a .mu domain and a tool told me it was in Italy. It was behind Cloudflare, and the "Italy" was just the CDN edge nearest the asker. TFII now labels each fact (IP location, hosted in, CDN edge node, TLD registry, registrant country) and refuses to pin a country on a CDN.
>
> It's Docker, MIT, no telemetry, and `docs/DATA_FLOWS.md` lists every outbound call. It's not a SIEM or a paid-TI replacement, and there's been no independent security audit; details are in the README. Screenshots use seeded demo data.
>
> I'd love feedback on the confidence model and on what you'd want from a small-team TI tool. Known gap: the GeoIP source is ip-api's free tier (non-commercial); an offline GeoIP source would be a great PR.

---

## r/selfhosted (text post)

**Title:** `TFII: a self-hosted threat intelligence platform (Docker, MIT, no telemetry)`

> Hi all, I'm the author. TFII is a self-hosted threat intel workspace for small teams and homelabs: it pulls free public feeds (phishing, botnet C2, blocklists, CVEs with CISA KEV and EPSS) into one UI with search, bulk lookup, a relationship graph, and STIX/TAXII.
>
> - `git clone … && ./scripts/docker-setup.sh` generates secrets and a one-off admin password
> - Runs on a small VM (an always-free ARM instance is enough)
> - No telemetry; the outbound calls are documented in `docs/DATA_FLOWS.md`
> - Bring your own API keys (VirusTotal, AbuseIPDB, abuse.ch, OTX), per user, encrypted, with a Test button
>
> Screenshots (demo data): <link>. Repo: https://github.com/sherifrahim/TFII. Honest limitations are listed in the README. Happy to answer questions and take bug reports.

---

## r/blueteamsec / r/cybersecurity

Lead with the lesson, not the product. Use blog draft 1 as the post and put the tool link in a final line. Check each sub's rules on self-promotion first.

**Title:** `Your IOC tool's "country" for a domain is probably a CDN edge, not the origin`

> (Paste the blog draft, or a 4-paragraph summary + link. End with: "I built this into an open-source tool, TFII, which now labels these facts instead of guessing: <repo>. Disclosure: I'm the author.")

---

## LinkedIn

> I searched a .mu domain in a threat-intel tool and it said the domain was in Italy.
>
> It wasn't. It was behind Cloudflare, and the "location" was just the CDN edge nearest to whoever asked.
>
> That small lie is why I built TFII: open-source, self-hosted threat intelligence that shows its work.
>
> • Confidence from multiple sources, with the reasoning visible
> • Locations labelled for what they are (IP, hosting, CDN edge, TLD registry), never guessed
> • Bulk lookup for up to 150 IOCs, CSV export
> • CVEs with KEV and EPSS, mapped to the software you run
> • Docker, MIT, no telemetry
>
> It's built for small blue teams without a TI budget. It is not a SIEM and it has not had an independent audit; the README says so.
>
> Repo and screenshots (demo data) in the first comment. I'd value feedback from anyone running a small SOC.
>
> #threatintelligence #blueteam #opensource #cybersecurity

**First comment:** the repo link + landing page.

---

## X / Bluesky / Mastodon (thread)

1. `Searched a .mu domain in a threat-intel tool. "Location: Italy." It was behind Cloudflare; that's just the CDN edge nearest the asker. So I built TFII: self-hosted threat intel that shows its work. 🧵` (+ screenshot 03)
2. `Confidence isn't one feed's opinion. Each source has a reliability, independent sources combine, and aggregators like IPsum aren't double-counted. Every indicator page shows the reasoning.` (+ screenshot 03)
3. `Location is labelled: IP location / hosted in / CDN edge node / TLD registry / registrant country, plus past addresses from passive DNS to see behind a CDN.`
4. `Bulk lookup: paste up to 150 IOCs (defanged is fine), get reputation + network + location, export CSV.` (+ screenshot 05)
5. `CVEs with CISA KEV + EPSS, mapped to the software you actually run.` (+ screenshot 06)
6. `Docker, MIT, no telemetry, every outbound call documented. Not a SIEM; no independent audit yet. Repo: https://github.com/sherifrahim/TFII (I'm the author; feedback welcome).`

Hashtags on Mastodon: #infosec #threatintel #selfhosted #opensource #blueteam.

---

## Awesome-list PR one-liners

Match each list's format exactly and read its contribution guide.

- **awesome-threat-intelligence** (Tools / Platforms):
  `- [TFII](https://github.com/sherifrahim/TFII) - Self-hosted threat intelligence platform with multi-source IOC feeds, corroborated confidence, CVE monitoring, bulk lookup and STIX/TAXII.`
- **awesome-selfhosted** (check current criteria; they require things like a stable release and a described license, and their format is `- [Name](url) - Description. ([Demo](url), [Source Code](url)) `MIT` `Python``):
  `- [TFII](https://github.com/sherifrahim/TFII) - Threat intelligence platform that combines public IOC feeds and CVE data with corroborated confidence scoring, bulk lookup and STIX/TAXII. ([Source Code](https://github.com/sherifrahim/TFII)) `MIT` `Python`/`Docker``

---

## Newsletter pitch (≈60 words)

**Subject:** `Open-source threat intel that labels its own uncertainty (TFII)`

> Hi <name>, I maintain TFII, a free self-hosted threat-intel platform for small teams. Two ideas might suit your readers: confidence built from independent source agreement (aggregators aren't double-counted), and IOC location labelled honestly, so a domain behind a CDN isn't given a country. MIT, Docker, no telemetry. Repo: <link>. Happy to write a short guest note if useful.

---

## Directory listing blurb (AlternativeTo, etc.)

**Name:** TFII (ThreatFeed Intelligence Platform) · **Category:** Security / Threat intelligence · **Licence:** MIT, self-hosted
**Tagline:** Self-hosted threat intelligence that shows its work.
**Description:** Combine public IOC feeds and CVE data in one workspace with corroborated confidence, honest location labelling, bulk lookup, relationship graph and STIX/TAXII. Docker, no telemetry.
**Alternatives to name:** MISP, OpenCTI, OpenCVE (say what you do differently; be generous).

---

## Release notes draft

**v0.1.0: first public release**

TFII is a self-hosted threat intelligence platform for small teams.

**Highlights**
- Multi-source IOC feeds (Feodo Tracker, OpenPhish, Phishing.Database, IPsum, CINS, Emerging Threats, blocklist.de, AlienVault OTX, abuse.ch) with per-source reliability and corroborated confidence.
- Honest location: IP location, hosted-in, CDN edge, TLD registry, registrant country, and past addresses.
- Bulk lookup (up to 150), CSV export, DNS records with SPF/DMARC.
- **Detailed report**: pick indicators from a lookup and get one tab per provider (detections, engines, registration, DNS, reports, payloads), side by side, as Markdown or JSON.
- **Email indicators** judged through their domain (SPF, DMARC, age, free or disposable provider), with optional breach-exposure (XposedOrNot), address-risk (IPQualityScore) and deep mail-domain tests (MxToolbox).
- **AI assistants** (Groq, or your own CodeCraft key): summarise a report, assess an indicator, digest a bulk batch, draft an investigation write-up, turn plain English into IOC filters, explain an email domain. Answers are labelled AI-generated and shown as plain text beside the data. No key, no call.
- CVE monitoring with KEV, EPSS and "affects my software".
- Per-user encrypted API keys with a Test button.
- STIX 2.1 export and TAXII 2.1 server.
- A redesigned interface that works on phones and passes an automated WCAG 2 A/AA audit (axe-core) on every page.

**Security and setup**
- No default password: the setup script generates one, or the backend prints a random one on first start.
- Docker quick start is built and started in CI on every change to the Docker files, UI or backend.
- See `SECURITY.md` for reporting and `docs/DATA_FLOWS.md` for every outbound call, including exactly what each AI button sends.

**Known limitations**
- No independent security audit.
- GeoIP uses ip-api's free tier (non-commercial); an offline source is planned.
- Public feeds are noisy; scores are a triage aid.
- AI answers can be wrong. They summarise the data on screen and never replace it.
- The XposedOrNot, IPQualityScore and MxToolbox integrations have been tested against recorded responses, not yet at scale against the live services. (CodeCraft as an AI provider has been confirmed with a real key.)
- Automated accessibility checks do not replace testing with a screen reader.

Thanks to the maintainers of the public feeds this depends on.
