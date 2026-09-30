# Positioning

## One line

**TFII is self-hosted threat intelligence that shows its work.**

Longer: a free, open-source platform that pulls public threat feeds and CVE data into one analyst workspace and explains why it believes what it says: which sources agree, how confident it is, and what a location actually means.

## The problem, in the audience's words

- "We have twelve feeds and no idea which to trust."
- "The tool says this domain is in Italy. It's behind Cloudflare. It's not in Italy."
- "MISP and OpenCTI are great but heavy; I need something I can stand up on a Friday."
- "Commercial TI is out of budget; the free lists are just text files."

## Who it is for (ranked)

1. **Small blue teams and one-person SOCs** (MSSPs, mid-size companies, universities). Need triage and context, have no TI budget. *Primary.*
2. **Homelab / self-hosted enthusiasts and security learners** who want a real TI tool to run and read. They amplify: they post, star and contribute. *Amplifier.*
3. **Incident responders and threat hunters** who paste lists of indicators and want fast, honest context. *Power users of bulk lookup.*
4. **Contributors** (feed authors, GeoIP/DNS folks). Not customers, but the project needs them.

Not for: enterprises needing SLAs, multi-tenant SaaS, or a SIEM/EDR replacement.

## Why choose it (proof points that are true today)

| Claim | Proof in the product |
|---|---|
| Confidence you can audit | Per-source reliability; independent sources combine; aggregators are not double-counted; the reasoning is shown on each indicator |
| Honest location | Labels: IP location / hosted in / CDN edge node / TLD registry / registrant country; refuses to pin a country on a CDN edge; shows past addresses via VirusTotal passive DNS |
| Runs on your box | Docker quick start, no telemetry, every outbound call documented |
| Keys stay yours | Per-user encrypted keys, owner-only, Test button |
| Fast triage | Bulk lookup of up to 150 IOCs, defang-tolerant, CSV export |
| Interoperable | STIX 2.1 export, TAXII 2.1 server, STIX/TAXII/MISP/CSV import |
| Cheap | Runs on a free-tier VM; default feeds are free |

## How it differs (be fair to the neighbours)

| | Where it is stronger | Where TFII fits |
|---|---|---|
| **MISP** | Mature sharing, huge community, deep data model | Lighter, opinionated, ready-to-read UI; not a sharing hub |
| **OpenCTI** | Full knowledge graph, connectors, enterprise features | Much smaller footprint; a starter you can outgrow |
| **OpenCVE** | Focused CVE monitoring and alerting | TFII covers CVEs and IOCs together, with KEV/EPSS and "affects my software" |
| **Commercial TIPs** | Curated proprietary intel, support | Free, transparent, no vendor lock-in |

Never say "better than MISP/OpenCTI". Say "lighter, and explains itself". People from those communities are the best contributors; do not start fights.

## Messaging pillars

1. **Shows its work.** Every score has reasons. Every location has a label.
2. **Small-team friendly.** One `docker` command, free data, no cloud account.
3. **Yours.** Self-hosted, your keys, no telemetry.
4. **Honest about limits.** A "What it is not" section is a feature; it builds trust with a sceptical audience.

## Tone

Plain, technical, specific. Show a screenshot or a concrete example (the `.mu` domain in "Italy") in the first three lines of anything. Sceptical readers trust modesty and specifics, and punish hype.

## Words to avoid

"AI-powered", "next-gen", "revolutionary", "military-grade", "real-time" (feeds refresh on schedules), "enterprise-grade", "zero-trust", "100%", "the best". Also avoid implying endorsement by MITRE, NIST, CISA, VirusTotal or any data source.

## Boilerplate

**Short (≤160):** TFII is free, self-hosted threat intelligence with corroborated feed confidence, honest IOC location, CVE monitoring and bulk lookup.

**Medium:** TFII (ThreatFeed Intelligence Platform) is an open-source, self-hosted platform for small security teams. It combines public IOC feeds and CVE data in one workspace, scores indicators by how many independent sources agree, and labels what each fact means, for example never claiming a country for a domain behind a CDN. MIT-licensed, runs with Docker, no telemetry.
