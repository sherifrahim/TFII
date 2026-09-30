# A practical playbook for triaging a list of IOCs in 15 minutes

*Draft. Suggested venues: your site / dev.to, LinkedIn. Screenshot: TFII bulk lookup (docs/screenshots/05-bulk-lookup.png, demo data).*

You've been handed a list: from a phishing report, an incident ticket, a vendor blog. Forty domains, some URLs, a few IPs, a couple of hashes, all defanged (`hxxps://evil[.]example`). What now?

Here is a workflow that fits in a coffee break.

## 1. Normalise first

Refang, deduplicate, and strip noise: `hxxp` → `http`, `[.]` → `.`, trailing punctuation, tracking parameters. Separate by type (IP, domain, URL, hash). Mixing types in one query is how things get missed.

*A good tool does this on paste.* TFII's bulk lookup accepts up to 150 indicators, tolerates defanged input, and sorts them by type.

## 2. Drop the obviously benign

Your own domains, well-known infrastructure, RFC1918 addresses. Anything you'd embarrass yourself by blocking. Keep a small allowlist.

## 3. Get a quick reputation for everything

You want one row per indicator: reputation source(s), confidence, first seen. This is the "is anyone else worried about this?" pass. Free sources (abuse.ch, blocklists) cover a lot; VirusTotal and AbuseIPDB add depth if you have keys. Respect quotas: batch, cache, and don't re-query the same thing.

## 4. Add context that changes decisions

For domains and URLs:
- **Is it behind a CDN?** If yes, blocking the IP is pointless, and the location field is not the origin.
- **When was it registered?** Brand-new registrations are much more suspicious than old ones.
- **DNS records:** name servers, mail servers, and whether SPF/DMARC exist. A lookalike domain with no MX and a fresh registration is a phishing landing page, not a mail sender.
- **Past addresses** (passive DNS): a previous non-CDN address can reveal the real host.

For IPs: network owner, and whether GeoIP agrees with a second source.

## 5. Decide, then record

Three buckets: **block / watch / ignore**. For each, one line of *why*. Export the table (CSV) and attach it to the ticket. Two weeks later, "why did we block this?" has an answer.

## 6. Feed what you learned back

Add the confirmed-bad ones to your blocklist or SIEM watchlist; add the interesting ones to an investigation so related indicators (same campaign, same /24, same registrar) surface.

## Pitfalls

- A country is not attribution. See "Your IOC tool's country is probably a CDN edge".
- Aggregated blocklists overstate agreement; see "Don't count the same evidence twice".
- Treat every score as a triage aid, not a verdict.

This workflow is built into TFII: bulk lookup with labelled location, DNS records, past addresses, and CSV export. It's open-source, self-hosted, MIT: https://github.com/sherifrahim/TFII

*Disclosure: I'm the author.*
