# Don't count the same evidence twice: scoring IOCs from public blocklists

*Draft. Suggested venues: your site / dev.to, r/netsec-style technical audience, LinkedIn. Add a diagram if you can: a box for IPsum containing CINS/ET/blocklist.de and an arrow to "your score".*

Say an IP shows up on four public blocklists. Is that four independent pieces of evidence?

Often not. Some lists are *aggregators*: IPsum, for example, collects roughly thirty public blocklists and reports how many of them list each address. If you ingest IPsum **and** the lists it aggregates, and then count "seen by 4 sources", you have counted the same observation two or three times.

Naive scoring makes noisy indicators look certain.

## The principles we ended up with

**1. Sources have different reliability.** A curated botnet C2 list (Feodo Tracker) deserves more weight than a large, unordered list of phishing domains. Give every source a number.

**2. Independent sources combine; they don't just add.** If two independent sources each give 70% confidence, the combined belief is higher than either but never above 100%. A "noisy-OR" style combination (`1 - Π(1 - p_i)`) does this naturally and cannot overflow.

**3. Count *distinct sources*, not distinct rows.** The same source repeating an indicator must not raise the score.

**4. Handle aggregators explicitly.** Don't count IPsum on top of CINS, Emerging Threats or blocklist.de as if they were independent. Use IPsum's own "listed on N lists" as the evidence, and treat the individual lists it covers as corroboration of the same thing.

**5. Use consensus for big noisy lists.** A giant list of domains with no ordering or metadata is weak on its own. Only promote an entry when another source also reports it.

**6. Show the reasoning.** A score with no explanation can't be argued with, and analysts stop trusting it. Show which sources contributed and why.

## What it looks like in practice

With IPsum, the number of lists that report an address is itself the evidence: a handful of lists is moderate confidence, seven or more is high. An address seen only by one noisy list stays low and unpromoted. An address reported by a curated C2 tracker *and* an aggregator gets a high combined score, and the indicator page lists both, so you can see precisely why.

## Caveats (say these out loud)

- Confidence here means "how much do independent sources agree", **not** "how likely is this to be malicious to you". A scanner IP is on many lists and may be irrelevant to your environment.
- Public feeds have false positives, shared hosting, and stale entries. Expire aggressively (TFII gives each source its own lifetime).
- Reliability numbers are judgement calls. Make them visible and tunable.

This scoring is implemented in TFII, an open-source, self-hosted threat-intel platform: https://github.com/sherifrahim/TFII (`backend/feeds.py` and `docs/INTELLIGENCE_CORE.md`). If you think the weights are wrong, open an issue; that's a feature.

*Disclosure: I'm the author.*
