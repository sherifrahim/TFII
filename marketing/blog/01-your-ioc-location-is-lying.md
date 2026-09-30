# Your IOC tool's "country" is probably a CDN edge, not the origin

*Draft. Suggested venues: your own site / dev.to / Medium, then LinkedIn and r/blueteamsec. Add your own real example screenshot from TFII.*

I searched a `.mu` domain in a threat-intel tool and it told me the domain was in Italy.

Mauritius, Italy... neither was obviously wrong until I looked. The domain sat behind Cloudflare. "Italy" was simply where the Cloudflare node that answered my query was located. It had nothing to do with the site, its operators, or where the malware was served from.

If you triage indicators, you have probably seen this. It's worth understanding why it happens, what you *can* infer, and how a tool should present it.

## Why the country is wrong

When you resolve a domain, you get IP addresses. GeoIP databases map an IP to a country. That works for an ordinary server: the IP is the server.

CDNs and anycast networks break the assumption. The same IP is announced from many places, and DNS answers can differ by the location of whoever asks. What your tool sees is the edge nearest to *it*. Ask from a server in Milan and you may "find" the site in Italy. Ask from Frankfurt and it moves.

So for a domain behind a CDN, a country next to it is a fact about the **asker's neighbourhood**, and it reads like a fact about the **target**.

## What you can infer instead

A more honest breakdown of "where is this?":

| Question | What answers it | How much to trust it |
|---|---|---|
| Where is this **IP**? | GeoIP of that address | Fine for ordinary hosting; meaningless for anycast |
| Where is the **web host** of this domain? | GeoIP of the resolved IPs, *if not a CDN* | Where the servers are, not the operators |
| Is it behind a **CDN**? | Network owner of the IP (Cloudflare, Akamai, Fastly...) | Reliable; then withhold the country |
| What does the **TLD** say? | Country-code TLDs (`.mu`, `.de`) name a registry country | A hint only: `.io`, `.co`, `.tv` are sold worldwide; registrants are anywhere |
| Who **registered** it, and when? | WHOIS/RDAP registrar, creation date, sometimes a registrant country | Self-declared and often redacted; a creation date of *last week* is a strong signal |
| What did the name **point to before**? | Passive DNS history | The best clue to an origin that later moved behind a CDN |

None of these prove where an attacker is. Together they let an analyst reason, instead of copying a country into a ticket.

## Design rules for tools

1. **Label every fact** with what it is. "Hosted in: Germany" and "TLD registry: Mauritius" are different sentences.
2. **Refuse to guess.** Behind a CDN, say so and show the edge as an *edge*, muted, with a note that it follows the asker.
3. **Show the age of the name.** New registrations are often the useful part.
4. **Give a way to look behind the CDN**, e.g. past addresses from passive DNS, flagging the ones that were not CDN.
5. **Cross-check** an IP's country against a second source and show disagreement rather than hiding it.

## What I did about it

I fixed this in TFII, the open-source, self-hosted threat-intel platform I'm building. For the `.mu` domain it now shows: *Behind Cloudflare, real host hidden*; *CDN edge node: Italy* (muted, with an explanation); *TLD registry: Mauritius*; *Registered: registrar and date*; and a button to show past addresses. No country is claimed.

(An overcorrection along the way: at first I hid the edge country entirely, and people rightly said "now there's no location at all". Showing the edge, labelled, was the better answer.)

TFII is MIT-licensed, runs with Docker, and has no telemetry: https://github.com/sherifrahim/TFII

*Disclosure: I'm the author.*
