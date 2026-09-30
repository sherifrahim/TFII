# 3-minute demo script

Record at 1440×900 or 1920×1080 with a screen recorder (e.g. OBS, or the OS built-in). Use a clean instance with demo data (a fresh install after the feeds have run once works well). Turn off notifications, blur nothing that isn't yours. Export an MP4 for social and a short GIF (≤15 s, ≤5 MB) for the README.

Say it plainly; don't read the screen aloud.

| Time | On screen | Say |
|---|---|---|
| 0:00 | Command Center | "This is TFII, a self-hosted threat intel workspace. These numbers come from public feeds and CVE data running on my own server." |
| 0:20 | Click into IOC Intelligence; filter by type Domain, confidence high | "Thousands of indicators from Feodo, OpenPhish, IPsum, abuse.ch and others. Filter by confidence, source, campaign." |
| 0:40 | Open one indicator | "One page per indicator. This confidence isn't one feed's opinion: it's how many independent sources agree, and here's the reasoning." |
| 1:05 | Scroll to location / registration | "Location is labelled. This one is behind a CDN, so TFII doesn't claim a country; it shows the edge node as an edge node, the registry country of the TLD as a hint, and registration details." |
| 1:30 | Click **Show past addresses** | "Passive DNS shows what this name pointed to before it went behind the CDN, a real clue to the origin." |
| 1:45 | **Look up DNS records** | "DNS records, with SPF and DMARC parsed and flagged." |
| 2:00 | Bulk Lookup: paste a defanged list, run, then Export CSV | "Paste up to 150 indicators, defanged is fine. Reputation, network owner and labelled location per row. Export to CSV." |
| 2:25 | CVE Intelligence | "CVEs with KEV and EPSS, grouped by the software I run." |
| 2:40 | Ctrl+K search | "Ctrl+K searches everything." |
| 2:50 | Landing page or README, quick start command | "Docker, MIT, no telemetry. `git clone`, run the setup script, done. Link below." |

**Caption for social:** *3-minute tour of TFII, self-hosted threat intel that shows its work. Screen shows demo data.*

**Checklist**
- [ ] Use demo or non-sensitive data only
- [ ] No API keys, passwords or private hostnames visible (the settings pages especially)
- [ ] Cursor movements slow and deliberate
- [ ] Add captions (most people watch muted)
