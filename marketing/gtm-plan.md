# Go-to-market plan

**Model:** open-source, self-hosted, bring-your-own-keys. The goal for the first 90 days is **real installs and contributors**, not revenue. Stars are a lagging indicator, so measure activation (someone got it running and looked up an indicator).

All numbers below are *targets to steer by*, not forecasts.

## The funnel

`See it` → `Understand it in 20 seconds` → `Trust it` → `Run it in 5 minutes` → `Get value` → `Tell someone / contribute`

Each phase fixes the weakest step.

## Phase 0: Trust and readiness (before any post)

Done in the repo: no default password, LICENSE, SECURITY, CONTRIBUTING, templates, CI, honest README, data-flow disclosure, landing page, social card, real screenshots.
Owner steps in [README.md](README.md#what-only-you-can-do-in-this-order): Pages, repo About/topics, social preview, Discussions, private vuln reporting, fresh-install test, first release.

**Gate:** a stranger can go from the README to a logged-in instance with data in under 10 minutes. If not, fix that first.

## Phase 1: Soft launch (week 1)

Goal: 5–10 people run it and tell you what breaks.

- Personal network first: LinkedIn post + direct messages to a handful of practitioners (template in [outreach.md](outreach.md)). Ask for a fresh install and honest feedback, not a star.
- Post in one small, friendly community (e.g. a security Discord/Slack you already belong to).
- Fix every install snag the same day. Collect real quotes (with permission) for later.

## Phase 2: Public launch (week 2–3)

One coordinated day, mid-week, morning US Eastern (when HN and Reddit are most active).

| Channel | Format | Angle |
|---|---|---|
| **Hacker News** (Show HN) | Link to GitHub or Pages | "Self-hosted threat intel that shows its work" plus the CDN-location story |
| **r/selfhosted** | Text post with screenshot | Self-hosting angle, Docker quick start, no telemetry |
| **r/blueteamsec**, **r/cybersecurity**, **r/netsec** | Follow each sub's self-promo rules exactly (r/netsec favours technical write-ups over product links: lead with a blog draft instead) | Technical lesson first, tool second |
| **LinkedIn** | Post + first-comment link | Practitioner audience, small SOC pain |
| **X / Bluesky / Mastodon (infosec.exchange)** | Thread with screenshots | The "Italy" story, then the feature list |
| **Lobsters** | Only if you have an invite and it fits the rules | Technical |
| **dev.to / Medium / Hashnode** | Cross-post blog drafts | SEO and long tail |

Rules: post once per community, never cross-spam the same hour, disclose you are the author, answer every comment, take criticism graciously.

## Phase 3: Distribution (weeks 3–8)

Get listed where people already look:

- **Awesome lists** (PRs, not requests): awesome-threat-intelligence, awesome-selfhosted (check the current inclusion criteria, some lists require a minimum project age or release history), awesome-incident-response / blue-team lists. Each PR: one line, correct category, follow their template.
- **Newsletters**: pitch the editors of security and self-hosting newsletters (tl;dr sec, Risky Bulletin, self-hosting weeklies, "This Week in…" digests). Verify each one's current submission method. Send a two-sentence pitch with a link, not an attachment.
- **Directories**: AlternativeTo, Slant, OpenAlternative-style lists, SaaSHub, GitHub topics pages. Free, evergreen, slow-burn traffic.
- **Podcasts / meetups**: submit a 15-minute talk ("Why your IOC feed's location field lies") to local BSides, OWASP and security-meetup CFPs. Talks build contributors better than posts.
- **Feed maintainers**: credit them and tell them (template in outreach). Some will link back; all deserve to know their data is used.

## Phase 4: Content flywheel (ongoing)

One article every 1–2 weeks from [blog/](blog/), each teaching a real lesson and ending with "TFII does this". Suggested order: (1) CDN location lie, (2) double-counted evidence, (3) bulk triage playbook, then: DMARC/SPF from DNS records, a KEV+EPSS "what to patch first" walkthrough, a self-hosted TAXII how-to. Reuse each as a LinkedIn post, a thread, and a talk.

SEO basics: use the phrases people search (*self-hosted threat intelligence platform*, *open source threat intel*, *IOC lookup*, *bulk IOC checker*, *MISP alternative lightweight*), keep the landing page fast, and publish the docs on Pages.

## Phase 5: Community and contributors

- Label 5–10 `good first issue` items (new feed parser, offline GeoIP source, self-hosted fonts, a docs page, translation of UI strings).
- Discussions for Q&A and a monthly "what shipped" note.
- Credit contributors in release notes. Reply to first-time PRs within 48 hours.

## Metrics (targets to steer by, adjust to reality)

| Stage | Signal | 30-day target |
|---|---|---|
| Reach | Landing-page visits, README views (GitHub Insights → Traffic; Pages has no analytics by default, which is consistent with the privacy stance) | Track the trend |
| Interest | Stars, watchers | Not a goal in itself |
| Activation | Issues/Discussions from people who installed; "it works" messages | 10+ real installs reported |
| Retention | People still running it after 2 weeks (ask) | A few |
| Contribution | External PRs / issues | 3+ |
| Advocacy | Unprompted mentions, list inclusions | 2+ lists |

Do not add analytics scripts to the landing page without telling users; if you want visit counts, use privacy-friendly analytics and say so on the page.

## Options to consider later (not decided; none built)

Only after there is real usage and people asking:

1. **GitHub Sponsors / Open Collective** for the maintainer.
2. **Paid support or installation help** for teams.
3. **A hosted version**, which changes the licensing situation for feeds and GeoIP (commercial terms apply), so budget for that.
4. **Commercial-licensed data connectors** (proper GeoIP, VirusTotal Premium) as opt-in.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Broken quick start on launch day | Fresh-install test (Phase 0 gate) |
| Security scrutiny finds a hole | SECURITY.md, private reporting on, fast fixes, thank reporters publicly |
| "Just another MISP/OpenCTI" | Lead with the concrete difference (evidence and honest location), not the feature list |
| Licence problems (ip-api free tier, VirusTotal, OpenPhish) | Documented in `docs/DATA_FLOWS.md`; swap to offline GeoIP; pitch to individuals and small teams until resolved |
| Name collision hurts search | Always write "TFII threat intelligence"; consider a distinctive name early |
| Maintainer overload | Say what is in scope, use issue templates, label and close politely |
