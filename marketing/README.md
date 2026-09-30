# TFII marketing kit

Everything needed to launch TFII and get it in front of the right people. Nothing here has been posted anywhere: publishing, accounts and repo settings are yours to do (they are outward-facing and need your identity). This file is the shortest path.

| File | What it is |
|---|---|
| [positioning.md](positioning.md) | Who it is for, the one-line pitch, differentiation, messaging, words to avoid |
| [gtm-plan.md](gtm-plan.md) | Phased launch plan, channels, cadence, targets to measure |
| [launch-copy.md](launch-copy.md) | Ready-to-paste posts: Show HN, Reddit, LinkedIn, X/Mastodon, awesome-list PRs, newsletter pitches, release notes |
| [blog/](blog/) | Three article drafts that each teach something and end at TFII |
| [outreach.md](outreach.md) | Templates for feed maintainers, newsletter editors, and early users |
| [demo-script.md](demo-script.md) | A 3-minute walkthrough to record as a screencast / GIF |

Assets already in the repo: `docs/index.html` (landing page), `docs/og.png` (1200×630 social card), `docs/screenshots/` (7 shots, **seeded demo data**), a rewritten `README.md`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, issue/PR templates, CI, and `docs/DATA_FLOWS.md`.

## What only you can do (in this order)

**Before any post goes out (about 30 minutes)**

1. **Merge and deploy** this work to `master` (already pushed if you are reading this on master).
2. **Turn on GitHub Pages**: repo → Settings → Pages → Source: *Deploy from a branch* → `master` / `/docs`. The site will be at `https://sherifrahim.github.io/TFII/` (the landing page and OG tags assume this URL; if you use a custom domain, search-and-replace it in `docs/index.html`).
3. **Set the repo "About"**: description *"Self-hosted threat intelligence that shows its work: multi-source IOC feeds with corroborated confidence, honest location, CVE monitoring, bulk lookup, STIX/TAXII."*, website = the Pages URL, topics: `threat-intelligence`, `cti`, `ioc`, `cybersecurity`, `blue-team`, `soc`, `self-hosted`, `fastapi`, `react`, `stix`, `taxii`, `cve`, `threat-feed`.
4. **Upload the social preview**: Settings → General → Social preview → `docs/og.png`.
5. **Enable Discussions** (Settings → General → Features) and **private vulnerability reporting** (Settings → Code security). `SECURITY.md` points people there, so it must be on.
6. **Fresh-install test on a clean machine**: run the Quick Start exactly as the README says and note the first-login step. The Docker path was not runnable in the authoring sandbox, so it is the one thing not verified end to end. If it breaks, fix it before posting; a broken quick start on launch day is the most expensive mistake available.
7. **Create labels and 5–10 starter issues** (`good first issue`, `help wanted`): a new feed parser, an offline GeoIP source, self-hosting the UI fonts, docs pages. [outreach.md](outreach.md) and the GTM plan assume they exist.
8. **Tag a first release** (`v0.1.0`) with the notes in [launch-copy.md](launch-copy.md#release-notes-draft). Releases give newsletters and aggregators something to link.
9. **Decide the ip-api.com question** (see below) before you promote to companies.

**Launch week**

10. Post per [gtm-plan.md](gtm-plan.md) using [launch-copy.md](launch-copy.md). Be present in the comments for the first few hours; that is most of the work.
11. Record the screencast from [demo-script.md](demo-script.md) and add it to the README and landing page.

**Ongoing**

12. Publish one blog draft every 1–2 weeks. Reply to every issue within a day for the first month.

## Licensing flag to resolve before promoting to companies

TFII's location feature calls **ip-api.com's free endpoint**, whose published terms restrict it to non-commercial use, over HTTP. That is fine for personal and hobby use, but a company adopting TFII would be in breach without a paid plan. Options, easiest first: (a) leave it and state it (done in `docs/DATA_FLOWS.md`); (b) buy an ip-api plan; (c) swap in an offline GeoIP database. (c) is the best fix and is a good "first contribution" for the community. Also see the VirusTotal and OpenPhish notes in `docs/DATA_FLOWS.md`. This is diligence, not legal advice.

## Naming

"TFII" is also a well-known gene/transcription-factor name and a ticker-like string, so search for the bare name is crowded. Always pair it: **"TFII threat intelligence"**, and use the descriptor *self-hosted threat intelligence* in every title and repo description so search and social previews carry the meaning. A distinctive name would help in the long run; renaming is your call and is cheapest before people link to it.

## Honesty rules used throughout

- No claims about users, downloads, stars, accuracy or "AI-powered" anything that is not true. Add real numbers only when you have them.
- Screenshots are labelled as demo data.
- The product is described as open-source and self-hosted with bring-your-own keys. Paid options (hosted version, support, sponsorship) are listed in the GTM plan only as *options to consider later*.
- No testimonials are written here; collect real ones (see [outreach.md](outreach.md)).
