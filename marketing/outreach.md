# Outreach templates

Rules: personalise the first line, keep it short, make one clear ask, and never ask for a star. Send to people you have a genuine reason to contact. No mass mailing, no scraped lists.

## 1. Practitioner early-tester (DM / email)

> Hi <name>, I saw your <post/talk/comment> about <specific thing>. I've built an open-source, self-hosted threat-intel tool for small teams (TFII) and I'm looking for 5–10 people who'd try a fresh install and tell me where it breaks. Docker, about 10 minutes, no account or telemetry. Would you be up for it? Even "the quick start failed at step 3" is useful. Repo: <link>. Thanks either way.

**Follow-up questions to ask** (these produce your best quotes and roadmap):
1. Where did you get stuck? 2. What did you expect to see first? 3. Which feed or field would you not trust? 4. What would make you keep it running? 5. Can I quote you (name/anonymous)?

## 2. Feed maintainer (credit + heads-up)

> Hi <name>, I maintain TFII, an open-source threat-intel platform. It pulls <feed> on a <interval> schedule with a `TFII-ThreatIntel` user-agent, credits you as the source on every indicator, and links to your homepage. I wanted to say thanks, and check that this use is fine with you (I've read <licence/terms page>). If you'd prefer a different interval, attribution wording or a link back, tell me and I'll change it.

Keep a note of each maintainer's answer. If anyone objects, disable that feed by default.

## 3. Newsletter / podcast editor

> Hi <name>, I enjoyed <recent issue/episode>. Sharing in case it suits your readers: TFII is a free self-hosted threat-intel platform whose two ideas are (1) confidence from independent source agreement, with the reasoning visible, and (2) honest IOC location that doesn't pin a country on a domain behind a CDN. MIT, Docker, no telemetry. Link: <link>. Happy to answer questions or write a short piece. No worries if it's not a fit.

## 4. Meetup / conference CFP

**Title:** *Your IOC feed's "location" field is lying to you*
**Abstract (≈100 words):** Threat-intel tools happily print a country next to a domain. Behind a CDN, that country is where the *edge node nearest the lookup* is, not where the attacker or origin server is. We walk through how DNS, anycast and CDNs produce misleading locations, what you can and can't infer (hosting, TLD registry, registrant, passive DNS), and how to label uncertainty in a tool. Includes live examples and an open-source implementation (TFII). Audience: SOC analysts, threat hunters, tool builders. Level: intermediate. 20 minutes.

## 5. Contributor invitation (on a relevant issue, PR or forum thread)

> This looks like something TFII could use. The feed parsers in `backend/feeds.py` are small and pure (a URL, a parser, a reliability), so adding one is a self-contained first PR. There's a `good first issue` label with a few starting points and `CONTRIBUTING.md` covers running the tests. Happy to help you get set up.

## 6. Thanking a first-time contributor or reporter

> Thanks for this: <one specific thing they did>. It's merged/fixed in <ref> and you're credited in the release notes. If you'd like a different name or link used, tell me.

## 7. Collecting a testimonial (only real ones)

> Would you be comfortable with me quoting what you said ("<exact quote>") on the project page, credited as <name, role, org> or anonymously? I'll show you the final wording first.
