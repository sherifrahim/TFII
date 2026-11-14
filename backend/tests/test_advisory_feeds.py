"""Advisory feeds on the Intel Wall: each item is read from its own block, so a channel-level description can never shift
summaries (and the CVEs found in them) onto the next item; RSS 2.0, RDF and Atom all parse; ICHI is a source."""
import asyncio

import httpx

import main

# Shape of ICHI's feed (https://ichi.global/api/alerts), trimmed: note the channel <description> before the items.
ICHI = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel><title>ICHI — Critical vulnerability advisories</title>
<link>https://ichi.global/alert</link><atom:link href="https://ichi.global/api/alerts" rel="self" type="application/rss+xml"/>
<description>One advisory per critical active threat ICHI tracks.</description><lastBuildDate>Sat, 14 Nov 2026 22:57:04 GMT</lastBuildDate>
<item><title>New advisory: Openwave Messaging Limited Webtop Media Transcoder vulnerability exploited in the wild</title>
<link>https://ichi.global/alert?id=ichi-adv-202611-6e04e88ecfa8280e</link><guid isPermaLink="false">ichi-adv-202611-6e04e88ecfa8280e</guid>
<pubDate>Tue, 10 Nov 2026 20:57:04 GMT</pubDate><category>ADVISORY</category>
<description>ICHI assesses Openwave Messaging Limited Webtop Media Transcoder (CVE-2026-111793) as a critical active threat. Listed in the CISA KEV catalog. Review CISA&apos;s required action</description></item>
<item><title>New advisory: Cisco BroadWorks vulnerability exploited in the wild</title>
<link>https://ichi.global/alert?id=ichi-adv-202611-3e4a34cf2cbe6e8b</link><guid isPermaLink="false">ichi-adv-202611-3e4a34cf2cbe6e8b</guid>
<pubDate>Tue, 10 Nov 2026 20:57:04 GMT</pubDate><category>ADVISORY</category>
<description>ICHI assesses Cisco BroadWorks (CVE-2026-20320) as a critical active threat.</description></item>
</channel></rss>"""

ATOM = """<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Vendor</title>
<subtitle>Security notices</subtitle><link href="https://vendor.example/"/>
<entry><title>Critical remote code execution in Widget</title><link rel="alternate" href="https://vendor.example/a/1"/>
<updated>2026-11-12T10:00:00Z</updated><summary type="html">&lt;p&gt;Fixes CVE-2026-1111 &amp;amp; CVE-2026-2222.&lt;/p&gt;</summary></entry>
<entry><title>Hardening update for Gadget</title><link href="https://vendor.example/a/2"/><updated>2026-11-11T09:00:00Z</updated>
<summary>No CVE assigned.</summary></entry></feed>"""

RDF = """<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"
 xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>Debian Security</title><description>Debian Security Advisories</description></channel>
<item rdf:about="https://www.debian.org/security/2026/dsa-6629"><title>DSA-6629-1 network-manager-iodine - security update</title>
<link>https://www.debian.org/security/2026/dsa-6629</link><description><![CDATA[CVE-2026-3333 was found in iodine.]]></description>
<dc:date>2026-11-15</dc:date></item></rdf:RDF>"""


def test_each_item_keeps_its_own_summary_and_cves_despite_a_channel_description():
    items = main.parse_advisory_feed(ICHI)
    assert [i["cves_mentioned"] for i in items] == [["CVE-2026-111793"], ["CVE-2026-20320"]]
    assert items[1]["title"] == "New advisory: Cisco BroadWorks vulnerability exploited in the wild"
    assert items[1]["description"].startswith("ICHI assesses Cisco BroadWorks")          # the old parser gave it Openwave's text
    assert "CISA's required action" in items[0]["description"]                             # entities decoded
    assert items[0]["url"] == "https://ichi.global/alert?id=ichi-adv-202611-6e04e88ecfa8280e" and items[0]["date"] == "2026-11-10"


def test_atom_and_rdf_feeds_parse_too():
    atom = main.parse_advisory_feed(ATOM)
    assert [a["url"] for a in atom] == ["https://vendor.example/a/1", "https://vendor.example/a/2"]
    assert atom[0]["cves_mentioned"] == ["CVE-2026-1111", "CVE-2026-2222"] and atom[0]["severity"] == "Critical"
    assert atom[0]["description"] == "Fixes CVE-2026-1111 & CVE-2026-2222." and atom[1]["cves_mentioned"] == []
    rdf = main.parse_advisory_feed(RDF)
    assert len(rdf) == 1 and rdf[0]["cves_mentioned"] == ["CVE-2026-3333"] and rdf[0]["date"] == "2026-11-15"


def test_junk_and_empty_feeds_give_no_items():
    assert main.parse_advisory_feed("") == [] and main.parse_advisory_feed("<html><body>Not a feed</body></html>") == []
    assert main.parse_advisory_feed("<rss><channel><item><title>x</title></item></channel></rss>") == []    # title too short


def test_ichi_is_an_intel_wall_advisory_source_and_fetches_through_the_parser(monkeypatch):
    assert ("https://ichi.global/api/alerts", "ICHI", "Exploited") in main.CVE_FEEDS
    real = httpx.AsyncClient

    def fake_client(**kw):
        kw.pop("transport", None)
        return real(transport=httpx.MockTransport(lambda req: httpx.Response(200, text=ICHI)), **kw)
    monkeypatch.setattr(main.httpx, "AsyncClient", fake_client)
    r = asyncio.run(main.fetch_cve_rss("https://ichi.global/api/alerts", "ICHI", "Exploited"))
    assert r["ok"] and r["source"] == "ICHI" and len(r["items"]) == 2
    assert {i["source"] for i in r["items"]} == {"ICHI"} and r["items"][1]["cves_mentioned"] == ["CVE-2026-20320"]
