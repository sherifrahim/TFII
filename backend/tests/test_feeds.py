"""IOC feeds: parsing, validation of third-party data, consensus + corroboration, provenance, admin API."""
import asyncio
import json

import pytest

import feeds


# ── parsers (pure) ───────────────────────────────────────────────────────────
FEODO = json.dumps([
    {"ip_address": "45.9.148.10", "port": 443, "status": "online", "malware": "QakBot", "country": "NL", "as_number": 1, "first_seen": "2026-09-20 10:00:00"},
    {"ip_address": "185.1.2.3", "port": 8080, "status": "offline", "malware": "Emotet"},
    {"ip_address": "10.0.0.5", "status": "online", "malware": "TrickBot"},          # private: must be dropped
    "not-an-object", {"ip_address": "999.1.1.1"},
])
IPSUM = "# comment\n45.9.148.10\t5\n8.8.4.4\t1\n93.184.215.9\t7\n192.168.1.1\t8\nbad-line\n"


def test_feodo_parser_and_validation():
    cands = [feeds.clean_candidate(c) for c in feeds.parse_feodo(FEODO)]
    good = [c for c in cands if c]
    assert [c.value for c in good] == ["45.9.148.10", "185.1.2.3"]
    assert good[0].reliability == 0.92 and good[1].reliability == 0.80
    assert good[0].family == "QakBot" and good[0].context["country"] == "NL" and good[0].first_seen.year == 2026


def test_ipsum_uses_the_blocklist_count_as_evidence_and_drops_weak_and_private():
    cands = feeds.parse_ipsum(IPSUM)                      # min level 3
    assert [c.value for c in cands] == ["192.168.1.1", "93.184.215.9", "45.9.148.10"]   # strongest first
    assert feeds.clean_candidate(cands[0]) is None         # private address
    by = {c.value: c.reliability for c in cands}
    assert by["93.184.215.9"] == 0.90 and by["45.9.148.10"] == 0.80


@pytest.mark.parametrize("c,ok", [
    (feeds.Candidate("http://evil.example/a", "URL", .8), True),
    (feeds.Candidate("javascript:alert(1)", "URL", .8), False),
    (feeds.Candidate("http://127.0.0.1/x", "URL", .8), False),
    (feeds.Candidate("http://10.1.1.1/x", "URL", .8), False),
    (feeds.Candidate("http://www.google.com/x", "URL", .8), False),       # trusted domain
    (feeds.Candidate("Evil.Example.", "Domain", .8), True),
    (feeds.Candidate("bad_domain", "Domain", .8), False),
    (feeds.Candidate("a" * 64, "SHA256", .9), True),
    (feeds.Candidate("a" * 63, "SHA256", .9), False),
    (feeds.Candidate("zz" * 32, "SHA256", .9), False),
    (feeds.Candidate("1.2.3.4", "Email", .9), False),
    (feeds.Candidate("", "IPv4", .9), False),
])
def test_feed_data_is_validated_as_hostile_input(c, ok):
    assert (feeds.clean_candidate(c, trusted_domains=("google.com",)) is not None) is ok


def test_otx_pulses():
    text = json.dumps({"results": [{"id": "p1", "name": "Campaign X", "adversary": "APT-Test", "tags": ["Phish"],
        "malware_families": [{"display_name": "Lumma"}],
        "indicators": [{"type": "domain", "indicator": "bad.example", "created": "2026-09-01T00:00:00"},
                       {"type": "FileHash-SHA256", "indicator": "b" * 64}, {"type": "email", "indicator": "x@y.z"}]}]})
    c = feeds.parse_otx(text)
    assert [(x.type, x.value) for x in c] == [("Domain", "bad.example"), ("SHA256", "b" * 64)]
    assert c[0].family == "Lumma" and c[0].reliability == pytest.approx(0.78) and c[0].context["adversary"] == "APT-Test"
    assert feeds.parse_otx("not json") == []


def test_noisy_or_rewards_distinct_agreement_only():
    assert feeds.noisy_or([0.62, 0.62]) == pytest.approx(1 - 0.38 ** 2)
    assert feeds.corroborated_confidence({"A": 0.62}) == 62
    assert feeds.corroborated_confidence({"A": 0.62, "B": 0.66}) > 85
    assert feeds.corroborated_confidence({"A": .9, "B": .9, "C": .9, "D": .9}) == feeds.CONF_CAP


# ── ingestion against the database ───────────────────────────────────────────
def _run(client, feed_id, cfg, texts):
    import main
    conn = main.get_db_direct()
    try:
        return asyncio.run(feeds.run_feed(conn, feed_id, cfg, ingest=main._ingest_feed_ioc, record_score=main.record_score,
                                          defang=main.defang, trusted_domains=tuple(main.TRUSTED_DOMAINS), texts=texts))
    finally:
        conn.close()


def _ioc(db, value):
    cur = db.cursor()
    cur.execute("SELECT confidence, valid_until, enrichment->>'source', tags, false_positive FROM iocs WHERE value=%s", (value,))
    return cur.fetchone()


def test_direct_feed_creates_indicators_with_provenance(client, db):
    r = _run(client, "feodo", {"min_confidence": 70}, {"feodo": FEODO})
    assert r["ok"] and r["added"] == 2 and r["skipped"] == 0
    conf, valid_until, source, tags, _ = _ioc(db, "45.9.148.10")
    assert conf == 92 and source == "Feodo Tracker" and "botnet-c2" in tags
    cur = db.cursor()
    cur.execute("SELECT obs_type, source_type, source_ref, confidence FROM entity_observations WHERE entity_ref='45.9.148.10'")
    assert cur.fetchall() == [("ingested", "feed", "https://feodotracker.abuse.ch/browse/host/45.9.148.10/", 92)]


def test_consensus_only_creates_what_independent_sources_agree_on(client, db):
    cfg = {"min_confidence": 70, "feeds": {"cins": {"enabled": True}, "et_compromised": {"enabled": True}, "blocklist_de": {"enabled": True}}}
    texts = {"cins": "91.92.109.7\n91.92.109.8\n91.92.109.99\n", "et_compromised": "91.92.109.7\n91.92.109.8\n", "blocklist_de": "91.92.109.7\n"}
    r = _run(client, "cins", cfg, texts)
    assert r["ok"] and r["below_floor"] >= 1
    assert _ioc(db, "91.92.109.7")[0] > 90                        # three independent lists agree
    assert 80 <= _ioc(db, "91.92.109.8")[0] <= 90                 # two agree
    assert _ioc(db, "91.92.109.99") is None                       # a single weak list: not created


def test_ipsum_is_not_double_counted_with_the_lists_it_aggregates(client, db):
    assert feeds.corroborated_confidence({"IPsum": 0.62, "CINS Army": 0.62, "Emerging Threats": 0.66}) == 62
    assert feeds.corroborated_confidence({"IPsum": 0.62, "Feodo Tracker": 0.92}) > 95          # a genuinely different source still counts
    cfg = {"min_confidence": 70, "feeds": {"ipsum": {"enabled": True}, "cins": {"enabled": True}, "et_compromised": {"enabled": True}}}
    texts = {"ipsum": "93.184.215.9\t7\n91.92.110.7\t3\n91.92.110.8\t4\n", "cins": "91.92.110.7\n", "et_compromised": "91.92.110.7\n"}
    r = _run(client, "ipsum", cfg, texts)
    assert r["ok"]
    assert _ioc(db, "93.184.215.9")[0] == 90                      # 7 lists: strong on its own
    assert _ioc(db, "91.92.110.8")[0] == 72                       # level 4
    assert _ioc(db, "91.92.110.7") is None                        # level 3 + the lists IPsum already contains: still only 62
    # an indicator already held (Feodo, 92) is corroborated by IPsum upward, never down
    _run(client, "feodo", {"min_confidence": 70}, {"feodo": FEODO})
    r = _run(client, "ipsum", cfg, {"ipsum": "45.9.148.10\t4\n", "cins": "", "et_compromised": ""})
    assert _ioc(db, "45.9.148.10")[0] >= 92
    cur = db.cursor()
    cur.execute("SELECT DISTINCT source FROM entity_observations WHERE entity_ref='45.9.148.10' ORDER BY 1")
    assert [x[0] for x in cur.fetchall()] == ["Feodo Tracker", "IPsum"]


def test_repair_corrects_double_counted_indicators_and_expires_the_ones_only_the_double_count_admitted(client, db):
    import main
    cur = db.cursor()
    import psycopg2.extras as ex
    for val, conf in (("91.92.111.1", 95), ("91.92.111.2", 95)):
        cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,enrichment,valid_until,created_at)
            VALUES (%s,'IPv4',%s,%s,'General','AMBER',%s,'d',ARRAY['feed'],%s,NOW()+INTERVAL '10 days',NOW())""",
                    (f"indicator--fix-{val}", val, val, conf, ex.Json({"source": "IPsum", "corroborated_by": ["CINS Army", "Emerging Threats", "IPsum"]})))
    conn = main.get_db_direct()
    try:
        for val in ("91.92.111.1", "91.92.111.2"):
            for src, c in (("IPsum", 62), ("CINS Army", 62), ("Emerging Threats", 66)):
                main.entities.record_observation(conn, "indicator", val, "ingested", src, "feed", confidence=c)
        # the second one is also confirmed by an independent source and must be kept alive
        main.entities.record_observation(conn, "indicator", "91.92.111.2", "sighting", "ThreatFox", "feed", confidence=85)
        conn.commit()
        res = feeds.repair_overcounted(conn, main.record_score)
    finally:
        conn.close()
    assert res["corrected"] >= 2
    cur.execute("SELECT confidence, valid_until > NOW() FROM iocs WHERE value='91.92.111.1'")
    assert cur.fetchone() == (62, False)          # corrected and expired: only the double count had admitted it
    cur.execute("SELECT confidence, valid_until > NOW() FROM iocs WHERE value='91.92.111.2'")
    conf, alive = cur.fetchone()
    assert conf > 90 and alive is True             # ThreatFox is a genuinely independent source
    cur.execute("DELETE FROM iocs WHERE value IN ('91.92.111.1', '91.92.111.2')")      # leave no rows for other tests


def test_sighting_refreshes_expiry_but_never_resurrects_false_positives(client, db):
    cur = db.cursor()
    cur.execute("UPDATE iocs SET valid_until = NOW() + INTERVAL '1 day' WHERE value='185.1.2.3'")
    cur.execute("UPDATE iocs SET false_positive = TRUE, valid_until = NOW() + INTERVAL '1 day' WHERE value='45.9.148.10'")
    r = _run(client, "feodo", {"min_confidence": 70}, {"feodo": FEODO})
    assert r["added"] == 0 and r["skipped"] == 2
    cur.execute("SELECT (valid_until > NOW() + INTERVAL '10 days') FROM iocs WHERE value='185.1.2.3'")
    assert cur.fetchone()[0] is True
    cur.execute("SELECT (valid_until < NOW() + INTERVAL '2 days'), confidence FROM iocs WHERE value='45.9.148.10'")
    still_short, conf = cur.fetchone()
    assert still_short is True                                     # false positive: expiry untouched
    cur.execute("UPDATE iocs SET false_positive = FALSE WHERE value='45.9.148.10'")


def test_a_failing_download_is_reported_not_raised(client):
    r = _run(client, "openphish", {}, {"openphish": ""})
    assert r["ok"] and r["added"] == 0
    import main
    conn = main.get_db_direct()
    try:
        res = asyncio.run(feeds.run_feed(conn, "otx", {}, ingest=main._ingest_feed_ioc, record_score=main.record_score, defang=main.defang,
                                         key=None, texts=None))
    finally:
        conn.close()
    assert res["ok"] is False and "error" in res              # no network / no key in the sandbox: reported


# ── admin API ────────────────────────────────────────────────────────────────
def test_catalog_and_config_are_admin_only(client, analyst, admin):
    assert client.get("/admin/connectors/catalog", headers=analyst).status_code == 403
    assert client.post("/admin/connectors/config", json={}, headers=analyst).status_code == 403
    assert client.post("/admin/connectors/feeds/feodo/run", headers=analyst).status_code == 403
    cat = client.get("/admin/connectors/catalog", headers=admin).json()
    ids = {f["id"] for f in cat["feeds"]}
    assert {"threatfox", "malwarebazaar", "urlhaus", "feodo", "ipsum", "otx", "openphish", "cins"} <= ids
    feodo = next(f for f in cat["feeds"] if f["id"] == "feodo")
    assert feodo["reliability"] == 92 and feodo["iocs"] >= 2 and feodo["enabled"] is False


def test_config_roundtrip_validation_and_settings_merge(client, admin):
    r = client.post("/admin/connectors/config", json={"min_confidence": 999, "feeds": {"feodo": {"enabled": True, "limit": 5}}}, headers=admin)
    assert r.status_code == 200
    cat = client.get("/admin/connectors/catalog", headers=admin).json()
    assert cat["min_confidence"] == 95
    f = next(x for x in cat["feeds"] if x["id"] == "feodo")
    assert f["enabled"] is True and f["limit"] == 50                # clamped
    assert client.post("/admin/connectors/config", json={"feeds": {"nope": {"enabled": True}}}, headers=admin).status_code == 400
    # saving the legacy abuse.ch settings must not wipe the feed configuration
    body = {"threatfox_enabled": True, "malwarebazaar_enabled": False, "urlhaus_enabled": False, "threatfox_days": 1,
            "malwarebazaar_limit": 100, "urlhaus_limit": 100, "schedule_hours": 6}
    assert client.post("/admin/connectors/settings", json=body, headers=admin).status_code == 200
    cat = client.get("/admin/connectors/catalog", headers=admin).json()
    assert next(x for x in cat["feeds"] if x["id"] == "feodo")["enabled"] is True
    assert next(x for x in cat["feeds"] if x["id"] == "threatfox")["enabled"] is True
    assert client.post("/admin/connectors/feeds/unknown/run", headers=admin).status_code == 404


# ── per-user API key indicators ──────────────────────────────────────────────
def test_key_status_is_reported_per_user_without_leaking_keys(client, analyst, analyst2):
    rows = {r["service"]: r for r in client.get("/users/me/api-keys", headers=analyst).json()}
    assert {"virustotal", "abuseipdb", "shodan", "groq", "nvd", "urlhaus", "otx"} <= set(rows)
    assert rows["virustotal"]["has_key"] is False and rows["virustotal"]["source"] in ("none", "platform")
    r = client.post("/users/me/api-keys/virustotal", json={"api_key": "vt-secret-key-1234567890"}, headers=analyst)
    assert r.status_code == 200
    mine = {r["service"]: r for r in client.get("/users/me/api-keys", headers=analyst).json()}
    assert mine["virustotal"]["has_key"] is True and mine["virustotal"]["source"] == "personal"
    assert "vt-secret-key-1234567890" not in json.dumps(mine) and mine["virustotal"]["masked"]
    other = {r["service"]: r for r in client.get("/users/me/api-keys", headers=analyst2).json()}
    assert other["virustotal"]["has_key"] is False                  # another user's key is not theirs
    assert client.post("/users/me/api-keys/urlhaus", json={"api_key": "abusech-key-123456"}, headers=analyst).status_code == 200
    assert client.delete("/users/me/api-keys/virustotal", headers=analyst).status_code == 200
    assert {r["service"]: r for r in client.get("/users/me/api-keys", headers=analyst).json()}["virustotal"]["has_key"] is False
    assert client.post("/users/me/api-keys/notaservice", json={"api_key": "x"}, headers=analyst).status_code == 400


def test_auto_enrichment_can_raise_confidence_but_never_lower_it(client, db, monkeypatch):
    import main
    _run(client, "feodo", {"min_confidence": 70}, {"feodo": FEODO.replace("45.9.148.10", "45.9.148.77")})
    cur = db.cursor()
    cur.execute("SELECT id, confidence FROM iocs WHERE value='45.9.148.77'")
    ioc_id, before = cur.fetchone()

    async def clean_looking(ioc_type, value, base, conn=None, **k):
        # a brand-new C2 that VirusTotal has not seen: 0 detections -> calc_confidence would say 30
        return {"virustotal": {"total": 70, "malicious": 0, "vt_score": 0}, "calculated_confidence": 30,
                "confidence_reasons": ["VirusTotal: no engines flagged (-confidence)"], "enriched_at": "2026-09-29T00:00:00+00:00"}

    async def fast_sleep(s): return None
    monkeypatch.setattr(main, "enrich", clean_looking)
    monkeypatch.setattr(main.asyncio, "sleep", fast_sleep)
    conn = main.get_db_direct()
    try:
        r = asyncio.run(main._auto_enrich(conn, [{"id": ioc_id, "type": "IPv4", "value": "45.9.148.77", "confidence": before}], 5))
    finally:
        conn.close()
    assert r["enriched"] == 1
    cur.execute("SELECT confidence, enrichment->'virustotal'->>'total' FROM iocs WHERE id=%s", (ioc_id,))
    assert cur.fetchone() == (before, "70")                       # confidence kept; the VT answer is stored for the analyst
    cur.execute("SELECT COUNT(*) FROM entity_observations WHERE entity_ref='45.9.148.77' AND obs_type='enrichment'")
    assert cur.fetchone()[0] == 1
