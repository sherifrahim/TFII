"""Phase 2 intelligence core: search, entities, relationships, provenance, workspace bridge, authz."""
import pytest


def get(client, path, hdr, **params):
    return client.get(path, params=params, headers=hdr)


# ── authn / authz ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path", [
    "/v2/search?q=abc", "/v2/entity?kind=cve&ref=CVE-2099-0001", "/v2/iocs", "/v2/iocs/facets", "/v2/intel-wall",
    "/v2/entity/graph?kind=cve&ref=CVE-2099-0001", "/v2/relationship-types",
])
def test_endpoints_require_authentication(client, path):
    assert client.get(path).status_code == 401


def test_explorer_role_cannot_read_the_indicator_database(client, explorer, data):
    assert get(client, "/v2/entity", explorer, kind="indicator", ref="1.2.3.4").status_code == 403
    assert get(client, "/v2/iocs", explorer).status_code == 403
    assert get(client, "/v2/entity/raw", explorer, kind="indicator", ref="1.2.3.4").status_code == 403


def test_explorer_search_is_limited_not_leaky(client, explorer, data):
    r = get(client, "/v2/search", explorer, q="evil.example")
    assert r.status_code == 200
    assert r.json()["limited"] is True and r.json()["total"] == 0


def test_status_and_relationship_writes_need_full_access(client, explorer, data):
    assert client.post("/v2/entity/status", json={"ref": "1.2.3.4", "status": "confirmed"}, headers=explorer).status_code == 403
    assert client.post("/v2/relationships", json={"src_kind": "cve", "src_ref": "CVE-2099-0001", "rel_type": "related_to",
                                                   "dst_kind": "actor", "dst_ref": "X"}, headers=explorer).status_code == 403


# ── global search ────────────────────────────────────────────────────────────
def test_search_exact_indicator_is_top_hit(client, analyst, data):
    r = get(client, "/v2/search", analyst, q="1.2.3.4").json()
    assert r["detected_type"] == "IPv4"
    assert r["top"]["kind"] == "indicator" and r["top"]["title"] == "1.2.3.4" and r["top"]["score"] == 100


def test_search_accepts_defanged_input(client, analyst, data):
    r = get(client, "/v2/search", analyst, q="hxxp://evil[.]example/payload.bin").json()
    assert r["normalized"] == "http://evil.example/payload.bin"
    assert r["top"]["kind"] == "indicator" and r["top"]["type"] == "URL"


def test_search_domain_finds_urls_hosted_on_it(client, analyst, data):
    r = get(client, "/v2/search", analyst, q="evil.example").json()
    titles = [h["title"] for h in r["groups"]["indicator"]["hits"]]
    assert "evil.example" in titles and "http://evil.example/payload.bin" in titles


def test_search_is_grouped_by_kind_and_covers_every_entity_type(client, analyst, data):
    for q, kind in [("CVE-2099-0001", "cve"), ("WidgetOS", "software"), ("LummaTest", "malware"),
                    ("APT-Test", "actor"), ("Tidewater", "campaign")]:
        r = get(client, "/v2/search", analyst, q=q).json()
        assert kind in r["groups"], (q, list(r["groups"]))


def test_search_escapes_like_wildcards(client, analyst, data):
    r = get(client, "/v2/search", analyst, q="%%%").json()
    assert r["total"] == 0
    assert get(client, "/v2/search", analyst, q="'; DROP TABLE iocs;--").status_code == 200


def test_search_kinds_filter(client, analyst, data):
    r = get(client, "/v2/search", analyst, q="evil", kinds="indicator").json()
    assert set(r["groups"]) == {"indicator"}


# ── entity retrieval ─────────────────────────────────────────────────────────
def test_indicator_envelope_by_value_and_by_id(client, analyst, data):
    by_value = get(client, "/v2/entity", analyst, kind="indicator", ref="1.2.3.4").json()
    by_id = get(client, "/v2/entity", analyst, kind="indicator", ref=data["ip"]).json()
    assert by_value["entity"]["id"] == by_id["entity"]["id"] == data["ip"]
    e = by_value["entity"]
    assert e["status"] == "active" and e["severity"] == "critical" and e["tracked"] is True
    assert by_value["overview"]["ioc"]["id"] == data["ip"]
    assert set(by_value["counts"]) == {"relationships", "timeline", "observations", "sources", "investigations"}


def test_unknown_indicator_is_untracked_not_404(client, analyst, data):
    r = get(client, "/v2/entity", analyst, kind="indicator", ref="9.9.9.9")
    assert r.status_code == 200
    e = r.json()["entity"]
    assert e["tracked"] is False and e["status"] == "untracked"
    assert r.json()["overview"] is None


def test_unknown_malware_and_bad_kind(client, analyst, data):
    assert get(client, "/v2/entity", analyst, kind="malware", ref="nope-family").status_code == 404
    assert get(client, "/v2/entity", analyst, kind="spaceship", ref="x").status_code == 400


@pytest.mark.parametrize("kind,ref_key,expect", [
    ("campaign", "campaign", "Op Tidewater"), ("software", "asset", "WidgetOS"),
])
def test_headers_for_id_based_kinds(client, analyst, data, kind, ref_key, expect):
    e = get(client, "/v2/entity", analyst, kind=kind, ref=data[ref_key]).json()["entity"]
    assert e["title"] == expect


def test_actor_and_malware_are_derived_from_real_rows(client, analyst, data):
    a = get(client, "/v2/entity", analyst, kind="actor", ref="apt-test").json()["entity"]
    assert a["title"] == "APT-Test" and a["campaign_count"] == 1
    m = get(client, "/v2/entity", analyst, kind="malware", ref="lummatest").json()["entity"]
    assert m["indicator_count"] == 2


# ── IOC detail & statuses ────────────────────────────────────────────────────
def test_status_model_derived_lifecycle(client, analyst, data):
    exp = get(client, "/v2/entity", analyst, kind="indicator", ref="old.example").json()["entity"]
    assert exp["status"] == "expired"
    low = get(client, "/v2/entity", analyst, kind="indicator", ref="meh.example").json()["entity"]
    assert low["status"] == "active" and low["severity"] == "low"


def test_ioc_list_filters_and_facets(client, analyst, data):
    r = get(client, "/v2/iocs", analyst, limit=100).json()
    values = {i["value"] for i in r["items"]}
    assert "old.example" not in values, "default status=live must hide expired"
    r = get(client, "/v2/iocs", analyst, status="expired").json()
    assert [i["value"] for i in r["items"]] == ["old.example"]
    r = get(client, "/v2/iocs", analyst, severity="critical").json()
    assert {i["value"] for i in r["items"]} >= {"1.2.3.4", "a" * 64}
    r = get(client, "/v2/iocs", analyst, source="URLhaus").json()
    assert [i["type"] for i in r["items"]] == ["URL"]
    f = get(client, "/v2/iocs/facets", analyst, type="ip").json()
    assert set(f) == {"types", "sources", "status", "severity"}
    assert get(client, "/v2/iocs/filter-options", analyst).status_code == 200


def test_ioc_list_search_treats_wildcards_literally(client, analyst, data):
    assert get(client, "/v2/iocs", analyst, q="%").json()["total"] == 0
    assert get(client, "/v2/iocs", analyst, q="evil[.]example", status="all").json()["total"] >= 2


def test_set_status_records_provenance_and_timeline(client, analyst, data):
    r = client.post("/v2/entity/status", json={"ref": "meh.example", "status": "suspicious", "reason": "seen in phish"}, headers=analyst)
    assert r.status_code == 200
    env = get(client, "/v2/entity", analyst, kind="indicator", ref="meh.example").json()
    assert env["entity"]["status"] == "suspicious"
    assert any(o["type"] == "status_change" and "seen in phish" in o["summary"] for o in env["observations"])
    assert any(t["type"] == "status" for t in env["timeline"])
    bad = client.post("/v2/entity/status", json={"ref": "meh.example", "status": "wat"}, headers=analyst)
    assert bad.status_code == 400
    assert client.post("/v2/entity/status", json={"ref": "9.9.9.9", "status": "confirmed"}, headers=analyst).status_code == 404


def test_only_owner_or_admin_may_flag_and_unflag_false_positive(client, analyst, analyst2, admin, data):
    # the hash was created by a connector (no author): a non-admin cannot flag it
    body = {"ref": "a" * 64, "status": "false_positive", "reason": "x"}
    assert client.post("/v2/entity/status", json=body, headers=analyst).status_code == 403
    assert client.post("/v2/entity/status", json=body, headers=admin).status_code == 200
    assert client.post("/v2/entity/status", json={"ref": "a" * 64, "status": "active"}, headers=analyst2).status_code == 403
    assert client.post("/v2/entity/status", json={"ref": "a" * 64, "status": "active"}, headers=admin).status_code == 200


# ── relationships ────────────────────────────────────────────────────────────
def groups(env):
    return {(g["rel"], g["direction"]): g for g in env["relationships"]["groups"]}


def test_domain_hosts_url_is_derived_from_the_url_hostname(client, analyst, data):
    g = groups(get(client, "/v2/entity", analyst, kind="indicator", ref="evil.example").json())
    hosted = [i["value"] for i in g[("hosts", "out")]["items"]]
    assert hosted == ["http://evil.example/payload.bin"]
    assert g[("hosts", "out")]["items"][0]["origin"] == "derived"


def test_url_points_back_to_host_and_malware(client, analyst, data):
    g = groups(get(client, "/v2/entity", analyst, kind="indicator", ref="http://evil.example/payload.bin").json())
    assert g[("hosts", "in")]["items"][0]["ref"] == "evil.example"
    assert g[("associated_with", "out")]["items"][0]["ref"] == "LummaTest"


def test_no_relationship_is_invented(client, analyst, data):
    env = get(client, "/v2/entity", analyst, kind="indicator", ref="meh.example").json()
    # the only edge a bare manual IOC has is where it came from — no hosts, resolutions or family links
    assert {g["rel"] for g in env["relationships"]["groups"]} <= {"observed_in"}


def test_malware_actor_campaign_cve_software_relationships(client, analyst, data):
    m = groups(get(client, "/v2/entity", analyst, kind="malware", ref="LummaTest").json())
    assert {i["ref"] for i in m[("associated_with", "in")]["items"]} == {"http://evil.example/payload.bin", "a" * 64}
    a = groups(get(client, "/v2/entity", analyst, kind="actor", ref="APT-Test").json())
    assert a[("operates_campaign", "out")]["items"][0]["ref"] == data["campaign"]
    c = groups(get(client, "/v2/entity", analyst, kind="campaign", ref=data["campaign"]).json())
    assert {i["ref"] for i in c[("uses", "out")]["items"]} == {"1.2.3.4", "evil.example"}
    v = groups(get(client, "/v2/entity", analyst, kind="cve", ref="CVE-2099-0001").json())
    assert v[("affects", "out")]["items"][0]["ref"] == data["asset"]
    s = groups(get(client, "/v2/entity", analyst, kind="software", ref=data["asset"]).json())
    assert {i["ref"] for i in s[("affects", "in")]["items"]} == {"CVE-2099-0001", "CVE-2099-0002"}


def test_stored_relationship_lifecycle_with_provenance_and_ownership(client, analyst, analyst2, admin, data):
    body = {"src_kind": "indicator", "src_ref": "meh.example", "rel_type": "resolves_to", "dst_kind": "indicator", "dst_ref": "5.6.7.8",
            "note": "passive DNS", "source_ref": "https://pdns.example/x"}
    r = client.post("/v2/relationships", json=body, headers=analyst)
    assert r.status_code == 201
    rid = r.json()["id"]
    assert client.post("/v2/relationships", json=body, headers=analyst).status_code == 409
    env = get(client, "/v2/entity", analyst, kind="indicator", ref="meh.example").json()
    it = groups(env)[("resolves_to", "out")]["items"][0]
    assert it["ref"] == "5.6.7.8" and it["origin"] == "stored" and it["source"] == "analyst:analyst1" and it["evidence"] == "passive DNS"
    # the other end sees it as an incoming edge
    back = groups(get(client, "/v2/entity", analyst, kind="indicator", ref="5.6.7.8").json())
    assert back[("resolves_to", "in")]["items"][0]["ref"] == "meh.example"
    # only the author or an admin may remove it
    assert client.delete(f"/v2/relationships/{rid}", headers=analyst2).status_code == 403
    assert client.delete(f"/v2/relationships/{rid}", headers=analyst).status_code == 200


@pytest.mark.parametrize("body", [
    {"src_kind": "indicator", "src_ref": "a.example", "rel_type": "nope", "dst_kind": "indicator", "dst_ref": "b.example"},
    {"src_kind": "spaceship", "src_ref": "a", "rel_type": "related_to", "dst_kind": "indicator", "dst_ref": "b.example"},
    {"src_kind": "indicator", "src_ref": "a.example", "rel_type": "related_to", "dst_kind": "indicator", "dst_ref": "A.EXAMPLE"},
])
def test_relationship_validation(client, analyst, body):
    assert client.post("/v2/relationships", json=body, headers=analyst).status_code == 400


def test_entity_graph_is_drawn_from_the_same_relationships(client, analyst, data):
    g = get(client, "/v2/entity/graph", analyst, kind="campaign", ref=data["campaign"]).json()
    ids = {n["id"] for n in g["nodes"]}
    assert g["center"] in ids and len(g["nodes"]) >= 4
    for e in g["edges"]:
        assert e["source"] in ids and e["target"] in ids


# ── CVE & software detail ────────────────────────────────────────────────────
def test_cve_detail_uses_only_stored_facts(client, analyst, data):
    env = get(client, "/v2/entity", analyst, kind="cve", ref="cve-2099-0001").json()
    o = env["overview"]
    assert o["cvss"]["score"] == 9.8 and o["kev"]["listed"] is True
    assert o["software"][0]["name"] == "WidgetOS" and o["software"][0]["affected_versions"] == "< 4.3"
    assert [i["ref"] if "ref" in i else i["value"] for i in o["linked_iocs"]] == ["1.2.3.4"]
    urls = [r["url"] for r in o["references"]]
    assert urls == ["https://acme.example/advisory/1"], "javascript: references must be dropped"
    second = get(client, "/v2/entity", analyst, kind="cve", ref="CVE-2099-0002").json()["overview"]
    assert second["kev"]["listed"] is False


def test_untracked_cve_has_no_overview(client, analyst, data):
    env = get(client, "/v2/entity", analyst, kind="cve", ref="CVE-2000-1").json()
    assert env["entity"]["tracked"] is False and env["overview"] is None


def test_software_detail_and_timeline_dates_are_real(client, analyst, data):
    env = get(client, "/v2/entity", analyst, kind="software", ref=data["asset"]).json()
    e = env["entity"]
    assert e["cve_count"] == 2 and e["kev_count"] == 1 and e["unpatched"] == 1
    assert any(t["type"] == "kev" and t["ts"].startswith("2099-01-05") for t in env["timeline"])
    assert all(t["ts"] for t in env["timeline"])
    lite = get(client, f"/v2/software/{data['asset']}", analyst)
    assert lite.status_code == 200
    assert get(client, "/v2/cve/summary", analyst).json()["kev"] >= 1


# ── provenance ───────────────────────────────────────────────────────────────
def test_legacy_rows_get_reconstructed_provenance_flagged_derived(client, analyst, data):
    env = get(client, "/v2/entity", analyst, kind="indicator", ref="a" * 64).json()
    ingest = [o for o in env["observations"] if o["type"] == "ingested"]
    assert ingest and ingest[0]["derived"] is True and ingest[0]["source"] == "MalwareBazaar"
    assert "MalwareBazaar" in [s["source"] for s in env["sources"]]
    assert any("MalwareBazaar" in line for line in env["rationale"])


def test_feed_ingestion_writes_an_observation_and_deduplicates(client, db, data):
    import main
    conn = main.get_db_direct()
    cur = conn.cursor()
    kw = dict(type_="Domain", value="feed-new.example", defanged="feed-new[.]example", tlp="AMBER", confidence=70,
              description="ThreatFox: X", tags=["threatfox"], enrichment={"source": "ThreatFox", "malware_family": "LummaTest"},
              valid_days=30, source="ThreatFox", source_ref="https://threatfox.abuse.ch/ioc/1/")
    first = main._ingest_feed_ioc(cur, conn, **kw)
    again = main._ingest_feed_ioc(cur, conn, **kw)
    assert first[0] is True and first[1]
    assert again[0] is False and again[1] == first[1]                # a sighting of the same row, not a duplicate
    conn.commit()
    c2 = db.cursor()
    c2.execute("SELECT COUNT(*) FROM iocs WHERE value='feed-new.example'")
    assert c2.fetchone()[0] == 1
    c2.execute("SELECT obs_type FROM entity_observations WHERE entity_ref='feed-new.example' ORDER BY id")
    assert [r[0] for r in c2.fetchall()] == ["ingested", "sighting"]
    conn.close()


def test_observations_and_timeline_only_contain_timestamped_events(client, analyst, data):
    env = get(client, "/v2/entity", analyst, kind="indicator", ref="1.2.3.4").json()
    assert all(t["ts"] for t in env["timeline"])
    assert any(t["type"] == "first_seen" for t in env["timeline"])


# ── workspace ↔ entity ───────────────────────────────────────────────────────
def test_workspace_round_trip_preserves_reason_and_context(client, analyst, data):
    inv = client.post("/v2/investigations", json={"name": "Tidewater hunt", "severity": "high"}, headers=analyst).json()
    iid = inv["id"]
    add = client.post(f"/v2/investigations/{iid}/entities", json={"kind": "indicator", "ref": "evil.example",
                                                                  "reason": "C2 domain from the phishing kit"}, headers=analyst)
    assert add.status_code == 201
    assert client.post(f"/v2/investigations/{iid}/entities", json={"kind": "indicator", "ref": "evil.example"}, headers=analyst).status_code == 409
    for kind, ref in [("cve", "CVE-2099-0001"), ("malware", "LummaTest"), ("actor", "APT-Test"), ("campaign", data["campaign"]),
                      ("software", data["asset"]), ("indicator", "203.0.113.9")]:
        assert client.post(f"/v2/investigations/{iid}/entities", json={"kind": kind, "ref": ref, "reason": "r"}, headers=analyst).status_code == 201, kind

    # entity page opened from the investigation: membership + reason + flagged relationships
    env = get(client, "/v2/entity", analyst, kind="indicator", ref="evil.example", inv=iid).json()
    assert env["membership"]["member"] is True and env["membership"]["reason"] == "C2 domain from the phishing kit"
    assert env["investigations"][0]["id"] == iid
    assert any(g["rel"] == "appears_in" for g in env["relationships"]["groups"])
    assert any(t["type"] == "investigation" and "phishing kit" in (t["detail"] or "") for t in env["timeline"])
    camp = get(client, "/v2/entity", analyst, kind="campaign", ref=data["campaign"], inv=iid).json()
    uses = groups(camp)[("uses", "out")]["items"]
    assert {i["ref"]: i["in_investigation"] for i in uses}["evil.example"] is True
    assert {i["ref"]: i["in_investigation"] for i in uses}["1.2.3.4"] is False

    # and back: the investigation lists them with the reason
    detail = client.get(f"/v2/investigations/{iid}", headers=analyst).json()
    item = next(i for i in detail["items"] if i["value"] == "evil.example")
    assert item["reason"] == "C2 domain from the phishing kit"
    r = client.patch(f"/v2/investigations/{iid}/items/{item['id']}", json={"reason": "updated"}, headers=analyst)
    assert r.status_code == 200
    assert get(client, "/v2/entity/membership", analyst, kind="indicator", ref="evil.example", inv=iid).json()["reason"] == "updated"

    # investigation entity relationships feed the graph
    g = get(client, "/v2/entity/graph", analyst, kind="investigation", ref=iid).json()
    assert len(g["nodes"]) >= 6


def test_workspace_errors(client, analyst, data):
    assert client.post("/v2/investigations/inv-missing/entities", json={"kind": "cve", "ref": "CVE-2099-0001"}, headers=analyst).status_code == 404
    inv = client.post("/v2/investigations", json={"name": "x"}, headers=analyst).json()["id"]
    assert client.post(f"/v2/investigations/{inv}/entities", json={"kind": "malware", "ref": "no-such"}, headers=analyst).status_code == 404
    assert client.post(f"/v2/investigations/{inv}/entities", json={"kind": "investigation", "ref": inv}, headers=analyst).status_code == 400


# ── intel wall ───────────────────────────────────────────────────────────────
def test_intel_wall_links_only_to_known_entities(client, analyst, data):
    import main

    async def fake_rss(*a, **k):
        return [{"title": "CVE-2099-0001 exploited by APT-Test against WidgetOS", "summary": "C2 at 1.2.3.4 and evil.example",
                 "url": "javascript:alert(1)", "source": "Test", "date": "2099-01-01"}]

    async def fake_cve(*a, **k):
        return {"ok": True, "items": [], "error": None}

    main.INTEL_DEPS.fetch_rss, main.INTEL_DEPS.fetch_cve_rss = fake_rss, fake_cve
    r = client.get("/v2/intel-wall?refresh=true", headers=analyst).json()
    it = next(i for i in r["items"] if "APT-Test" in i["title"])
    assert it["url"] is None, "javascript: feed links must never be emitted"
    found = {(e["kind"], e["label"]) for e in it["entities"]}
    assert {("cve", "CVE-2099-0001"), ("actor", "APT-Test"), ("software", "WidgetOS"), ("indicator", "1.2.3.4")} <= found
    assert "evil.example" not in {label for kind, label in found if kind != "indicator"}
    assert it["affects"] and it["affects"][0]["asset_name"] == "WidgetOS"
    filtered = client.get("/v2/intel-wall?entity_kind=actor&entity_ref=APT-Test", headers=analyst).json()
    assert filtered["items"] and all(any(e["kind"] == "actor" for e in i["entities"]) for i in filtered["items"])
    # explorers get CVE links only — no view into the analyst's entity data
    ex = client.get("/v2/intel-wall", headers=data_explorer(client)).json()
    assert {e["kind"] for i in ex["items"] for e in i["entities"]} <= {"cve"}


def data_explorer(client):
    import secrets
    r = client.post("/auth/signup", json={"username": "explorer_wall", "password": "Exp-" + secrets.token_hex(8)})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ── provenance from the v1 write paths ───────────────────────────────────────
def test_manual_add_and_fp_toggle_leave_provenance(client, analyst, db, monkeypatch):
    import main

    async def no_enrich(ioc_type, value, base, conn=None, **k):
        return {"calculated_confidence": base, "confidence_reasons": ["test"], "virustotal": {"total": 70, "malicious": 5}}
    monkeypatch.setattr(main, "enrich", no_enrich)

    r = client.post("/iocs", json={"type": "Domain", "value": "prov-manual.example", "confidence": 70, "tlp": "AMBER",
                                   "industry": "General", "description": "d", "tags": [], "valid_days": 30}, headers=analyst)
    assert r.status_code == 201, r.text
    env = get(client, "/v2/entity", analyst, kind="indicator", ref="prov-manual.example").json()
    types = {(o["type"], o["source"]) for o in env["observations"]}
    assert ("ingested", "analyst:analyst1") in types and ("enrichment", "VirusTotal") in types
    assert all(not o["derived"] for o in env["observations"] if o["type"] in ("ingested", "enrichment"))

    iid = env["entity"]["id"]
    assert client.patch(f"/iocs/{iid}/false-positive", json={"false_positive": True, "reason": "benign CDN"}, headers=analyst).status_code == 200
    env = get(client, "/v2/entity", analyst, kind="indicator", ref="prov-manual.example").json()
    assert any(o["type"] == "status_change" and "benign CDN" in o["summary"] for o in env["observations"])
    assert env["entity"]["status"] == "false_positive"
