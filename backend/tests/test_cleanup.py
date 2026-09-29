"""The advisory-IOC cleanup removes junk, never indicators a threat feed ingested (they have no owner by design)."""
import uuid

import psycopg2.extras as ex
import pytest


def _ioc(db, value, typ="URL", source=None, tags=None, created_by=None):
    iid = f"indicator--{uuid.uuid4()}"
    db.cursor().execute(
        """INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,created_by,enrichment)
           VALUES (%s,%s,%s,%s,'General','AMBER',80,'cleanup test',%s,%s,%s)""",
        (iid, typ, value, value, tags or [], created_by, ex.Json({"source": source} if source else {})))
    return iid


def _exists(db, iid):
    cur = db.cursor()
    cur.execute("SELECT 1 FROM iocs WHERE id = %s", (iid,))
    return cur.fetchone() is not None


@pytest.fixture
def rows(db):
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE username = 'admin'")
    admin_id = cur.fetchone()[0]
    r = {
        # junk the cleanup exists for
        "advisory_link": _ioc(db, "https://nvd.nist.gov/vuln/detail/CVE-2099-1"),                      # trusted host, no source
        "auto_tagged": _ioc(db, "http://changelog.example/notes", tags=["auto-extracted"]),
        "orphan": _ioc(db, "http://orphan.example/a"),                                                 # no owner, no feed
        # what it must leave alone
        "threatfox_url": _ioc(db, "http://c2.example/gate.php", source="ThreatFox"),
        "threatfox_domain": _ioc(db, "c2-domain.example", typ="Domain", source="ThreatFox"),
        "urlhaus_url": _ioc(db, "http://dropper.example/x.exe", source="URLhaus", tags=["urlhaus", "connector"]),
        "feed_on_trusted_host": _ioc(db, "https://cve.org/abuse-of-a-trusted-host", source="OpenPhish"),
        "lookalike": _ioc(db, "https://nvd.nist.gov.evil.example/login", source="OpenPhish"),          # contains a trusted name, is not it
        "lookalike_no_feed": _ioc(db, "https://cve.org.evil.example/login", created_by=admin_id),        # owned by an analyst
        "analyst_url": _ioc(db, "http://analyst-added.example/p", created_by=admin_id),
        "ip_no_owner": _ioc(db, "203.0.113.77", typ="IPv4", source="Feodo Tracker"),
    }
    yield r
    for iid in r.values():
        db.cursor().execute("DELETE FROM iocs WHERE id = %s", (iid,))


def test_cleanup_removes_junk_but_keeps_everything_a_feed_brought_in(client, admin, db, rows):
    preview = client.post("/admin/cleanup-advisory-iocs?dry_run=true", headers=admin).json()
    assert preview["dry_run"] is True and preview["would_remove"] >= 3
    assert all(_exists(db, i) for i in rows.values())                     # a preview deletes nothing

    r = client.post("/admin/cleanup-advisory-iocs", headers=admin)
    assert r.status_code == 200 and r.json()["removed"] >= 3
    gone = {k for k, i in rows.items() if not _exists(db, i)}
    assert gone == {"advisory_link", "auto_tagged", "orphan"}, gone


def test_the_trusted_domain_rule_matches_hosts_not_substrings():
    import main
    assert main._on_trusted_domain("https://nvd.nist.gov/vuln/detail/CVE-1")
    assert main._on_trusted_domain("https://www.cisa.gov/x")                 # subdomain of a trusted domain
    assert main._on_trusted_domain("cisa.gov")
    assert not main._on_trusted_domain("https://cisa.gov.evil.example/x")
    assert not main._on_trusted_domain("http://not-cisa.gov/x")
    assert not main._on_trusted_domain("")
