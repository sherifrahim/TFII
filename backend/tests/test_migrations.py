import migrations


def test_migrations_are_idempotent_and_recorded(client, db):
    import main
    assert migrations.run_migrations(main.get_db_direct) == []          # already applied at startup
    cur = db.cursor()
    cur.execute("SELECT version, name FROM schema_migrations ORDER BY version")
    assert [v for v, _ in cur.fetchall()] == [m[0] for m in migrations.MIGRATIONS]


def test_a_failing_required_step_does_not_crash_and_is_retried(client, db):
    import main
    bad = [(999, "broken", [migrations.R("SELECT * FROM table_that_does_not_exist")])]
    assert migrations.run_migrations(main.get_db_direct, bad) == []
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = 999")
    assert cur.fetchone()[0] == 0, "a failed migration must not be recorded as applied"


def test_optional_steps_may_fail_without_blocking(client, db):
    import main
    ok = [(998, "optional", [migrations.O("CREATE EXTENSION does_not_exist_ext"), migrations.R("SELECT 1")])]
    assert migrations.run_migrations(main.get_db_direct, ok) == [998]
    db.cursor().execute("DELETE FROM schema_migrations WHERE version = 998")


def test_index_on_a_table_the_role_does_not_own_does_not_block_later_migrations(client, db):
    """Production regression: 'must be owner of table cve_findings' on an index stopped migration 1,
    so migration 2 (analyst_status, entity tables) never ran and the v2 pages returned 500."""
    import main
    cur = db.cursor()
    # simulate an unowned table: an index statement that errors the way a permission failure does
    steps = [(997, "unowned_index", [migrations.O("CREATE INDEX idx_nope ON table_owned_by_someone_else (x)"),
                                     migrations.R("CREATE TABLE IF NOT EXISTS mig_probe (id INT)")]),
             (996, "after", [migrations.R("CREATE TABLE IF NOT EXISTS mig_probe2 (id INT)")])]
    assert migrations.run_migrations(main.get_db_direct, steps) == [997, 996]
    for t in ("mig_probe", "mig_probe2"):
        cur.execute(f"DROP TABLE {t}")
    cur.execute("DELETE FROM schema_migrations WHERE version IN (996, 997)")


def test_every_index_statement_is_optional():
    for version, name, stmts in migrations.MIGRATIONS:
        for sql, optional in stmts:
            if sql.lstrip().upper().startswith(("CREATE INDEX", "CREATE UNIQUE INDEX")):
                assert optional, f"migration {version}: index must be optional -> {sql[:70]}"
