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
