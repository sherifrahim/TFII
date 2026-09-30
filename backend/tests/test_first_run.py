"""First-run admin: no published default password."""
import re


def test_a_random_password_is_generated_when_none_is_configured(monkeypatch):
    import main
    monkeypatch.delenv("ADMIN_INITIAL_PASSWORD", raising=False)
    a, gen_a = main.initial_admin_password()
    b, gen_b = main.initial_admin_password()
    assert gen_a and gen_b and a != b and len(a) >= 16 and re.fullmatch(r"[A-Za-z0-9_-]+", a)
    assert "TFeed@99" not in (a, b)


def test_a_configured_password_is_used_as_is(monkeypatch):
    import main
    monkeypatch.setenv("ADMIN_INITIAL_PASSWORD", "chosen-by-the-operator-1")
    assert main.initial_admin_password() == ("chosen-by-the-operator-1", False)


def test_placeholders_and_short_passwords_are_not_used(monkeypatch):
    import main
    for bad in ("replace_with_initial_admin_password", "REPLACE_WITH_ANYTHING", "short", "  ", "123456789"):
        monkeypatch.setenv("ADMIN_INITIAL_PASSWORD", bad)
        pw, generated = main.initial_admin_password()
        assert generated and pw != bad and len(pw) >= 16, bad


def test_the_env_template_and_setup_script_carry_no_password():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    assert "ADMIN_INITIAL_PASSWORD=\n" in (root / ".env.example").read_text()      # blank: nothing to copy by accident
    assert "ADMIN_INITIAL_PASSWORD=${ADMIN_PW}" in (root / "scripts/docker-setup.sh").read_text()


def test_the_old_default_password_is_gone_from_the_code():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    for f in ("backend/main.py", "scripts/docker-setup.sh", "README.md"):
        assert "TFeed@99" not in (root / f).read_text(), f
