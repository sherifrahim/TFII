"""Stored API keys must be saveable even when ENCRYPTION_KEY is missing or not a valid Fernet key."""
import base64
import os

import pytest


@pytest.fixture
def main_module(client):
    import main
    yield main


@pytest.mark.parametrize("value", ["", "replace_with_fernet_key", "not base64 at all!", "dG9vc2hvcnQ="])
def test_a_bad_or_missing_encryption_key_does_not_break_saving_keys(main_module, monkeypatch, value):
    monkeypatch.setattr(main_module, "ENCRYPTION_KEY", value)
    token = main_module.encrypt_key("gsk_secret_value")
    assert token != "gsk_secret_value" and "gsk_secret_value" not in token
    assert main_module.decrypt_key(token) == "gsk_secret_value"


def test_a_valid_fernet_key_is_used(main_module, monkeypatch):
    monkeypatch.setattr(main_module, "ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    assert main_module.decrypt_key(main_module.encrypt_key("abc")) == "abc"
