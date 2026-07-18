"""Tests for SamlSettings configuration."""

from typing import Any, cast

import pytest
from pydantic import ValidationError

from fastapi_auth.saml.settings import SamlSettings

_BASE: dict[str, Any] = dict(
    entity_id="urn:test:sp",
    base_url="https://sp.example",
    key_file="/tmp/sp.key",
    cert_file="/tmp/sp.crt",
    fixed_idp_entity_id="urn:test:idp",
    session_secret="s3cr3t",
)


def test_defaults_and_acs_url():
    s = SamlSettings(**_BASE)
    assert s.acs_path == "/saml/acs"
    assert s.acs_url == "https://sp.example/saml/acs"
    assert s.metadata_source == "direct"
    assert s.discovery_mode == "passthrough"
    assert s.want_assertions_signed is True


def test_acs_url_strips_trailing_slash():
    s = SamlSettings(**cast(dict[str, Any], {**_BASE, "base_url": "https://sp.example/"}))
    assert s.acs_url == "https://sp.example/saml/acs"


def test_missing_required_field_raises():
    incomplete = {k: v for k, v in _BASE.items() if k != "entity_id"}
    with pytest.raises(ValidationError):
        SamlSettings(**incomplete)


def test_env_prefix(monkeypatch):
    for k, v in _BASE.items():
        monkeypatch.setenv(f"SAML_{k.upper()}", v)
    s = SamlSettings()
    assert s.entity_id == "urn:test:sp"
