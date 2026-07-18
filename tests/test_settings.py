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


def test_profile_defaults():
    s = SamlSettings(**_BASE)
    assert s.identifier == "subject_id"
    assert s.identifier_fallback == ["pairwise_id", "eppn"]
    assert s.required_attributes == []
    assert s.entity_categories == []
    assert s.allowed_redirect_hosts == []


def test_encryption_files_default_to_signing_pair():
    s = SamlSettings(**_BASE)
    assert s.enc_key_file == s.key_file
    assert s.enc_cert_file == s.cert_file


def test_encryption_files_override():
    s = SamlSettings(
        **cast(
            dict[str, Any],
            {
                **_BASE,
                "encryption_key_file": "/tmp/enc.key",
                "encryption_cert_file": "/tmp/enc.crt",
            },
        )
    )
    assert s.enc_key_file == "/tmp/enc.key"
    assert s.enc_cert_file == "/tmp/enc.crt"


def test_profile_lists_from_values():
    s = SamlSettings(
        **cast(
            dict[str, Any],
            {
                **_BASE,
                "required_attributes": ["eduPersonPrincipalName", "mail"],
                "entity_categories": ["code-of-conduct"],
            },
        )
    )
    assert s.required_attributes == ["eduPersonPrincipalName", "mail"]
    assert s.entity_categories == ["code-of-conduct"]


def test_backend_store_defaults():
    s = SamlSettings(**_BASE)
    assert s.backend == "cookie"
    assert s.store == "memory"
    assert s.jwt_alg == "HS256"


def test_jwt_signing_secret_defaults_to_session_secret():
    s = SamlSettings(**cast(dict[str, Any], {**_BASE, "session_secret": "x" * 40}))
    assert s.jwt_signing_secret == "x" * 40


def test_jwt_backend_requires_strong_secret():
    with pytest.raises(ValidationError, match="32"):
        SamlSettings(**cast(dict[str, Any], {**_BASE, "backend": "jwt", "session_secret": "short"}))


def test_jwt_backend_accepts_strong_secret():
    s = SamlSettings(**cast(dict[str, Any], {**_BASE, "backend": "jwt", "session_secret": "s" * 32}))
    assert s.backend == "jwt"
