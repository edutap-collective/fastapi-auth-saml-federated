"""Mount-path drives all absolute SP URLs consistently."""

from typing import Any, cast

from fastapi_auth.saml.settings import SamlSettings

_BASE: dict[str, Any] = dict(
    entity_id="urn:test:sp",
    base_url="https://sp.example",
    key_file="/tmp/k",
    cert_file="/tmp/c",
    fixed_idp_entity_id="urn:test:idp",
    session_secret="x",
)


def test_default_mount_path_reproduces_saml_prefix():
    s = SamlSettings(**_BASE)
    assert s.mount_path == "/saml"
    assert s.acs_url == "https://sp.example/saml/acs"
    assert s.absolute_url("/disco") == "https://sp.example/saml/disco"
    assert s.absolute_url("/slo/return") == "https://sp.example/saml/slo/return"
    assert s.wayf_login_path == "/saml/login"


def test_custom_mount_path_propagates():
    s = SamlSettings(**cast(dict[str, Any], {**_BASE, "mount_path": "/auth/saml"}))
    assert s.acs_url == "https://sp.example/auth/saml/acs"
    assert s.absolute_url("/disco") == "https://sp.example/auth/saml/disco"
    assert s.wayf_login_path == "/auth/saml/login"
