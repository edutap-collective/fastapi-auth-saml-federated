"""SamlEngine.idp_sso_url: the IdP's SingleSignOnService location from loaded metadata."""

from typing import Any

import pytest
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from tests.conftest import IDP_EID, SSO, build_signed_aggregate

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.settings import SamlSettings


def _settings(certs, **overrides: Any) -> SamlSettings:
    values: dict[str, Any] = dict(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
    )
    values.update(overrides)
    return SamlSettings(**values)


def test_defaults_to_the_fixed_idp_and_http_redirect(certs, idp_metadata_file):
    engine = SamlEngine(_settings(certs, idp_metadata_file=idp_metadata_file))
    assert engine.idp_sso_url() == SSO


def test_explicit_idp_and_binding(certs, idp_metadata_file):
    engine = SamlEngine(_settings(certs, idp_metadata_file=idp_metadata_file))
    assert engine.idp_sso_url(IDP_EID, binding=BINDING_HTTP_REDIRECT) == SSO


async def test_matches_the_authn_request_target(certs, idp_metadata_file):
    """The URL the AuthnRequest redirects to starts with exactly this location."""
    engine = SamlEngine(_settings(certs, idp_metadata_file=idp_metadata_file))
    _reqid, location = await engine.create_authn_request(relay_state="/app")
    assert location.startswith(engine.idp_sso_url() + "?")


def test_selects_one_idp_out_of_a_federation(tmp_path, certs):
    aggregate = build_signed_aggregate(tmp_path, certs, ["urn:test:idp-a", "urn:test:idp-b"])
    engine = SamlEngine(
        _settings(
            certs,
            metadata_source="aggregate",
            aggregate_file=aggregate,
            discovery_mode="embedded",
        )
    )
    assert engine.idp_sso_url("urn:test:idp-b") == SSO


def test_unknown_idp_raises_lookup_error(certs, idp_metadata_file):
    engine = SamlEngine(_settings(certs, idp_metadata_file=idp_metadata_file))
    with pytest.raises(LookupError, match="urn:test:unknown"):
        engine.idp_sso_url("urn:test:unknown")


def test_binding_not_offered_raises_lookup_error(certs, idp_metadata_file):
    """The test IdP publishes only HTTP-Redirect for single sign-on."""
    engine = SamlEngine(_settings(certs, idp_metadata_file=idp_metadata_file))
    with pytest.raises(LookupError, match="HTTP-POST"):
        engine.idp_sso_url(binding=BINDING_HTTP_POST)
