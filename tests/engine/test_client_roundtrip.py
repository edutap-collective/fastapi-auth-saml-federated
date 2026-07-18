"""End-to-end engine test: SP AuthnRequest -> in-memory IdP -> SP validates."""

import pytest
from tests.conftest import IDP_EID, SSO, mint_response

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.engine.errors import SamlResponseError
from fastapi_auth.saml.settings import SamlSettings


def _settings(certs, idp_metadata_file) -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
    )


async def test_create_authn_request_returns_redirect(certs, idp_metadata_file):
    engine = SamlEngine(_settings(certs, idp_metadata_file))
    reqid, location = await engine.create_authn_request(relay_state="/app")
    assert reqid
    assert location.startswith(SSO)


async def test_roundtrip_yields_federated_identity(certs, idp_metadata_file, make_idp):
    settings = _settings(certs, idp_metadata_file)
    engine = SamlEngine(settings)
    reqid, _ = await engine.create_authn_request(relay_state="/app")

    idp = make_idp(engine.sp_metadata())
    saml_response = mint_response(
        idp,
        reqid,
        ava={
            "eduPersonPrincipalName": ["u123@test.de"],
            "mail": ["u@test.de"],
            "eduPersonScopedAffiliation": ["staff@test.de"],
        },
    )

    identity, in_response_to = await engine.parse_response(
        saml_response, outstanding={reqid: "/app"}
    )
    assert identity.eppn == "u123@test.de"
    assert identity.mail == ["u@test.de"]
    assert identity.scoped_affiliation == ["staff@test.de"]
    assert identity.idp_entity_id == IDP_EID
    assert identity.name_id == "u123-persistent"
    assert in_response_to == reqid


async def test_unsigned_assertion_is_rejected(certs, idp_metadata_file, make_idp):
    """want_assertions_signed=True must reject a response with an unsigned assertion."""
    settings = _settings(certs, idp_metadata_file)
    engine = SamlEngine(settings)
    reqid, _ = await engine.create_authn_request(relay_state="/app")

    idp = make_idp(engine.sp_metadata())
    saml_response = mint_response(
        idp,
        reqid,
        ava={"eduPersonPrincipalName": ["u123@test.de"]},
        sign_response=False,
        sign_assertion=False,
    )

    with pytest.raises(SamlResponseError):
        await engine.parse_response(saml_response, outstanding={reqid: "/app"})
