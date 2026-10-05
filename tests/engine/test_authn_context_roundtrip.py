"""SamlEngine: per-login RequestedAuthnContext in the AuthnRequest, checked in the response."""

from urllib.parse import parse_qs, urlparse

import pytest
from saml2 import samlp
from saml2.s_utils import decode_base64_and_inflate
from tests.conftest import IDP_EID, PASSWORD_PROTECTED_TRANSPORT, mint_response

from fastapi_auth.saml.engine.authn_context import (
    REFEDS_MFA,
    AuthnContextError,
    RequestedAuthnContext,
)
from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.settings import SamlSettings

MFA = RequestedAuthnContext(class_refs=(REFEDS_MFA,))


def _engine(certs, idp_metadata_file) -> SamlEngine:
    return SamlEngine(
        SamlSettings(
            entity_id="urn:test:sp",
            base_url="https://sp.example",
            key_file=certs["sp_key"],
            cert_file=certs["sp_crt"],
            idp_metadata_file=idp_metadata_file,
            fixed_idp_entity_id=IDP_EID,
            session_secret="s3cr3t",
        )
    )


def _authn_request(location: str) -> samlp.AuthnRequest:
    saml_request = parse_qs(urlparse(location).query)["SAMLRequest"][0]
    request = samlp.authn_request_from_string(decode_base64_and_inflate(saml_request))
    assert request is not None
    return request


async def test_authn_request_carries_the_requested_context(certs, idp_metadata_file):
    engine = _engine(certs, idp_metadata_file)

    _reqid, location = await engine.create_authn_request(
        relay_state="/app", requested_authn_context=MFA
    )

    rac = _authn_request(location).requested_authn_context
    assert rac is not None
    assert rac.comparison == "exact"
    assert [ref.text for ref in rac.authn_context_class_ref] == [REFEDS_MFA]


async def test_context_is_per_login_not_global(certs, idp_metadata_file):
    engine = _engine(certs, idp_metadata_file)
    await engine.create_authn_request(relay_state="/app", requested_authn_context=MFA)

    _reqid, location = await engine.create_authn_request(relay_state="/app")

    assert _authn_request(location).requested_authn_context is None


async def test_matching_context_is_accepted(certs, idp_metadata_file, make_idp):
    engine = _engine(certs, idp_metadata_file)
    reqid, _ = await engine.create_authn_request(relay_state="/app", requested_authn_context=MFA)
    idp = make_idp(engine.sp_metadata())
    response = mint_response(
        idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"]}, authn_class_ref=REFEDS_MFA
    )

    identity, _ = await engine.parse_response(
        response, outstanding={reqid: "/app"}, requested_authn_context=MFA
    )

    assert identity.authn_context_class == REFEDS_MFA


async def test_deviating_context_is_rejected(certs, idp_metadata_file, make_idp):
    engine = _engine(certs, idp_metadata_file)
    reqid, _ = await engine.create_authn_request(relay_state="/app", requested_authn_context=MFA)
    idp = make_idp(engine.sp_metadata())
    response = mint_response(
        idp,
        reqid,
        ava={"eduPersonPrincipalName": ["u@test.de"]},
        authn_class_ref=PASSWORD_PROTECTED_TRANSPORT,
    )

    with pytest.raises(AuthnContextError) as excinfo:
        await engine.parse_response(
            response, outstanding={reqid: "/app"}, requested_authn_context=MFA
        )

    assert excinfo.value.returned == [PASSWORD_PROTECTED_TRANSPORT]


async def test_without_requested_context_nothing_is_checked(certs, idp_metadata_file, make_idp):
    engine = _engine(certs, idp_metadata_file)
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    idp = make_idp(engine.sp_metadata())
    response = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"]})

    identity, _ = await engine.parse_response(response, outstanding={reqid: "/app"})

    assert identity.authn_context_class == PASSWORD_PROTECTED_TRANSPORT
