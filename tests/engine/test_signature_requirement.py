"""Which signature an SP demands: on the assertion, on the response, or on both.

Each variant is checked end to end against the in-memory IdP: the response
it requires is accepted, every response lacking a required signature is
rejected with ``SamlResponseError``.
"""

import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError
from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import IdPConfig
from saml2.server import Server
from tests.conftest import IDP_EID, SSO, mint_response

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.engine.config import build_sp_config
from fastapi_auth.saml.engine.errors import SamlResponseError
from fastapi_auth.saml.settings import SamlSettings

ASSERTION_ONLY = {"want_assertions_signed": True, "want_response_signed": False}
RESPONSE_ONLY = {"want_assertions_signed": False, "want_response_signed": True}
BOTH = {"want_assertions_signed": True, "want_response_signed": True}


def _settings(certs, idp_metadata_file, **overrides) -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        **overrides,
    )


async def _login(
    certs,
    idp_metadata_file,
    make_idp,
    requirement: dict[str, bool],
    *,
    sign_response: bool,
    sign_assertion: bool,
    encrypt: bool = False,
) -> str | None:
    """Run one login; return the eppn on success, ``None`` if the SP rejected the response."""
    engine = SamlEngine(_settings(certs, idp_metadata_file, **requirement))
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    saml_response = mint_response(
        make_idp(engine.sp_metadata()),
        reqid,
        ava={"eduPersonPrincipalName": ["u123@test.de"]},
        sign_response=sign_response,
        sign_assertion=sign_assertion,
        encrypt_cert=Path(certs["sp_crt"]).read_text() if encrypt else None,
    )
    try:
        identity, _ = await engine.parse_response(saml_response, outstanding={reqid: "/app"})
    except SamlResponseError:
        return None
    return identity.eppn


# --- settings ---------------------------------------------------------------


def test_default_requires_a_signed_assertion_only(certs, idp_metadata_file):
    settings = _settings(certs, idp_metadata_file)
    assert settings.want_assertions_signed is True
    assert settings.want_response_signed is False


def test_requiring_no_signature_at_all_is_refused(certs, idp_metadata_file):
    with pytest.raises(ValidationError, match="want_assertions_signed or want_response_signed"):
        _settings(certs, idp_metadata_file, want_assertions_signed=False)


def test_no_signature_set_after_construction_is_refused_by_the_engine(certs, idp_metadata_file):
    """``SamlSettings`` is mutable; the engine rechecks before handing it to pysaml2."""
    settings = _settings(certs, idp_metadata_file)
    settings.want_assertions_signed = False
    with pytest.raises(ValueError, match="want_assertions_signed or want_response_signed"):
        SamlEngine(settings)


@pytest.mark.parametrize("requirement", [ASSERTION_ONLY, RESPONSE_ONLY, BOTH])
def test_requirement_reaches_the_pysaml2_config(certs, idp_metadata_file, requirement):
    sp = build_sp_config(_settings(certs, idp_metadata_file, **requirement))["service"]["sp"]
    assert sp["want_assertions_signed"] is requirement["want_assertions_signed"]
    assert sp["want_response_signed"] is requirement["want_response_signed"]


# --- signed assertion required (default) -------------------------------------


@pytest.mark.parametrize(
    ("sign_response", "sign_assertion", "accepted"),
    [
        (False, True, True),
        (True, True, True),
        (True, False, False),
        (False, False, False),
    ],
    ids=["assertion-signed", "both-signed", "response-signed", "unsigned"],
)
async def test_assertion_requirement(
    certs, idp_metadata_file, make_idp, sign_response, sign_assertion, accepted
):
    eppn = await _login(
        certs,
        idp_metadata_file,
        make_idp,
        ASSERTION_ONLY,
        sign_response=sign_response,
        sign_assertion=sign_assertion,
    )
    assert (eppn == "u123@test.de") is accepted


# --- signed response required ------------------------------------------------


@pytest.mark.parametrize(
    ("sign_response", "sign_assertion", "accepted"),
    [
        (True, False, True),
        (True, True, True),
        (False, True, False),
        (False, False, False),
    ],
    ids=["response-signed", "both-signed", "assertion-signed", "unsigned"],
)
async def test_response_requirement(
    certs, idp_metadata_file, make_idp, sign_response, sign_assertion, accepted
):
    eppn = await _login(
        certs,
        idp_metadata_file,
        make_idp,
        RESPONSE_ONLY,
        sign_response=sign_response,
        sign_assertion=sign_assertion,
    )
    assert (eppn == "u123@test.de") is accepted


async def test_response_requirement_with_encrypted_unsigned_assertion(
    certs, idp_metadata_file, make_idp
):
    """A signed response carrying an encrypted, unsigned assertion is accepted."""
    eppn = await _login(
        certs,
        idp_metadata_file,
        make_idp,
        RESPONSE_ONLY,
        sign_response=True,
        sign_assertion=False,
        encrypt=True,
    )
    assert eppn == "u123@test.de"


# --- both signatures required ------------------------------------------------


@pytest.mark.parametrize(
    ("sign_response", "sign_assertion", "accepted"),
    [
        (True, True, True),
        (False, True, False),
        (True, False, False),
        (False, False, False),
    ],
    ids=["both-signed", "assertion-signed", "response-signed", "unsigned"],
)
async def test_both_requirement(
    certs, idp_metadata_file, make_idp, sign_response, sign_assertion, accepted
):
    eppn = await _login(
        certs,
        idp_metadata_file,
        make_idp,
        BOTH,
        sign_response=sign_response,
        sign_assertion=sign_assertion,
    )
    assert (eppn == "u123@test.de") is accepted


# --- signature by a key the metadata does not name ----------------------------


@pytest.mark.parametrize(
    ("requirement", "sign_response", "sign_assertion"),
    [(ASSERTION_ONLY, False, True), (RESPONSE_ONLY, True, False), (BOTH, True, True)],
    ids=["assertion", "response", "both"],
)
async def test_signature_by_a_foreign_key_is_rejected(
    certs, idp_metadata_file, requirement, sign_response, sign_assertion
):
    """A forger signs with its own key (here the SP's); the IdP metadata names another."""
    engine = SamlEngine(_settings(certs, idp_metadata_file, **requirement))
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    forger = Server(
        config=IdPConfig().load(
            {
                "entityid": IDP_EID,
                "xmlsec_binary": shutil.which("xmlsec1"),
                "service": {
                    "idp": {"endpoints": {"single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)]}}
                },
                "key_file": certs["sp_key"],
                "cert_file": certs["sp_crt"],
                "metadata": {"inline": [engine.sp_metadata()]},
            }
        )
    )
    saml_response = mint_response(
        forger,
        reqid,
        ava={"eduPersonPrincipalName": ["u123@test.de"]},
        sign_response=sign_response,
        sign_assertion=sign_assertion,
    )
    with pytest.raises(SamlResponseError):
        await engine.parse_response(saml_response, outstanding={reqid: "/app"})


@pytest.mark.parametrize(
    ("requirement", "advertised"),
    [
        (ASSERTION_ONLY, 'WantAssertionsSigned="true"'),
        (RESPONSE_ONLY, 'WantAssertionsSigned="false"'),
    ],
    ids=["assertion", "response"],
)
def test_sp_metadata_advertises_the_assertion_requirement(
    certs, idp_metadata_file, requirement, advertised
):
    engine = SamlEngine(_settings(certs, idp_metadata_file, **requirement))
    assert advertised in engine.sp_metadata()
