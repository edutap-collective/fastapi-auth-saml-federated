"""Smoke test for SamlSP.identifier(): primary field, then fallback chain."""

from tests.conftest import IDP_EID

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _sp(certs, idp_metadata_file):
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        cookie_secure=False,
    )
    return SamlSP(settings)


def test_identifier_prefers_subject_id(certs, idp_metadata_file):
    sp = _sp(certs, idp_metadata_file)
    identity = FederatedIdentity(subject_id="s@x", eppn="e@x")
    assert sp.identifier(identity) == "s@x"


def test_identifier_falls_back_to_eppn_when_subject_id_missing(certs, idp_metadata_file):
    sp = _sp(certs, idp_metadata_file)
    identity = FederatedIdentity(subject_id=None, eppn="e@x")
    assert sp.identifier(identity) == "e@x"
