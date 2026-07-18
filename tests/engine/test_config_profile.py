"""SP metadata reflects the requested-attributes / entity-category / mdui profile."""

from saml2.config import SPConfig
from saml2.metadata import create_metadata_string
from tests.conftest import IDP_EID

from fastapi_auth.saml.engine.config import build_sp_config
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
        required_attributes=["eduPersonPrincipalName", "mail"],
        optional_attributes=["displayName"],
        entity_categories=["code-of-conduct", "research-and-scholarship"],
        sp_display_name="Test SP",
        privacy_statement_url="https://sp.example/privacy",
    )


def _sp_metadata(certs, idp_metadata_file) -> str:
    cfg = SPConfig().load(build_sp_config(_settings(certs, idp_metadata_file)))
    return create_metadata_string(None, config=cfg, sign=False).decode()


def test_metadata_has_required_attribute_is_required_true(certs, idp_metadata_file):
    md = _sp_metadata(certs, idp_metadata_file)
    assert 'isRequired="true"' in md
    assert "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" in md  # eduPersonPrincipalName


def test_metadata_has_optional_attribute_is_required_false(certs, idp_metadata_file):
    md = _sp_metadata(certs, idp_metadata_file)
    assert 'isRequired="false"' in md


def test_metadata_has_entity_attributes(certs, idp_metadata_file):
    assert "EntityAttributes" in _sp_metadata(certs, idp_metadata_file)


def test_metadata_has_uiinfo_privacy(certs, idp_metadata_file):
    assert "privacy" in _sp_metadata(certs, idp_metadata_file).lower()


def test_metadata_has_encryption_key_descriptor(certs, idp_metadata_file):
    assert 'use="encryption"' in _sp_metadata(certs, idp_metadata_file)
