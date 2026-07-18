"""Tests for building the pysaml2 SP config from settings."""

import pytest
from saml2 import BINDING_HTTP_POST
from saml2.config import SPConfig

from fastapi_auth.saml.engine.config import build_sp_config, load_idp_metadata
from fastapi_auth.saml.settings import SamlSettings


def _settings(tmp_path, idp_md: str) -> SamlSettings:
    md = tmp_path / "idp.xml"
    md.write_text(idp_md)
    key = tmp_path / "sp.key"
    crt = tmp_path / "sp.crt"
    key.write_text("x")
    crt.write_text("x")
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=str(key),
        cert_file=str(crt),
        idp_metadata_file=str(md),
        fixed_idp_entity_id="urn:test:idp",
        session_secret="s3cr3t",
    )


MINIMAL_IDP_MD = (
    '<?xml version="1.0"?>'
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:test:idp">'
    "</EntityDescriptor>"
)


def test_load_idp_metadata_from_file(tmp_path):
    s = _settings(tmp_path, MINIMAL_IDP_MD)
    assert "urn:test:idp" in load_idp_metadata(s)


def test_load_idp_metadata_requires_a_source(tmp_path):
    s = _settings(tmp_path, MINIMAL_IDP_MD)
    s.idp_metadata_file = None
    with pytest.raises(ValueError, match="metadata"):
        load_idp_metadata(s)


def test_build_sp_config_shape(tmp_path):
    s = _settings(tmp_path, MINIMAL_IDP_MD)
    cfg = build_sp_config(s)
    assert cfg["entityid"] == "urn:test:sp"
    acs = cfg["service"]["sp"]["endpoints"]["assertion_consumer_service"]
    assert acs == [("https://sp.example/saml/acs", BINDING_HTTP_POST)]
    assert cfg["service"]["sp"]["want_assertions_signed"] is True
    assert cfg["metadata"]["inline"] == [MINIMAL_IDP_MD]


def _generate_sp_key_and_cert(tmp_path):
    """Write a throwaway RSA key + self-signed certificate for pysaml2 to load.

    ``SPConfig().load`` builds a pysaml2 security context, which parses
    ``key_file``/``cert_file`` as real PEM material (via ``cryptography``)
    regardless of signing settings. The placeholder ``"x"`` content used
    elsewhere in this module is fine for tests that never call
    ``SPConfig().load``, but this test needs an actually-valid keypair.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sp.example")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "real_sp.key"
    cert_path = tmp_path / "real_sp.crt"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(key_path), str(cert_path)


def test_build_sp_config_loads_in_pysaml2(tmp_path):
    # Real IdP metadata is needed for SPConfig().load to accept it; use a
    # generated descriptor so the config actually parses.
    from saml2 import BINDING_HTTP_REDIRECT
    from saml2.config import IdPConfig
    from saml2.metadata import create_metadata_string

    idp_cfg = IdPConfig().load(
        {
            "entityid": "urn:test:idp",
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [("https://idp/sso", BINDING_HTTP_REDIRECT)]
                    }
                }
            },
        }
    )
    idp_md = create_metadata_string(None, config=idp_cfg, sign=False).decode()
    s = _settings(tmp_path, idp_md)
    # SPConfig().load parses key_file/cert_file as real PEM; swap in a valid
    # throwaway keypair (see _generate_sp_key_and_cert for why).
    s.key_file, s.cert_file = _generate_sp_key_and_cert(tmp_path)
    cfg = build_sp_config(s)
    loaded = SPConfig().load(cfg)  # must not raise
    assert loaded.entityid == "urn:test:sp"
