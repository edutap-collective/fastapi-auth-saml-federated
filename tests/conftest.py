"""Shared test fixtures: test certs and an in-memory pysaml2 IdP."""

import base64
import subprocess
from pathlib import Path

import pytest
from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import IdPConfig
from saml2.metadata import create_metadata_string
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NameID
from saml2.server import Server

SP_EID = "urn:test:sp"
IDP_EID = "urn:test:idp"
ACS = "https://sp.example/saml/acs"
SSO = "https://idp.example/sso"


def _make_cert(path_key: Path, path_crt: Path, cn: str) -> None:
    subprocess.run(  # noqa: S603
        [
            "/opt/homebrew/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(path_key),
            "-out",
            str(path_crt),
            "-days",
            "2",
            "-subj",
            f"/CN={cn}",
        ],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def certs(tmp_path):
    d = tmp_path / "certs"
    d.mkdir()
    idp_key, idp_crt = d / "idp.key", d / "idp.crt"
    sp_key, sp_crt = d / "sp.key", d / "sp.crt"
    _make_cert(idp_key, idp_crt, "test-idp")
    _make_cert(sp_key, sp_crt, "test-sp")
    return {
        "idp_key": str(idp_key),
        "idp_crt": str(idp_crt),
        "sp_key": str(sp_key),
        "sp_crt": str(sp_crt),
    }


@pytest.fixture
def idp_metadata_file(tmp_path, certs):
    idp_cfg = IdPConfig().load(
        {
            "entityid": IDP_EID,
            "service": {
                "idp": {"endpoints": {"single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)]}}
            },
            "key_file": certs["idp_key"],
            "cert_file": certs["idp_crt"],
        }
    )
    md = create_metadata_string(None, config=idp_cfg, sign=False).decode()
    path = tmp_path / "idp-metadata.xml"
    path.write_text(md)
    return str(path)


@pytest.fixture
def make_idp(certs):
    """Return a factory that builds an in-memory IdP Server bound to given SP metadata."""

    def _factory(sp_metadata_xml: str) -> Server:
        idp_cfg = {
            "entityid": IDP_EID,
            "xmlsec_binary": "/opt/homebrew/bin/xmlsec1",
            "service": {
                "idp": {"endpoints": {"single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)]}}
            },
            "key_file": certs["idp_key"],
            "cert_file": certs["idp_crt"],
            "metadata": {"inline": [sp_metadata_xml]},
        }
        return Server(config=IdPConfig().load(idp_cfg))

    return _factory


def mint_response(
    idp: Server, request_id: str, ava: dict[str, list[str]], name_id_text: str = "u123-persistent"
) -> str:
    """Mint a signed base64 SAML response as an IdP would POST to the ACS."""
    name_id = NameID(format=NAMEID_FORMAT_PERSISTENT, text=name_id_text)
    xml = idp.create_authn_response(
        identity=ava,
        in_response_to=request_id,
        destination=ACS,
        sp_entity_id=SP_EID,
        name_id=name_id,
        sign_response=True,
        sign_assertion=True,
        authn={
            "class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "authn_auth": IDP_EID,
        },
    )
    return base64.b64encode(xml.encode()).decode()
