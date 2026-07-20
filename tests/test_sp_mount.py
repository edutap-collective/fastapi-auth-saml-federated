"""SamlSP.mount(app) keeps mount_path and router prefix consistent."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.conftest import IDP_EID

from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _sp(certs, idp_metadata_file, **overrides):
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        cookie_secure=False,
        **overrides,
    )
    return SamlSP(settings)


def test_mount_uses_default_mount_path(certs, idp_metadata_file):
    sp = _sp(certs, idp_metadata_file)
    app = FastAPI()
    sp.mount(app)
    client = TestClient(app)

    resp = client.get("/saml/metadata")

    assert resp.status_code == 200
    assert "urn:test:sp" in resp.text


def test_mount_follows_custom_mount_path(certs, idp_metadata_file):
    sp = _sp(certs, idp_metadata_file, mount_path="/auth/saml")
    app = FastAPI()
    sp.mount(app)
    client = TestClient(app)

    matched = client.get("/auth/saml/metadata")
    unmatched = client.get("/saml/metadata")

    assert matched.status_code == 200
    assert "urn:test:sp" in matched.text
    assert unmatched.status_code == 404
