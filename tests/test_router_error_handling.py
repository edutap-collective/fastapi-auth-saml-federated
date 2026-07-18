"""A malformed/invalid SAML response yields HTTP 400, not 500."""

import base64

from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.conftest import IDP_EID

from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _app(certs, idp_metadata_file):
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
    sp = SamlSP(settings)
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")
    return app


def test_acs_garbage_response_is_400(certs, idp_metadata_file):
    app = _app(certs, idp_metadata_file)
    client = TestClient(app)
    garbage = base64.b64encode(b"<not-a-saml-response/>").decode()
    r = client.post(
        "/saml/acs", data={"SAMLResponse": garbage, "RelayState": "/app"}, follow_redirects=False
    )
    assert r.status_code == 400
