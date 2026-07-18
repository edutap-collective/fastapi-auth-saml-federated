"""ACS enforces mandatory attributes end-to-end."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.conftest import IDP_EID, mint_response

from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _app(certs, idp_metadata_file, required):
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        cookie_secure=False,
        required_attributes=required,
    )
    sp = SamlSP(settings)
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")
    return app, sp


def _login_and_get_reqid(client, sp):
    client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    return next(iter(sp.store._outstanding))  # noqa: SLF001


def test_acs_403_when_mandatory_missing(certs, idp_metadata_file, make_idp):
    app, sp = _app(certs, idp_metadata_file, ["eduPersonPrincipalName", "mail"])
    client = TestClient(app)
    reqid = _login_and_get_reqid(client, sp)
    idp = make_idp(sp.engine.sp_metadata())
    resp = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"]})  # no mail
    r = client.post(
        "/saml/acs", data={"SAMLResponse": resp, "RelayState": "/app"}, follow_redirects=False
    )
    assert r.status_code == 403
    assert "mail" in r.text


def test_acs_success_when_all_present(certs, idp_metadata_file, make_idp):
    app, sp = _app(certs, idp_metadata_file, ["eduPersonPrincipalName", "mail"])
    client = TestClient(app)
    reqid = _login_and_get_reqid(client, sp)
    idp = make_idp(sp.engine.sp_metadata())
    resp = mint_response(
        idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"], "mail": ["u@test.de"]}
    )
    r = client.post(
        "/saml/acs", data={"SAMLResponse": resp, "RelayState": "/app"}, follow_redirects=False
    )
    assert r.status_code == 303
