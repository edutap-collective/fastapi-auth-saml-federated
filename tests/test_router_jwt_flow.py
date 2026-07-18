"""End-to-end login flow with backend='jwt'."""

from typing import cast

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from tests.conftest import IDP_EID, mint_response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def test_jwt_login_flow(certs, idp_metadata_file, make_idp):
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s" * 40,
        backend="jwt",
        cookie_secure=False,
    )
    sp = SamlSP(settings)
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")

    @app.get("/me")
    async def me(user: FederatedIdentity = Depends(sp.current_user())):  # noqa: B008
        return {"eppn": user.eppn}

    client = TestClient(app)
    client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    reqid = next(iter(cast(MemoryStore, sp.store)._outstanding))  # noqa: SLF001
    idp = make_idp(sp.engine.sp_metadata())
    resp = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"]})
    acs = client.post(
        "/saml/acs", data={"SAMLResponse": resp, "RelayState": "/app"}, follow_redirects=False
    )
    assert acs.status_code == 303
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")
    assert client.get("/me").json()["eppn"] == "u@test.de"
