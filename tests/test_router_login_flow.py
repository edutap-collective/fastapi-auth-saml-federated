"""End-to-end login flow through the FastAPI router with an in-memory IdP."""

from urllib.parse import parse_qs, urlparse

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from tests.conftest import IDP_EID, mint_response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _build_app(certs, idp_metadata_file):
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

    @app.get("/me")
    async def me(
        user: FederatedIdentity = Depends(sp.current_user()),  # noqa: B008 - standard FastAPI DI pattern
    ):
        return {"eppn": user.eppn, "affiliation": user.scoped_affiliation}

    return app, sp


def test_metadata_endpoint(certs, idp_metadata_file):
    app, _ = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    resp = client.get("/saml/metadata")
    assert resp.status_code == 200
    assert "urn:test:sp" in resp.text


def test_protected_route_401_without_session(certs, idp_metadata_file):
    app, _ = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    assert client.get("/me").status_code == 401


def test_full_login_flow(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)

    # 1. /login -> redirect to IdP SSO with SAMLRequest
    login = client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    assert login.status_code == 303
    location = login.headers["location"]
    assert "SAMLRequest" in urlparse(location).query
    # the outstanding request id is what pysaml2 generated
    reqids = list(sp.store._outstanding)
    assert len(reqids) == 1
    reqid = reqids[0]

    # 2. IdP mints a signed response for that request
    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(
        idp,
        reqid,
        ava={
            "eduPersonPrincipalName": ["u123@test.de"],
            "eduPersonScopedAffiliation": ["staff@test.de"],
        },
    )

    # 3. POST to ACS -> session cookie set, redirect to next
    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "/app"},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == "/app"
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")

    # 4. protected route now returns the identity (cookie carried by client)
    me = client.get("/me")
    assert me.status_code == 200
    assert me.json()["eppn"] == "u123@test.de"
    assert me.json()["affiliation"] == ["staff@test.de"]


def test_login_next_open_redirect_is_sanitized(certs, idp_metadata_file, make_idp):
    """A protocol-relative `next` ("//evil.com") must never reach the IdP or the ACS redirect."""
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)

    # 1. /login with a malicious next -> the RelayState sent to the IdP is sanitized
    login = client.get("/saml/login", params={"next": "//evil.com"}, follow_redirects=False)
    assert login.status_code == 303
    location = login.headers["location"]
    query = parse_qs(urlparse(location).query)
    assert query["RelayState"] == ["/"]

    reqids = list(sp.store._outstanding)
    assert len(reqids) == 1
    reqid = reqids[0]
    assert sp.store._outstanding[reqid][0] == "/"

    # 2. IdP mints a signed response for that request
    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(
        idp,
        reqid,
        ava={"eduPersonPrincipalName": ["u123@test.de"]},
    )

    # 3. POST to ACS (echoing back the already-sanitized RelayState) -> redirect stays local
    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": query["RelayState"][0]},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == "/"


def test_acs_relay_state_open_redirect_is_sanitized(certs, idp_metadata_file, make_idp):
    """A validly-minted SAMLResponse with an absolute-URL RelayState must redirect locally."""
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)

    login = client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    assert login.status_code == 303
    reqids = list(sp.store._outstanding)
    assert len(reqids) == 1
    reqid = reqids[0]

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(
        idp,
        reqid,
        ava={"eduPersonPrincipalName": ["u123@test.de"]},
    )

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "https://evil.com"},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == "/"
