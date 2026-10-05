"""Router: SamlSP(requested_authn_context=...) requests the context and enforces it at the ACS."""

from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient
from saml2 import samlp
from saml2.s_utils import decode_base64_and_inflate
from tests.conftest import IDP_EID, PASSWORD_PROTECTED_TRANSPORT, mint_response

from fastapi_auth import saml
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP

MFA = saml.RequestedAuthnContext(class_refs=(saml.REFEDS_MFA,))


def _app(certs, idp_metadata_file, *, allow_idp_initiated=False):
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        cookie_secure=False,
        allow_idp_initiated=allow_idp_initiated,
    )
    sp = SamlSP(settings, requested_authn_context=MFA)
    app = FastAPI()
    sp.mount(app)
    return app, sp


def _login(client, sp):
    login = client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    assert login.status_code == 303
    return login.headers["location"], next(iter(sp.store._outstanding))  # noqa: SLF001


def test_login_requests_the_configured_context(certs, idp_metadata_file):
    app, sp = _app(certs, idp_metadata_file)
    location, _reqid = _login(TestClient(app), sp)

    saml_request = parse_qs(urlparse(location).query)["SAMLRequest"][0]
    request = samlp.authn_request_from_string(decode_base64_and_inflate(saml_request))
    assert request is not None
    assert request.requested_authn_context is not None
    assert [r.text for r in request.requested_authn_context.authn_context_class_ref] == [
        saml.REFEDS_MFA
    ]


def test_acs_accepts_the_requested_context(certs, idp_metadata_file, make_idp):
    app, sp = _app(certs, idp_metadata_file)
    client = TestClient(app)
    _location, reqid = _login(client, sp)
    idp = make_idp(sp.engine.sp_metadata())
    response = mint_response(
        idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"]}, authn_class_ref=saml.REFEDS_MFA
    )

    acs = client.post(
        "/saml/acs", data={"SAMLResponse": response, "RelayState": "/app"}, follow_redirects=False
    )

    assert acs.status_code == 303
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")


def test_acs_403_on_deviating_context(certs, idp_metadata_file, make_idp, caplog):
    app, sp = _app(certs, idp_metadata_file)
    client = TestClient(app)
    _location, reqid = _login(client, sp)
    idp = make_idp(sp.engine.sp_metadata())
    response = mint_response(
        idp,
        reqid,
        ava={"eduPersonPrincipalName": ["u@test.de"]},
        authn_class_ref=PASSWORD_PROTECTED_TRANSPORT,
    )

    with caplog.at_level("WARNING", logger="fastapi_auth.saml"):
        acs = client.post(
            "/saml/acs",
            data={"SAMLResponse": response, "RelayState": "/app"},
            follow_redirects=False,
        )

    assert acs.status_code == 403
    assert sp.settings.session_cookie_name not in acs.headers.get("set-cookie", "")
    assert PASSWORD_PROTECTED_TRANSPORT in caplog.text


def test_acs_403_on_unsolicited_response_with_deviating_context(certs, idp_metadata_file, make_idp):
    """The SP-wide requirement also holds for IdP-initiated logins, which request nothing."""
    app, sp = _app(certs, idp_metadata_file, allow_idp_initiated=True)
    client = TestClient(app)
    idp = make_idp(sp.engine.sp_metadata())
    response = mint_response(
        idp, "ignored", ava={"eduPersonPrincipalName": ["u@test.de"]}, in_response_to=None
    )

    acs = client.post("/saml/acs", data={"SAMLResponse": response}, follow_redirects=False)

    assert acs.status_code == 403
