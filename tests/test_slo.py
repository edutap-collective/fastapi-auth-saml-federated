"""Best-effort SP-initiated Single Logout (SLO): LogoutRequest build + local invalidation."""

import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import IdPConfig
from saml2.metadata import create_metadata_string
from tests.conftest import IDP_EID, SLO, SSO, mint_response

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _settings(certs, idp_metadata_file) -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        cookie_secure=False,
    )


def _build_app(certs, idp_metadata_file):
    sp = SamlSP(_settings(certs, idp_metadata_file))
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")

    @app.get("/me")
    async def me(
        user: FederatedIdentity = Depends(sp.current_user()),  # noqa: B008 - standard FastAPI DI pattern
    ):
        return {"eppn": user.eppn}

    return app, sp


def _idp_metadata_without_slo(tmp_path: Path, certs: dict[str, str]) -> str:
    """IdP metadata with an SSO endpoint but no SingleLogoutService.

    Used to exercise the best-effort fallback: the IdP simply doesn't advertise
    SLO, so ``create_logout_redirect`` must return ``None`` and the router must
    still invalidate the local session and redirect home.
    """
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
    path = tmp_path / "idp-metadata-no-slo.xml"
    path.write_text(md)
    return str(path)


def _login(client, sp, make_idp):
    """Drive a full login (like test_router_login_flow) so a session cookie is set."""
    login = client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    assert login.status_code == 303
    reqid = next(iter(sp.store._outstanding))

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u123@test.de"]})

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "/app"},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")


def _logout_form(client, next_url: str | None = None) -> dict[str, str]:
    """GET the logout confirmation page and return the fields of its POST form."""
    params = {"next": next_url} if next_url is not None else {}
    page = client.get("/saml/slo", params=params, follow_redirects=False)
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert re.search(r'<form method="post" action="/saml/slo">', page.text)
    return dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', page.text))


def _logout(client):
    """Log out the way a browser does: confirmation page, then POST its form."""
    return client.post("/saml/slo", data=_logout_form(client), follow_redirects=False)


# --- (a) create_logout_redirect() builds a signed LogoutRequest to the IdP's SLO ---


async def test_create_logout_redirect_returns_idp_slo_url(certs, idp_metadata_file):
    engine = SamlEngine(_settings(certs, idp_metadata_file))
    identity = FederatedIdentity(idp_entity_id=IDP_EID, name_id="u123-persistent")

    location = await engine.create_logout_redirect(identity)

    assert location is not None
    parsed = urlparse(location)
    assert parsed.netloc == urlparse(SLO).netloc
    assert "SAMLRequest" in parse_qs(parsed.query)


async def test_create_logout_redirect_none_without_name_id(certs, idp_metadata_file):
    engine = SamlEngine(_settings(certs, idp_metadata_file))
    identity = FederatedIdentity(idp_entity_id=IDP_EID, name_id=None)

    assert await engine.create_logout_redirect(identity) is None


async def test_create_logout_redirect_none_without_idp_slo_endpoint(certs, tmp_path):
    idp_metadata_file = _idp_metadata_without_slo(tmp_path, certs)
    engine = SamlEngine(_settings(certs, idp_metadata_file))
    identity = FederatedIdentity(idp_entity_id=IDP_EID, name_id="u123-persistent")

    assert await engine.create_logout_redirect(identity) is None


async def test_create_logout_redirect_never_raises_when_nameid_build_fails(
    certs, idp_metadata_file, monkeypatch
):
    """The NameID construction is pysaml2-adjacent and must be covered by the
    same best-effort guard as do_logout(): if it raises for any reason,
    create_logout_redirect must swallow it and return None, never propagate.

    This is the regression test for the hardening fix that moved the NameID
    build inside the try/except in engine/logout.py -- it fails if that guard
    is reverted (NameID construction moved back outside the try).
    """
    engine = SamlEngine(_settings(certs, idp_metadata_file))
    identity = FederatedIdentity(idp_entity_id=IDP_EID, name_id="u123-persistent")

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("fastapi_auth.saml.engine.logout.NameID", _boom)

    assert await engine.create_logout_redirect(identity) is None


# --- (b) POST /saml/slo ALWAYS clears the local session ---


def test_slo_redirects_to_idp_and_clears_session(certs, idp_metadata_file, make_idp):
    """When the IdP advertises SLO, /saml/slo redirects there AND wipes the local session."""
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)
    assert client.get("/me").status_code == 200

    slo = _logout(client)
    assert slo.status_code == 303
    location = slo.headers["location"]
    assert urlparse(location).netloc == urlparse(SLO).netloc
    assert "SAMLRequest" in parse_qs(urlparse(location).query)
    assert sp.settings.session_cookie_name in slo.headers.get("set-cookie", "")

    assert client.get("/me").status_code == 401


def test_slo_clears_session_and_redirects_home_without_idp_slo(certs, tmp_path, make_idp):
    """When the IdP offers no SLO endpoint, /saml/slo still ALWAYS clears the session."""
    idp_metadata_file = _idp_metadata_without_slo(tmp_path, certs)
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)
    assert client.get("/me").status_code == 200

    slo = _logout(client)
    assert slo.status_code == 303
    assert slo.headers["location"] == "/"
    assert sp.settings.session_cookie_name in slo.headers.get("set-cookie", "")

    assert client.get("/me").status_code == 401


def test_slo_clears_session_when_logout_redirect_build_raises(
    certs, idp_metadata_file, make_idp, monkeypatch
):
    """End-to-end: even if building the IdP LogoutRequest blows up (here via a
    failing NameID construction), GET /saml/slo must still invalidate the
    local session -- local logout must never depend on the SLO round trip.
    """
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)
    assert client.get("/me").status_code == 200

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("fastapi_auth.saml.engine.logout.NameID", _boom)

    slo = _logout(client)
    assert slo.status_code == 303
    assert sp.settings.session_cookie_name in slo.headers.get("set-cookie", "")

    assert client.get("/me").status_code == 401


def test_slo_without_prior_session_still_redirects(certs, idp_metadata_file):
    """No identity was ever established: /saml/slo is a no-op locally but still redirects."""
    app, _sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)

    slo = client.post("/saml/slo", data={"next": "/app"}, follow_redirects=False)
    assert slo.status_code == 303
    assert slo.headers["location"] == "/app"


def test_slo_get_without_session_redirects_without_confirmation(certs, idp_metadata_file):
    app, _sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)

    slo = client.get("/saml/slo", params={"next": "/app"}, follow_redirects=False)
    assert slo.status_code == 303
    assert slo.headers["location"] == "/app"


# --- (c) logout CSRF (issue #15): GET never logs out, POST needs the session's token ---


def test_slo_get_only_renders_a_confirmation_page(certs, idp_metadata_file, make_idp):
    """A cross-site link or redirect to GET /slo must not end the session (issue #15)."""
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)

    fields = _logout_form(client, next_url="/app")

    assert fields["next"] == "/app"
    assert fields["csrf_token"]
    assert client.get("/me").status_code == 200


def test_slo_confirmation_page_cannot_be_framed(certs, idp_metadata_file, make_idp):
    """Clickjacking the confirmation button would be CSRF by other means."""
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)

    page = client.get("/saml/slo")

    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]


def test_slo_confirmation_page_escapes_next(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)

    page = client.get("/saml/slo", params={"next": '/a"><script>x</script>'})

    assert "<script>" not in page.text


def test_slo_post_without_token_is_rejected(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)

    slo = client.post("/saml/slo", data={"next": "/app"}, follow_redirects=False)

    assert slo.status_code == 403
    assert sp.settings.session_cookie_name not in slo.headers.get("set-cookie", "")
    assert client.get("/me").status_code == 200


def test_slo_post_with_wrong_token_is_rejected(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)

    slo = client.post("/saml/slo", data={"csrf_token": "forged"}, follow_redirects=False)

    assert slo.status_code == 403
    assert client.get("/me").status_code == 200


def test_slo_post_with_non_ascii_token_is_rejected_not_an_error(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    _login(client, sp, make_idp)

    slo = client.post("/saml/slo", data={"csrf_token": "ä"}, follow_redirects=False)

    assert slo.status_code == 403


def test_slo_token_is_bound_to_the_session(certs, idp_metadata_file, make_idp):
    """A token an attacker obtained for their own session does not log out the victim."""
    app, sp = _build_app(certs, idp_metadata_file)
    attacker, victim = TestClient(app), TestClient(app)
    _login(attacker, sp, make_idp)
    _login(victim, sp, make_idp)
    attacker_token = _logout_form(attacker)["csrf_token"]

    slo = victim.post("/saml/slo", data={"csrf_token": attacker_token}, follow_redirects=False)

    assert slo.status_code == 403
    assert victim.get("/me").status_code == 200


def test_logout_csrf_token_for_app_rendered_forms(certs, idp_metadata_file, make_idp):
    """Apps that render their own logout button get the token from SamlSP."""
    app, sp = _build_app(certs, idp_metadata_file)

    @app.get("/token")
    async def token(request: Request):
        return {"token": sp.logout_csrf_token(request)}

    client = TestClient(app)
    assert client.get("/token").json() == {"token": None}
    _login(client, sp, make_idp)
    csrf_token = client.get("/token").json()["token"]

    slo = client.post("/saml/slo", data={"csrf_token": csrf_token}, follow_redirects=False)

    assert slo.status_code == 303
    assert client.get("/me").status_code == 401


def test_slo_return_ignores_missing_and_garbage_response(certs, idp_metadata_file):
    """GET /saml/slo/return is best-effort: no SAMLResponse, or a garbage one, redirects home."""
    app, _sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)

    no_response = client.get("/saml/slo/return", follow_redirects=False)
    assert no_response.status_code == 303
    assert no_response.headers["location"] == "/"

    garbage = client.get(
        "/saml/slo/return", params={"SAMLResponse": "not-a-real-response"}, follow_redirects=False
    )
    assert garbage.status_code == 303
    assert garbage.headers["location"] == "/"
