"""End-to-end IdP-initiated (unsolicited) ACS flow + assertion-replay protection.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from tests.conftest import IDP_EID, mint_response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP

_AVA = {
    "eduPersonPrincipalName": ["u123@test.de"],
    "eduPersonScopedAffiliation": ["staff@test.de"],
}


def _build_app(
    certs,
    idp_metadata_file,
    *,
    allow_idp_initiated: bool,
    idp_initiated_default_relay_state: str = "/",
):
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
        idp_initiated_default_relay_state=idp_initiated_default_relay_state,
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


def test_unsolicited_response_succeeds_and_redirects_to_default_relay_state(
    certs, idp_metadata_file, make_idp
):
    app, sp = _build_app(certs, idp_metadata_file, allow_idp_initiated=True)
    client = TestClient(app)

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, "unused", _AVA, in_response_to=None)

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == sp.settings.idp_initiated_default_relay_state
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")

    me = client.get("/me")
    assert me.status_code == 200
    assert me.json()["eppn"] == "u123@test.de"
    assert me.json()["affiliation"] == ["staff@test.de"]


def test_unsolicited_response_uses_configured_default_relay_state_when_omitted(
    certs, idp_metadata_file, make_idp
):
    """A non-default idp_initiated_default_relay_state must fire when RelayState is omitted.

    Regression test for the Plan 8 docs-review bug: the ACS handler used to
    declare ``RelayState: Annotated[str, Form()] = "/"``, so FastAPI filled in
    ``"/"`` whenever the IdP omitted the field entirely (the common
    IdP-initiated case). ``RelayState or idp_initiated_default_relay_state``
    then always short-circuited on ``"/"``, so a configured
    ``idp_initiated_default_relay_state`` such as ``"/dashboard"`` never took
    effect. With the fixed ``= None`` default, an omitted field is
    distinguishable from an explicit ``"/"`` and the configured default fires.
    """
    app, sp = _build_app(
        certs,
        idp_metadata_file,
        allow_idp_initiated=True,
        idp_initiated_default_relay_state="/dashboard",
    )
    client = TestClient(app)

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, "unused", _AVA, in_response_to=None)

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == "/dashboard"


def test_unsolicited_response_honors_safe_relay_state(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file, allow_idp_initiated=True)
    client = TestClient(app)

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, "unused", _AVA, in_response_to=None)

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "/app"},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == "/app"


def test_unsolicited_response_sanitizes_unsafe_relay_state(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file, allow_idp_initiated=True)
    client = TestClient(app)

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, "unused", _AVA, in_response_to=None)

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "https://evil.com"},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == "/"


def test_replayed_unsolicited_response_is_rejected(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file, allow_idp_initiated=True)
    client = TestClient(app)

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, "unused", _AVA, in_response_to=None)

    first = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response},
        follow_redirects=False,
    )
    assert first.status_code == 303

    replay = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response},
        follow_redirects=False,
    )
    assert replay.status_code == 400


def test_unsolicited_response_rejected_when_disabled_by_default(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file, allow_idp_initiated=False)
    client = TestClient(app)

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, "unused", _AVA, in_response_to=None)

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response},
        follow_redirects=False,
    )
    assert acs.status_code == 400


def test_solicited_login_flow_still_works_when_idp_initiated_is_allowed(
    certs, idp_metadata_file, make_idp
):
    """SP-initiated (solicited) logins are unaffected by allow_idp_initiated=True."""
    app, sp = _build_app(certs, idp_metadata_file, allow_idp_initiated=True)
    client = TestClient(app)

    login = client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    assert login.status_code == 303
    reqids = list(sp.store._outstanding)
    assert len(reqids) == 1
    reqid = reqids[0]

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, reqid, _AVA)

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "/app"},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == "/app"
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")


def test_solicited_replay_rejected_when_idp_initiated_allowed(certs, idp_metadata_file, make_idp):
    """A replayed *solicited* response must be rejected even with allow_idp_initiated=True.

    Regression test for the Plan 8 review finding: ``allow_idp_initiated=True``
    sets pysaml2's ``allow_unsolicited=True``, which makes pysaml2 accept a
    solicited response (``InResponseTo`` present) even when the reqid no
    longer matches any outstanding request -- e.g. because it was already
    consumed by an earlier POST of the identical response. The ACS handler
    used to ignore the return value of ``pop_outstanding`` in the solicited
    branch, so the second POST of the same response re-established a session
    instead of being rejected as a replay.
    """
    app, sp = _build_app(certs, idp_metadata_file, allow_idp_initiated=True)
    client = TestClient(app)

    login = client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    assert login.status_code == 303
    reqids = list(sp.store._outstanding)
    assert len(reqids) == 1
    reqid = reqids[0]

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, reqid, _AVA)

    first = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "/app"},
        follow_redirects=False,
    )
    assert first.status_code == 303
    assert first.headers["location"] == "/app"

    replay = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "/app"},
        follow_redirects=False,
    )
    assert replay.status_code == 400


def test_forged_inresponseto_rejected_when_idp_initiated_allowed(
    certs, idp_metadata_file, make_idp
):
    """A solicited-shaped response carrying a reqid this SP never issued must be rejected.

    With ``allow_idp_initiated=True`` pysaml2 accepts any ``InResponseTo``,
    matching or not. Without the fix, ``pop_outstanding`` for a never-issued
    reqid returns ``None`` and the handler proceeded to establish a session
    anyway.
    """
    app, sp = _build_app(certs, idp_metadata_file, allow_idp_initiated=True)
    client = TestClient(app)

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, "unused", _AVA, in_response_to="id-never-issued")

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response},
        follow_redirects=False,
    )
    assert acs.status_code == 400
