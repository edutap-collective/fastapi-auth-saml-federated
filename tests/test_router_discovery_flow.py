"""End-to-end discovery flows: external DS redirect and embedded WAYF."""

from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.conftest import IDP_EID, build_signed_aggregate, mint_response

from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _build_app(settings: SamlSettings):
    sp = SamlSP(settings)
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")
    return app, sp


def test_external_discovery_redirects_to_ds_then_to_chosen_idp(certs, idp_metadata_file):
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        cookie_secure=False,
        discovery_mode="external",
        ds_url="https://ds.example/DS",
    )
    app, sp = _build_app(settings)
    client = TestClient(app)

    # 1. /login -> redirect to the external Discovery Service.
    login = client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    assert login.status_code == 303
    ds_location = login.headers["location"]
    q = parse_qs(urlparse(ds_location).query)
    assert ds_location.startswith("https://ds.example/DS")
    assert q["entityID"] == ["urn:test:sp"]
    (return_url,) = q["return"]
    assert "/saml/disco" in return_url
    assert "next=%2Fapp" in return_url

    # 2. DS return with the chosen IdP's entityID -> AuthnRequest to that IdP.
    disco = client.get(
        "/saml/disco", params={"entityID": IDP_EID, "next": "/app"}, follow_redirects=False
    )
    assert disco.status_code == 303
    idp_location = disco.headers["location"]
    assert "SAMLRequest" in urlparse(idp_location).query
    reqids = list(sp.store._outstanding)
    assert len(reqids) == 1
    assert sp.store._outstanding[reqids[0]][0] == "/app"


def test_external_disco_without_entity_id_is_rejected(certs, idp_metadata_file):
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        cookie_secure=False,
        discovery_mode="external",
        ds_url="https://ds.example/DS",
    )
    app, _sp = _build_app(settings)
    client = TestClient(app)

    resp = client.get("/saml/disco", follow_redirects=False)
    assert resp.status_code == 400


def test_embedded_wayf_lists_idps_and_selection_starts_login(tmp_path, certs):
    aggregate_file = build_signed_aggregate(tmp_path, certs, [IDP_EID])
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        fixed_idp_entity_id=IDP_EID,
        metadata_source="aggregate",
        aggregate_file=aggregate_file,
        session_secret="s3cr3t",
        cookie_secure=False,
        discovery_mode="embedded",
    )
    app, sp = _build_app(settings)
    client = TestClient(app)

    # 1. /login without a selection -> the embedded WAYF page listing the IdP.
    wayf = client.get("/saml/login", follow_redirects=False)
    assert wayf.status_code == 200
    assert "text/html" in wayf.headers["content-type"]
    assert IDP_EID in wayf.text

    # 2. /login?idp=<entityID> -> straight to an AuthnRequest for that IdP.
    selection = client.get("/saml/login", params={"idp": IDP_EID}, follow_redirects=False)
    assert selection.status_code == 303
    location = selection.headers["location"]
    assert "SAMLRequest" in urlparse(location).query
    reqids = list(sp.store._outstanding)
    assert len(reqids) == 1


def test_embedded_wayf_full_round_trip_with_in_memory_idp(tmp_path, certs, make_idp):
    """The enumerated IdP from the aggregate must also be the one that can mint a response."""
    aggregate_file = build_signed_aggregate(tmp_path, certs, [IDP_EID])
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        fixed_idp_entity_id=IDP_EID,
        metadata_source="aggregate",
        aggregate_file=aggregate_file,
        session_secret="s3cr3t",
        cookie_secure=False,
        discovery_mode="embedded",
    )
    app, sp = _build_app(settings)
    client = TestClient(app)

    selection = client.get("/saml/login", params={"idp": IDP_EID}, follow_redirects=False)
    assert selection.status_code == 303
    reqids = list(sp.store._outstanding)
    reqid = reqids[0]

    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u123@test.de"]})

    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "/"},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")
