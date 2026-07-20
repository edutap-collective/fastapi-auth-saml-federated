"""Tests for the JWT ``jwt_attributes`` claims allowlist (data minimisation)."""

import jwt as pyjwt
from fastapi import Request, Response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.jwt import JWTBackend
from fastapi_auth.saml.settings import SamlSettings


def _settings(jwt_attributes: list[str] | None = None) -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file="/tmp/k",
        cert_file="/tmp/c",
        fixed_idp_entity_id="urn:test:idp",
        session_secret="s" * 40,
        backend="jwt",
        cookie_secure=False,
        jwt_attributes=jwt_attributes,
    )


def _request(token: str) -> Request:
    return Request({"type": "http", "headers": [(b"cookie", f"fa_saml_session={token}".encode())]})


def _token_from(response: Response) -> str:
    return response.headers["set-cookie"].split(";")[0].split("=", 1)[1]


async def test_allowlist_filters_attrs_claim_and_restricts_load():
    settings = _settings(jwt_attributes=["eppn"])
    backend = JWTBackend(settings)
    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), response)

    token = _token_from(response)
    payload = pyjwt.decode(token, settings.jwt_verifying_key, algorithms=[settings.jwt_alg])
    assert payload["attrs"].get("eppn") == "u@lmu.de"
    assert not payload["attrs"].get("mail")

    loaded = await backend.load(_request(token))
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"
    assert loaded.mail == []


async def test_without_allowlist_full_identity_is_preserved():
    settings = _settings(jwt_attributes=None)
    backend = JWTBackend(settings)
    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), response)

    token = _token_from(response)
    payload = pyjwt.decode(token, settings.jwt_verifying_key, algorithms=[settings.jwt_alg])
    assert payload["attrs"].get("eppn") == "u@lmu.de"
    assert payload["attrs"].get("mail") == ["u@lmu.de"]

    loaded = await backend.load(_request(token))
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"
    assert loaded.mail == ["u@lmu.de"]
