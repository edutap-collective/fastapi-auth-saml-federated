"""Tests for the stateless JWT backend."""

from fastapi import Request, Response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.jwt import JWTBackend
from fastapi_auth.saml.settings import SamlSettings


def _settings() -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file="/tmp/k",
        cert_file="/tmp/c",
        fixed_idp_entity_id="urn:test:idp",
        session_secret="s" * 40,
        backend="jwt",
        cookie_secure=False,
    )


def _request(headers: list[tuple[bytes, bytes]]) -> Request:
    return Request({"type": "http", "headers": headers})


async def test_establish_sets_cookie_and_load_from_cookie():
    backend = JWTBackend(_settings())
    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), response)
    set_cookie = response.headers["set-cookie"]
    token = set_cookie.split(";")[0].split("=", 1)[1]
    req = _request([(b"cookie", f"fa_saml_session={token}".encode())])
    loaded = await backend.load(req)
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"
    assert loaded.mail == ["u@lmu.de"]


async def test_load_from_bearer_header():
    backend = JWTBackend(_settings())
    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de"), response)
    token = response.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    req = _request([(b"authorization", f"Bearer {token}".encode())])
    loaded = await backend.load(req)
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_load_without_token_returns_none():
    assert await JWTBackend(_settings()).load(_request([])) is None


async def test_load_tampered_token_returns_none():
    backend = JWTBackend(_settings())
    req = _request([(b"authorization", b"Bearer not.a.jwt")])
    assert await backend.load(req) is None
