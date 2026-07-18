"""Tests for the signed-cookie session backend."""

from fastapi import Request, Response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.cookie import CookieBackend
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings


def _settings() -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file="/tmp/k",
        cert_file="/tmp/c",
        fixed_idp_entity_id="urn:test:idp",
        session_secret="s3cr3t",
        cookie_secure=False,
    )


def _request_with_cookies(cookie_header: str) -> Request:
    scope = {"type": "http", "headers": [(b"cookie", cookie_header.encode())]}
    return Request(scope)


async def test_establish_sets_signed_cookie_and_load_roundtrips():
    settings = _settings()
    store = MemoryStore()
    backend = CookieBackend(settings, store)

    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de"), response)
    set_cookie = response.headers["set-cookie"]
    assert settings.session_cookie_name in set_cookie
    assert "httponly" in set_cookie.lower()

    cookie_value = set_cookie.split(";")[0].split("=", 1)[1]
    request = _request_with_cookies(f"{settings.session_cookie_name}={cookie_value}")
    loaded = await backend.load(request)
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_load_without_cookie_returns_none():
    backend = CookieBackend(_settings(), MemoryStore())
    assert await backend.load(_request_with_cookies("")) is None


async def test_load_with_tampered_cookie_returns_none():
    settings = _settings()
    backend = CookieBackend(settings, MemoryStore())
    request = _request_with_cookies(f"{settings.session_cookie_name}=not-a-valid-signed-value")
    assert await backend.load(request) is None
