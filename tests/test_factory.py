"""Tests for store/backend selection."""

from typing import Any

from fastapi_auth.saml.factory import make_backend, make_store
from fastapi_auth.saml.session.cookie import CookieBackend
from fastapi_auth.saml.session.jwt import JWTBackend
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings

_BASE: dict[str, Any] = dict(
    entity_id="urn:test:sp",
    base_url="https://sp.example",
    key_file="/tmp/k",
    cert_file="/tmp/c",
    fixed_idp_entity_id="urn:test:idp",
)


def test_make_store_memory_default():
    assert isinstance(make_store(SamlSettings(**_BASE, session_secret="x")), MemoryStore)


def test_make_backend_cookie_default():
    s = SamlSettings(**_BASE, session_secret="x")
    assert isinstance(make_backend(s, make_store(s)), CookieBackend)


def test_make_backend_jwt():
    s = SamlSettings(**_BASE, session_secret="s" * 40, backend="jwt")
    assert isinstance(make_backend(s, make_store(s)), JWTBackend)
