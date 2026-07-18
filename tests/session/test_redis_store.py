"""Tests for RedisStore using fakeredis (no real server)."""

import fakeredis.aioredis
import pytest

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.redis_store import RedisStore


@pytest.fixture
def store():
    return RedisStore(fakeredis.aioredis.FakeRedis())


async def test_session_roundtrip(store):
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), ttl=300)
    loaded = await store.load_session("s1")
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"
    assert loaded.mail == ["u@lmu.de"]


async def test_missing_session(store):
    assert await store.load_session("nope") is None


async def test_delete_session(store):
    await store.save_session("s1", FederatedIdentity(), ttl=300)
    await store.delete_session("s1")
    assert await store.load_session("s1") is None


async def test_outstanding_roundtrip_and_pop(store):
    await store.add_outstanding("r1", "/app", ttl=300)
    await store.add_outstanding("r2", "/other", ttl=300)
    assert await store.outstanding() == {"r1": "/app", "r2": "/other"}
    assert await store.pop_outstanding("r1") == "/app"
    assert await store.outstanding() == {"r2": "/other"}
    assert await store.pop_outstanding("gone") is None
