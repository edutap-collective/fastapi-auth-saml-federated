"""Tests for PostgresStore against in-memory SQLite (aiosqlite)."""

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.postgres_store import PostgresStore


@pytest.fixture
async def store():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    s = PostgresStore(engine)
    await s.create_all()
    yield s
    await engine.dispose()


async def test_session_roundtrip(store):
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de"), ttl=300)
    loaded = await store.load_session("s1")
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_delete_session(store):
    await store.save_session("s1", FederatedIdentity(), ttl=300)
    await store.delete_session("s1")
    assert await store.load_session("s1") is None


async def test_expired_session_is_absent(store):
    await store.save_session("s1", FederatedIdentity(), ttl=-1)  # already expired
    assert await store.load_session("s1") is None


async def test_outstanding_roundtrip_and_pop(store):
    await store.add_outstanding("r1", "/app", ttl=300)
    assert await store.outstanding() == {"r1": "/app"}
    assert await store.pop_outstanding("r1") == "/app"
    assert await store.pop_outstanding("r1") is None
