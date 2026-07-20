"""Tests documenting the atomic get+delete intent of pop_outstanding.

A single pop must both return the value and remove the entry in one step, so
that two workers racing on the same request_id cannot both observe it.
"""

import fakeredis.aioredis
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_auth.saml.session.postgres_store import PostgresStore
from fastapi_auth.saml.session.redis_store import RedisStore


@pytest.fixture
def redis_store():
    return RedisStore(fakeredis.aioredis.FakeRedis())


@pytest.fixture
async def postgres_store():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    s = PostgresStore(engine)
    await s.create_all()
    yield s
    await engine.dispose()


async def test_pop_outstanding_is_atomic(redis_store, postgres_store):
    for store in (redis_store, postgres_store):
        await store.add_outstanding("r", "/x", ttl=300)
        assert await store.pop_outstanding("r") == "/x"
        assert await store.pop_outstanding("r") is None


async def test_postgres_pop_outstanding_expired_returns_none(postgres_store):
    await postgres_store.add_outstanding("r", "/x", ttl=-1)
    assert await postgres_store.pop_outstanding("r") is None
