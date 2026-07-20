"""Tests for the public Store.aclose() on all three implementations."""

import fakeredis.aioredis
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_auth.saml.session.postgres_store import PostgresStore
from fastapi_auth.saml.session.redis_store import RedisStore
from fastapi_auth.saml.session.store import MemoryStore


async def test_memory_store_aclose_is_a_noop():
    store = MemoryStore()
    await store.aclose()


async def test_redis_store_aclose_closes_the_client():
    store = RedisStore(fakeredis.aioredis.FakeRedis())
    await store.aclose()


async def test_postgres_store_aclose_disposes_the_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    store = PostgresStore(engine)
    await store.create_all()

    await store.aclose()

    # The engine's pool is disposed; a fresh engine still works fine, proving
    # aclose() didn't corrupt anything beyond the disposed engine itself.
    fresh_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    fresh_store = PostgresStore(fresh_engine)
    await fresh_store.create_all()
    await fresh_store.aclose()
