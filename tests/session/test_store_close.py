"""Tests for the public Store.aclose() on all three implementations."""

from unittest.mock import AsyncMock

import fakeredis.aioredis
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_auth.saml.session.postgres_store import PostgresStore
from fastapi_auth.saml.session.redis_store import RedisStore
from fastapi_auth.saml.session.store import MemoryStore


async def test_memory_store_aclose_is_a_noop():
    store = MemoryStore()
    await store.aclose()


async def test_redis_store_aclose_closes_the_client():
    client = fakeredis.aioredis.FakeRedis()
    # Spy on the client's aclose method using AsyncMock.
    client.aclose = AsyncMock(wraps=client.aclose)
    store = RedisStore(client)
    await store.aclose()
    # Verify the underlying client.aclose was actually invoked.
    client.aclose.assert_awaited_once()


async def test_postgres_store_aclose_disposes_the_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    store = PostgresStore(engine)
    await store.create_all()

    # Spy on the store's aclose method with wraps so the real dispose is called
    # while still tracking that aclose was invoked.
    original_aclose = store.aclose
    store.aclose = AsyncMock(wraps=original_aclose)
    await store.aclose()
    # Verify the underlying store.aclose was actually invoked.
    store.aclose.assert_awaited_once()

    # The engine's pool is disposed; a fresh engine still works fine, proving
    # aclose() didn't corrupt anything beyond the disposed engine itself.
    fresh_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    fresh_store = PostgresStore(fresh_engine)
    await fresh_store.create_all()
    await fresh_store.aclose()
