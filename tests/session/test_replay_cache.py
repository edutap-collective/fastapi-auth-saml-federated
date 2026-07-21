"""Tests for the assertion-replay cache (Store.seen_assertion) across all backends."""

import fakeredis.aioredis
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_auth.saml.session.postgres_store import PostgresStore
from fastapi_auth.saml.session.redis_store import RedisStore
from fastapi_auth.saml.session.store import MemoryStore


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def memory_store():
    return MemoryStore()


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


@pytest.fixture(params=["memory_store", "redis_store", "postgres_store"])
def store(request):
    return request.getfixturevalue(request.param)


async def test_new_assertion_is_not_a_replay(store):
    assert await store.seen_assertion("a1", 300) is False


async def test_repeated_assertion_is_a_replay(store):
    assert await store.seen_assertion("a1", 300) is False
    assert await store.seen_assertion("a1", 300) is True


async def test_different_assertion_id_is_not_a_replay(store):
    assert await store.seen_assertion("a1", 300) is False
    assert await store.seen_assertion("a2", 300) is False


async def test_memory_store_forgets_after_ttl_expires():
    clock = _Clock()
    store = MemoryStore(clock=clock)
    assert await store.seen_assertion("a1", 100) is False
    clock.t = 101.0
    assert await store.seen_assertion("a1", 100) is False
