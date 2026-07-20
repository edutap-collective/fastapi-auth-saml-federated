"""Integration: RedisStore + PostgresStore against live services (make test-integration)."""

import os

import pytest

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.postgres_store import PostgresStore
from fastapi_auth.saml.session.redis_store import RedisStore

pytestmark = pytest.mark.integration

_REDIS = os.environ.get("IT_REDIS_URL", "redis://localhost:6379/0")
_DB = os.environ.get("IT_DB_URL", "postgresql+asyncpg://postgres:pw@localhost:5432/fa")


async def test_redis_store_roundtrip_live():
    store = RedisStore.from_url(_REDIS)
    try:
        await store.save_session(
            "s1", FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), ttl=300
        )
        loaded = await store.load_session("s1")
        assert loaded is not None and loaded.eppn == "u@lmu.de" and loaded.mail == ["u@lmu.de"]
        await store.add_outstanding("r1", "/app", ttl=300)
        assert await store.outstanding() == {"r1": "/app"}
        assert await store.pop_outstanding("r1") == "/app"
    finally:
        # RedisStore has no public close(); reach into the wrapped client to avoid
        # leaking the connection into a ResourceWarning (promoted to an error by
        # filterwarnings = ["error", ...] in pyproject.toml).
        await store._r.aclose()  # noqa: SLF001


async def test_postgres_store_roundtrip_live():
    store = PostgresStore.from_url(_DB)
    try:
        await store.create_all()
        await store.save_session("s1", FederatedIdentity(eppn="p@lmu.de"), ttl=300)
        loaded = await store.load_session("s1")
        assert loaded is not None and loaded.eppn == "p@lmu.de"
        await store.add_outstanding("r1", "/app", ttl=300)
        assert await store.outstanding() == {"r1": "/app"}
        assert await store.pop_outstanding("r1") == "/app"
    finally:
        # Same rationale as above: dispose the pooled asyncpg connections
        # explicitly instead of relying on GC (which trips filterwarnings=error).
        await store._engine.dispose()  # noqa: SLF001
