"""Tests for the in-memory Store (ttl + injectable clock, lazy expiry)."""

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.store import MemoryStore


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


async def test_session_roundtrip():
    store = MemoryStore()
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de"), ttl=300)
    loaded = await store.load_session("s1")
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_session_expires():
    clock = _Clock()
    store = MemoryStore(clock=clock)
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de"), ttl=100)
    clock.t = 101.0
    assert await store.load_session("s1") is None


async def test_delete_session():
    store = MemoryStore()
    await store.save_session("s1", FederatedIdentity(), ttl=300)
    await store.delete_session("s1")
    assert await store.load_session("s1") is None


async def test_outstanding_roundtrip_and_pop():
    store = MemoryStore()
    await store.add_outstanding("r1", "/app", ttl=300)
    await store.add_outstanding("r2", "/other", ttl=300)
    assert await store.outstanding() == {"r1": "/app", "r2": "/other"}
    assert await store.pop_outstanding("r1") == "/app"
    assert await store.outstanding() == {"r2": "/other"}
    assert await store.pop_outstanding("gone") is None


async def test_outstanding_expires():
    clock = _Clock()
    store = MemoryStore(clock=clock)
    await store.add_outstanding("r1", "/app", ttl=100)
    clock.t = 101.0
    assert await store.outstanding() == {}
    assert await store.pop_outstanding("r1") is None
