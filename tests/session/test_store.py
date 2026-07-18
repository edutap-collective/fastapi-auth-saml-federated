"""Tests for the in-memory session + outstanding-request store."""

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.store import MemoryStore


async def test_save_and_load_session():
    store = MemoryStore()
    ident = FederatedIdentity(eppn="u@lmu.de")
    await store.save_session("sid-1", ident)
    loaded = await store.load_session("sid-1")
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_load_missing_session_returns_none():
    store = MemoryStore()
    assert await store.load_session("nope") is None


async def test_delete_session():
    store = MemoryStore()
    await store.save_session("sid-1", FederatedIdentity())
    await store.delete_session("sid-1")
    assert await store.load_session("sid-1") is None


async def test_outstanding_roundtrip():
    store = MemoryStore()
    await store.add_outstanding("req-1", "/app", 0.0)
    await store.add_outstanding("req-2", "/other", 0.0)
    assert await store.outstanding() == {"req-1": "/app", "req-2": "/other"}
    assert await store.pop_outstanding("req-1") == "/app"
    assert await store.outstanding() == {"req-2": "/other"}
    assert await store.pop_outstanding("gone") is None


async def test_purge_expired_drops_old_entries_and_keeps_fresh_ones():
    store = MemoryStore()
    await store.add_outstanding("old", "/old", 0.0)
    await store.add_outstanding("fresh", "/fresh", 100.0)
    await store.purge_expired(ttl_seconds=60, now=100.0)
    assert await store.outstanding() == {"fresh": "/fresh"}
