"""In-memory Store + Store protocol (ttl-based, injectable clock, lazy expiry).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from fastapi_auth.saml.identity.model import FederatedIdentity


class Store(Protocol):
    """Session + outstanding-request storage backend."""

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        ...

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        ...

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        ...

    async def add_outstanding(self, request_id: str, return_url: str, ttl: int) -> None:
        """Add an outstanding AuthnRequest, expiring after ``ttl`` seconds."""
        ...

    async def outstanding(self) -> dict[str, str]:
        """Return all non-expired outstanding AuthnRequests as {request_id: return_url}."""
        ...

    async def pop_outstanding(self, request_id: str) -> str | None:
        """Remove and return the return_url for an outstanding AuthnRequest, or None."""
        ...

    async def seen_assertion(self, assertion_id: str, ttl: int) -> bool:
        """Atomically check-and-record an assertion ID for replay detection.

        Returns True if ``assertion_id`` was already seen within the ``ttl``
        window (a replay). Otherwise records it for ``ttl`` seconds and
        returns False.
        """
        ...

    async def aclose(self) -> None:
        """Release any resources held by the store (connections, pools, ...)."""
        ...


class MemoryStore:
    """Non-persistent Store (single process) with lazy TTL expiry."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Initialize an empty store using the given clock for TTL expiry."""
        self._clock = clock
        self._sessions: dict[str, tuple[FederatedIdentity, float]] = {}
        self._outstanding: dict[str, tuple[str, float]] = {}
        self._seen_assertions: dict[str, float] = {}

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        self._sessions[sid] = (identity, self._clock() + ttl)

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        item = self._sessions.get(sid)
        if item is None:
            return None
        identity, expires_at = item
        if self._clock() > expires_at:
            self._sessions.pop(sid, None)
            return None
        return identity

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        self._sessions.pop(sid, None)

    async def add_outstanding(self, request_id: str, return_url: str, ttl: int) -> None:
        """Add an outstanding AuthnRequest, expiring after ``ttl`` seconds."""
        self._outstanding[request_id] = (return_url, self._clock() + ttl)

    async def outstanding(self) -> dict[str, str]:
        """Return a copy of all non-expired outstanding AuthnRequests, dropping expired ones."""
        now = self._clock()
        live = {rid: url for rid, (url, exp) in self._outstanding.items() if now <= exp}
        self._outstanding = {rid: self._outstanding[rid] for rid in live}
        return live

    async def pop_outstanding(self, request_id: str) -> str | None:
        """Remove and return the return_url for an outstanding AuthnRequest.

        Returns None if the request ID is missing or has expired.
        """
        item = self._outstanding.pop(request_id, None)
        if item is None:
            return None
        url, expires_at = item
        return url if self._clock() <= expires_at else None

    async def seen_assertion(self, assertion_id: str, ttl: int) -> bool:
        """Atomically check-and-record an assertion ID for replay detection.

        Returns True if ``assertion_id`` was already seen within the ``ttl``
        window (a replay). Otherwise records it for ``ttl`` seconds and
        returns False.
        """
        expires_at = self._seen_assertions.get(assertion_id)
        if expires_at is not None and self._clock() <= expires_at:
            return True
        self._seen_assertions[assertion_id] = self._clock() + ttl
        return False

    async def aclose(self) -> None:
        """No-op: MemoryStore holds no external resources to release."""
