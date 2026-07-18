"""In-memory session and outstanding-request store (single process).

Milestone 2 default. Redis/Postgres backends arrive in Plan 3.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.saml.identity.model import FederatedIdentity


class MemoryStore:
    """Non-persistent store for sessions and outstanding AuthnRequests."""

    def __init__(self) -> None:
        """Initialize an empty session and outstanding-request store."""
        self._sessions: dict[str, FederatedIdentity] = {}
        self._outstanding: dict[str, tuple[str, float]] = {}

    async def save_session(self, sid: str, identity: FederatedIdentity) -> None:
        """Save a session with its associated identity."""
        self._sessions[sid] = identity

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found."""
        return self._sessions.get(sid)

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        self._sessions.pop(sid, None)

    async def add_outstanding(self, request_id: str, return_url: str, now: float) -> None:
        """Add an outstanding AuthnRequest with its return URL and creation timestamp."""
        self._outstanding[request_id] = (return_url, now)

    async def outstanding(self) -> dict[str, str]:
        """Return a copy of all outstanding AuthnRequests as {request_id: return_url}."""
        return {rid: url for rid, (url, _created) in self._outstanding.items()}

    async def pop_outstanding(self, request_id: str) -> str | None:
        """Remove and return the return_url for an outstanding AuthnRequest, or None."""
        entry = self._outstanding.pop(request_id, None)
        return entry[0] if entry is not None else None

    async def purge_expired(self, ttl_seconds: int, now: float) -> None:
        """Drop outstanding AuthnRequests older than ``ttl_seconds`` (caller supplies ``now``)."""
        expired = [
            rid for rid, (_url, created) in self._outstanding.items() if now - created > ttl_seconds
        ]
        for rid in expired:
            self._outstanding.pop(rid, None)
