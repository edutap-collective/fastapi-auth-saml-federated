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
        self._outstanding: dict[str, str] = {}

    async def save_session(self, sid: str, identity: FederatedIdentity) -> None:
        """Save a session with its associated identity."""
        self._sessions[sid] = identity

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found."""
        return self._sessions.get(sid)

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        self._sessions.pop(sid, None)

    async def add_outstanding(self, request_id: str, return_url: str) -> None:
        """Add an outstanding AuthnRequest with its return URL."""
        self._outstanding[request_id] = return_url

    async def outstanding(self) -> dict[str, str]:
        """Return a copy of all outstanding AuthnRequests as {request_id: return_url}."""
        return dict(self._outstanding)

    async def pop_outstanding(self, request_id: str) -> str | None:
        """Remove and return the return_url for an outstanding AuthnRequest, or None."""
        return self._outstanding.pop(request_id, None)
