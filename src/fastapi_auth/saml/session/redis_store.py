"""Redis-backed Store (redis.asyncio, native key TTL).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Any

from fastapi_auth.saml.identity.model import FederatedIdentity


class RedisStore:
    """Store backed by Redis; sessions/outstanding are keys with native TTL."""

    def __init__(
        self,
        client: Any,
        *,
        session_prefix: str = "fa:sess:",
        outstanding_prefix: str = "fa:out:",
        seen_assertion_prefix: str = "fa:seen:",
    ) -> None:
        """Wrap an existing ``redis.asyncio.Redis``-compatible client."""
        self._r = client
        self._sp = session_prefix
        self._op = outstanding_prefix
        self._ap = seen_assertion_prefix

    @classmethod
    def from_url(cls, url: str) -> RedisStore:
        """Build a RedisStore from a redis:// URL, lazily importing redis.asyncio."""
        try:
            import redis.asyncio as redis_async
        except ModuleNotFoundError as err:  # pragma: no cover - import guard
            msg = (
                "RedisStore requires the 'redis' extra: "
                "pip install 'fastapi-auth-saml-federated[redis]'"
            )
            raise RuntimeError(msg) from err
        return cls(redis_async.from_url(url))

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        await self._r.set(f"{self._sp}{sid}", identity.model_dump_json(), ex=ttl)

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        raw = await self._r.get(f"{self._sp}{sid}")
        if raw is None:
            return None
        return FederatedIdentity.model_validate_json(raw)

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        await self._r.delete(f"{self._sp}{sid}")

    async def add_outstanding(self, request_id: str, return_url: str, ttl: int) -> None:
        """Add an outstanding AuthnRequest, expiring after ``ttl`` seconds."""
        await self._r.set(f"{self._op}{request_id}", return_url, ex=ttl)

    async def outstanding(self) -> dict[str, str]:
        """Return all non-expired outstanding AuthnRequests as {request_id: return_url}."""
        result: dict[str, str] = {}
        async for key in self._r.scan_iter(match=f"{self._op}*"):
            rid = (key.decode() if isinstance(key, bytes) else key)[len(self._op) :]
            value = await self._r.get(key)
            if value is not None:
                result[rid] = value.decode() if isinstance(value, bytes) else value
        return result

    async def pop_outstanding(self, request_id: str) -> str | None:
        """Atomically remove and return the return_url for an outstanding AuthnRequest.

        Uses GETDEL (Redis 6.2+) so the get-and-remove happens as a single
        server-side operation, avoiding a race where two workers could both
        observe the same outstanding request_id.
        """
        value = await self._r.getdel(f"{self._op}{request_id}")
        if value is None:
            return None
        return value.decode() if isinstance(value, bytes) else value

    async def seen_assertion(self, assertion_id: str, ttl: int) -> bool:
        """Atomically check-and-record an assertion ID for replay detection.

        Returns True if ``assertion_id`` was already seen within the ``ttl``
        window (a replay). Otherwise records it for ``ttl`` seconds and
        returns False.

        Uses ``SET NX EX`` so the check-and-set is a single atomic Redis
        operation: the key is only written if it doesn't already exist, and
        the return value tells us which case happened.
        """
        was_set = await self._r.set(f"{self._ap}{assertion_id}", "1", nx=True, ex=ttl)
        return not was_set

    async def aclose(self) -> None:
        """Close the wrapped Redis client, releasing its connection pool."""
        await self._r.aclose()
