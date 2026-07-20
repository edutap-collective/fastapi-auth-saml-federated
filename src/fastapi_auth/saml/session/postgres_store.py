"""Postgres-backed Store via SQLModel async (test: SQLite/aiosqlite).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel, select

from fastapi_auth.saml.identity.model import FederatedIdentity


class SamlSession(SQLModel, table=True):
    """SQLModel table for a stored session (identity JSON + expiry)."""

    sid: str = Field(primary_key=True)
    data: str
    expires_at: float


class SamlOutstanding(SQLModel, table=True):
    """SQLModel table for an outstanding AuthnRequest (return URL + expiry)."""

    request_id: str = Field(primary_key=True)
    return_url: str
    expires_at: float


class PostgresStore:
    """Store backed by an async SQLAlchemy engine (Postgres in prod, SQLite in tests)."""

    def __init__(self, engine: Any) -> None:
        """Wrap an existing async SQLAlchemy engine."""
        self._engine = engine

    @classmethod
    def from_url(cls, url: str) -> PostgresStore:
        """Build a PostgresStore from a database URL, lazily importing SQLAlchemy."""
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
        except ModuleNotFoundError as err:  # pragma: no cover - import guard
            msg = (
                "PostgresStore requires the 'postgres' extra: "
                "pip install 'fastapi-auth-saml-federated[postgres]'"
            )
            raise RuntimeError(msg) from err
        return cls(create_async_engine(url))

    async def create_all(self) -> None:
        """Create all tables (used directly in tests; migrations own this in prod)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        async with AsyncSession(self._engine) as s:
            await s.merge(
                SamlSession(sid=sid, data=identity.model_dump_json(), expires_at=time.time() + ttl)
            )
            await s.commit()

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        async with AsyncSession(self._engine) as s:
            row = await s.get(SamlSession, sid)
            if row is None:
                return None
            if row.expires_at < time.time():
                await s.delete(row)
                await s.commit()
                return None
            return FederatedIdentity.model_validate_json(row.data)

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        async with AsyncSession(self._engine) as s:
            row = await s.get(SamlSession, sid)
            if row is not None:
                await s.delete(row)
                await s.commit()

    async def add_outstanding(self, request_id: str, return_url: str, ttl: int) -> None:
        """Add an outstanding AuthnRequest, expiring after ``ttl`` seconds."""
        async with AsyncSession(self._engine) as s:
            await s.merge(
                SamlOutstanding(
                    request_id=request_id, return_url=return_url, expires_at=time.time() + ttl
                )
            )
            await s.commit()

    async def outstanding(self) -> dict[str, str]:
        """Return all non-expired outstanding AuthnRequests as {request_id: return_url}."""
        now = time.time()
        async with AsyncSession(self._engine) as s:
            await s.execute(
                delete(SamlOutstanding).where(
                    SamlOutstanding.expires_at < now  # ty: ignore[invalid-argument-type]  # SQLAlchemy instrumented-attribute comparison returns ColumnElement[bool], not bool
                )
            )
            await s.commit()
            rows = (await s.execute(select(SamlOutstanding))).scalars().all()
            return {r.request_id: r.return_url for r in rows}

    async def pop_outstanding(self, request_id: str) -> str | None:
        """Atomically remove and return the return_url for an outstanding AuthnRequest.

        Uses a single ``DELETE ... RETURNING`` statement so the row can't be
        popped twice by concurrent callers racing on the same request_id.
        """
        async with AsyncSession(self._engine) as s:
            stmt = (
                delete(SamlOutstanding)  # ty: ignore[no-matching-overload]  # SQLModel field descriptors don't satisfy SQLAlchemy's returning() overloads, though they work fine at runtime
                .where(
                    SamlOutstanding.request_id == request_id  # ty: ignore[invalid-argument-type]  # SQLAlchemy instrumented-attribute comparison returns ColumnElement[bool], not bool
                )
                .returning(SamlOutstanding.return_url, SamlOutstanding.expires_at)
            )
            result = await s.execute(stmt)
            row = result.first()
            await s.commit()
            if row is None:
                return None
            url, expires_at = row
            return url if expires_at >= time.time() else None

    async def aclose(self) -> None:
        """Dispose the wrapped engine, releasing its connection pool."""
        await self._engine.dispose()
