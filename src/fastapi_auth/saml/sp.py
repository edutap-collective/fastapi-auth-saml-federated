"""SamlSP facade: wires settings, engine, store, session backend and router.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request, status

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.router import build_router
from fastapi_auth.saml.session.cookie import CookieBackend
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings


class SamlSP:
    """Composition root: one configured SAML service provider."""

    def __init__(self, settings: SamlSettings) -> None:
        """Build the engine, store, session backend and router from settings."""
        self.settings = settings
        self.engine = SamlEngine(settings)
        self.store = MemoryStore()
        self.backend = CookieBackend(settings, self.store)
        self.router = build_router(self)

    def optional_user(self) -> Callable[[Request], Awaitable[FederatedIdentity | None]]:
        """Dependency returning the FederatedIdentity or None."""

        async def _dep(request: Request) -> FederatedIdentity | None:
            return await self.backend.load(request)

        return _dep

    def current_user(self) -> Callable[[Request], Awaitable[FederatedIdentity]]:
        """Dependency returning the FederatedIdentity or raising 401."""

        async def _dep(request: Request) -> FederatedIdentity:
            identity = await self.backend.load(request)
            if identity is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
                )
            return identity

        return _dep


__all__ = ["SamlSP"]
