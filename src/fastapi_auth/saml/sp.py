"""SamlSP facade: wires settings, engine, store, session backend and router.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import HTTPException, Request, status
from jinja2 import Environment, FileSystemLoader, select_autoescape

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.factory import make_backend, make_store
from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.router import build_router
from fastapi_auth.saml.settings import SamlSettings

_WAYF_TEMPLATES_DIR = Path(__file__).parent / "wayf" / "templates"


class SamlSP:
    """Composition root: one configured SAML service provider."""

    def __init__(self, settings: SamlSettings) -> None:
        """Build the engine, store, session backend, WAYF renderer and router from settings."""
        self.settings = settings
        self.engine = SamlEngine(settings)
        self.store = make_store(settings)
        self.backend = make_backend(settings, self.store)
        # autoescape MUST stay on: the embedded WAYF page renders untrusted
        # display names/entity IDs sourced from federation metadata.
        self._jinja = Environment(
            loader=FileSystemLoader(_WAYF_TEMPLATES_DIR), autoescape=select_autoescape()
        )
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

    def identifier(self, identity: FederatedIdentity) -> str | None:
        """Return this SP's chosen stable identifier for the identity."""
        return select_identifier(
            identity, self.settings.identifier, self.settings.identifier_fallback
        )

    async def aclose(self) -> None:
        """Release the store's resources; call from a FastAPI lifespan shutdown."""
        await self.store.aclose()


__all__ = ["SamlSP"]
