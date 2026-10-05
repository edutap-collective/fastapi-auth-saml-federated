"""SamlSP facade: wires settings, engine, store, session backend and router.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from jinja2 import Environment, FileSystemLoader, select_autoescape

from fastapi_auth.saml.engine.authn_context import RequestedAuthnContext
from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.factory import make_backend, make_store
from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.router import build_router
from fastapi_auth.saml.settings import SamlSettings

_WAYF_TEMPLATES_DIR = Path(__file__).parent / "wayf" / "templates"


class SamlSP:
    """Composition root: one configured SAML service provider."""

    def __init__(
        self,
        settings: SamlSettings,
        *,
        requested_authn_context: RequestedAuthnContext | None = None,
    ) -> None:
        """Build the engine, store, session backend, WAYF renderer and router from settings.

        ``requested_authn_context`` is sent with every login this SP's router
        starts, and every response at its ACS -- solicited or IdP-initiated --
        must satisfy it (otherwise ``403``). For a context that varies per
        login, mount one ``SamlSP`` per context or call
        :class:`~fastapi_auth.saml.engine.client.SamlEngine` directly.
        """
        self.settings = settings
        self.requested_authn_context = requested_authn_context
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

    def mount(self, app: FastAPI, **kwargs: Any) -> None:
        """Include this SP's router on ``app`` under ``settings.mount_path``.

        This is the recommended way to attach a SamlSP to a FastAPI app: it
        guarantees the router's prefix and ``settings.mount_path`` -- which
        every absolute SP URL (ACS, disco, WAYF login, ...) is derived from --
        can never diverge. Calling ``app.include_router(sp.router, prefix=...)``
        directly still works, but the given ``prefix`` must then match
        ``settings.mount_path`` exactly, or the router will be reachable at a
        different path than the one baked into those absolute URLs.

        ``**kwargs`` are forwarded verbatim to ``app.include_router()`` (e.g.
        ``dependencies=``, ``tags=``) for any callers that need them.
        """
        app.include_router(self.router, prefix=self.settings.mount_path, **kwargs)

    async def aclose(self) -> None:
        """Release the store's resources; call from a FastAPI lifespan shutdown."""
        await self.store.aclose()


__all__ = ["SamlSP"]
