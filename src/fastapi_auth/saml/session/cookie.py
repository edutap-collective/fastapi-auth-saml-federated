"""Signed-cookie session backend (server-side session in a store).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings

_SALT = "fastapi-auth-saml-session"


class CookieBackend:
    """Server-side session addressed by a signed session id in a cookie."""

    def __init__(self, settings: SamlSettings, store: MemoryStore) -> None:
        """Initialize the cookie-based session backend.

        Args:
            settings: SAML settings including session secret and cookie configuration.
            store: Session store for persisting identity data.
        """
        self._settings = settings
        self._store = store
        self._serializer = URLSafeTimedSerializer(settings.session_secret, salt=_SALT)

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        """Create and set a new signed session cookie.

        Args:
            identity: The federated identity to store in the session.
            response: The response object to set the cookie on.
        """
        sid = secrets.token_urlsafe(32)
        await self._store.save_session(sid, identity)
        response.set_cookie(
            self._settings.session_cookie_name,
            self._serializer.dumps(sid),
            max_age=self._settings.session_ttl,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    async def load(self, request: Request) -> FederatedIdentity | None:
        """Load a session identity from a signed cookie, or None if invalid/missing.

        Args:
            request: The HTTP request to read the cookie from.

        Returns:
            The federated identity if the cookie is valid and signed correctly, None otherwise.
        """
        sid = self._read_sid(request)
        if sid is None:
            return None
        return await self._store.load_session(sid)

    async def revoke(self, request: Request, response: Response) -> None:
        """Revoke a session by removing it from the store and deleting the cookie.

        Args:
            request: The HTTP request to read the session cookie from.
            response: The response object to delete the cookie on.
        """
        sid = self._read_sid(request)
        if sid is not None:
            await self._store.delete_session(sid)
        response.delete_cookie(self._settings.session_cookie_name)

    def _read_sid(self, request: Request) -> str | None:
        """Read and deserialize the session ID from the request's signed cookie.

        Returns None if the cookie is missing, invalid, expired, or tampered with.

        Args:
            request: The HTTP request to read the cookie from.

        Returns:
            The session ID if valid, None if missing/invalid/expired.
        """
        raw = request.cookies.get(self._settings.session_cookie_name)
        if not raw:
            return None
        try:
            return self._serializer.loads(raw, max_age=self._settings.session_ttl)
        except (BadSignature, SignatureExpired):
            return None
