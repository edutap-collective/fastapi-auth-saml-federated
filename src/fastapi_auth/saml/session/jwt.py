"""Stateless JWT session backend (PyJWT).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time

import jwt
from fastapi import Request, Response

from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings


class JWTBackend:
    """Carries the identity in a signed JWT (cookie or Authorization: Bearer).

    The default ``jwt_alg`` (``HS256``) is a symmetric algorithm: anyone who can
    verify the token can also mint one. An asymmetric algorithm (e.g. RS256,
    EdDSA) with a separate signing/verification key pair would be needed to
    let other services verify tokens without being able to forge them; that is
    not implemented here.

    The token is signed, not encrypted: it carries the full identity
    (``attrs``) in plaintext, readable by whoever holds it. For
    attribute-rich identities this can approach the ~4 KB size limit typical
    for browser cookies.
    """

    def __init__(self, settings: SamlSettings) -> None:
        """Initialize the JWT backend with the given settings."""
        self._settings = settings

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        """Sign the identity into a JWT and set it as the session cookie."""
        subject = select_identifier(
            identity, self._settings.identifier, self._settings.identifier_fallback
        )
        payload = {
            "sub": subject or identity.name_id or "",
            "exp": int(time.time()) + self._settings.jwt_ttl,
            "attrs": identity.model_dump(mode="json"),
        }
        token = jwt.encode(
            payload, self._settings.jwt_signing_secret, algorithm=self._settings.jwt_alg
        )
        response.set_cookie(
            self._settings.session_cookie_name,
            token,
            max_age=self._settings.jwt_ttl,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    async def load(self, request: Request) -> FederatedIdentity | None:
        """Read and verify the JWT from the cookie or Bearer header, or None if invalid."""
        token = self._token_from(request)
        if token is None:
            return None
        try:
            payload = jwt.decode(
                token, self._settings.jwt_signing_secret, algorithms=[self._settings.jwt_alg]
            )
        except jwt.InvalidTokenError:
            return None
        return FederatedIdentity.model_validate(payload.get("attrs", {}))

    async def revoke(self, request: Request, response: Response) -> None:
        """Delete the session cookie (stateless: no server-side invalidation)."""
        response.delete_cookie(self._settings.session_cookie_name)

    def _token_from(self, request: Request) -> str | None:
        """Return the JWT from the Authorization header or the session cookie, if present."""
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:]
        return request.cookies.get(self._settings.session_cookie_name)
