"""Logout CSRF token, bound to the session cookie.

The token is an HMAC of the raw session cookie value under the SP's
``session_secret``. A cross-site page can neither read the cookie nor the
token, so it cannot forge a valid logout POST; a token obtained for one
session is useless for any other. Nothing is stored server-side.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import base64
import hashlib
import hmac

_LABEL = b"fastapi-auth-saml/logout-csrf\x00"


def logout_csrf_token(secret: str, session_cookie: str) -> str:
    """Return the logout CSRF token for one session cookie value."""
    digest = hmac.new(secret.encode(), _LABEL + session_cookie.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_logout_csrf_token(secret: str, session_cookie: str, token: str | None) -> bool:
    """Return whether ``token`` is the logout CSRF token for ``session_cookie`` (constant time)."""
    if not token:
        return False
    # Compare bytes: compare_digest raises TypeError for non-ASCII str input.
    expected = logout_csrf_token(secret, session_cookie).encode()
    return hmac.compare_digest(expected, token.encode())
