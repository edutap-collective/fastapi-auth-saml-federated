"""SessionBackend protocol.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Protocol

from fastapi import Request, Response

from fastapi_auth.saml.identity.model import FederatedIdentity


class SessionBackend(Protocol):
    """Establishes, loads and revokes a login session on a response/request."""

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        """Establish a session for the identity and write it to the response."""
        ...

    async def load(self, request: Request) -> FederatedIdentity | None:
        """Load and return the identity from the request, or None if not authenticated."""
        ...

    async def revoke(self, request: Request, response: Response) -> None:
        """Revoke the session and clear it from the response."""
        ...
