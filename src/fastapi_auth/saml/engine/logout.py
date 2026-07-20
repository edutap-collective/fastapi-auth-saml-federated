"""Best-effort SP-initiated Single Logout (SLO): build and parse LogoutRequest/-Response.

pysaml2 is synchronous and untyped; callers (:class:`~fastapi_auth.saml.engine.client.SamlEngine`)
wrap these functions in ``anyio.to_thread.run_sync``. Every function here is
best-effort: SLO must never block or fail the local session invalidation, so
any pysaml2 exception is caught and logged (never propagated).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import logging
from typing import Any

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NameID

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings

logger = logging.getLogger("fastapi_auth.saml")


def build_logout_redirect(
    client: Saml2Client, settings: SamlSettings, identity: FederatedIdentity
) -> str | None:
    """Build a signed LogoutRequest for ``identity``'s IdP; return the redirect URL.

    Best-effort: returns ``None`` instead of raising if ``identity.name_id`` or
    ``identity.idp_entity_id`` is missing, the IdP advertises no Single Logout
    Service endpoint, or pysaml2 fails to build/serialize the request for any
    other reason (e.g. ``LogoutError`` when no binding matches).
    """
    if not identity.name_id or not identity.idp_entity_id:
        return None
    try:
        name_id = NameID(
            format=identity.name_id_format or NAMEID_FORMAT_PERSISTENT, text=identity.name_id
        )
        # pysaml2 is untyped: do_logout() -> dict[entity_id, (binding, http_args)]
        # for entities it could build a request for; raises LogoutError if none.
        responses: Any = client.do_logout(
            name_id,
            [identity.idp_entity_id],
            reason="",
            expire=None,
            sign=settings.authn_requests_signed,
            expected_binding=BINDING_HTTP_REDIRECT,
        )
    except Exception as err:  # pysaml2 raises many types (incl. LogoutError); best-effort
        logger.warning("Could not build SLO LogoutRequest for %s: %s", identity.idp_entity_id, err)
        return None
    if not isinstance(responses, dict) or identity.idp_entity_id not in responses:
        return None
    _binding, http_args = responses[identity.idp_entity_id]
    location = dict(http_args.get("headers", [])).get("Location")
    return str(location) if location else None


def parse_logout_response(client: Saml2Client, saml_response: str, binding: str) -> bool:
    """Best-effort parse of a LogoutResponse from the IdP; return whether it parsed.

    Never raises: any pysaml2 failure is logged and treated as ``False``. The
    result only affects logging -- the browser is redirected home either way.
    """
    try:
        response = client.parse_logout_request_response(saml_response, binding)
    except Exception as err:  # pysaml2 raises many types on bad/forged input
        logger.warning("Could not parse SLO LogoutResponse: %s", err)
        return False
    return response is not None
