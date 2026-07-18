"""FastAPI router factory for the SAML SP endpoints.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Form, HTTPException, Response
from fastapi.responses import RedirectResponse

from fastapi_auth.saml.engine.enforcement import check_required_attributes
from fastapi_auth.saml.engine.errors import AttributeReleaseError, SamlResponseError
from fastapi_auth.saml.redirect import is_safe_redirect

if TYPE_CHECKING:
    from fastapi_auth.saml.sp import SamlSP

_METADATA_MEDIA_TYPE = "application/samlmetadata+xml"

logger = logging.getLogger("fastapi_auth.saml")


def build_router(sp: SamlSP) -> APIRouter:
    """Build the /login, /acs and /metadata routes bound to this SamlSP."""
    router = APIRouter()

    @router.get("/login")
    async def login(next: str = "/") -> RedirectResponse:
        safe_next = is_safe_redirect(next, sp.settings.allowed_redirect_hosts)
        request_id, location = await sp.engine.create_authn_request(relay_state=safe_next)
        await sp.store.add_outstanding(request_id, safe_next, sp.settings.outstanding_ttl)
        return RedirectResponse(location, status_code=303)

    @router.post("/acs")
    async def acs(
        SAMLResponse: Annotated[str, Form()],
        RelayState: Annotated[str, Form()] = "/",
    ) -> RedirectResponse:
        outstanding = await sp.store.outstanding()
        try:
            identity, in_response_to = await sp.engine.parse_response(SAMLResponse, outstanding)
        except SamlResponseError as err:
            logger.warning("SAML response rejected at ACS: %s", err)
            raise HTTPException(status_code=400, detail="Invalid SAML response") from err
        try:
            check_required_attributes(identity, sp.settings.required_attributes)
        except AttributeReleaseError as err:
            logger.warning("Attribute release insufficient, missing: %s", err.missing)
            raise HTTPException(status_code=403, detail=str(err)) from err
        await sp.store.pop_outstanding(in_response_to)
        target = is_safe_redirect(RelayState or "/", sp.settings.allowed_redirect_hosts)
        response = RedirectResponse(target, status_code=303)
        await sp.backend.establish(identity, response)
        return response

    @router.get("/metadata")
    async def metadata() -> Response:
        return Response(sp.engine.sp_metadata(), media_type=_METADATA_MEDIA_TYPE)

    return router
