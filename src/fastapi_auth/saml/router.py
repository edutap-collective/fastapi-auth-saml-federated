"""FastAPI router factory for the SAML SP endpoints.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from fastapi_auth.saml.discovery.embedded import render_wayf
from fastapi_auth.saml.discovery.external import ds_redirect_url, parse_ds_return
from fastapi_auth.saml.engine.enforcement import check_required_attributes
from fastapi_auth.saml.engine.errors import AttributeReleaseError, SamlResponseError
from fastapi_auth.saml.redirect import is_safe_redirect

if TYPE_CHECKING:
    from fastapi_auth.saml.sp import SamlSP

_METADATA_MEDIA_TYPE = "application/samlmetadata+xml"
_WAYF_LOGIN_PATH = "/saml/login"

logger = logging.getLogger("fastapi_auth.saml")


async def _start_login(sp: SamlSP, next_url: str, idp_entity_id: str | None) -> RedirectResponse:
    """Issue an AuthnRequest to ``idp_entity_id`` (or the fixed IdP) and redirect the browser."""
    request_id, location = await sp.engine.create_authn_request(
        relay_state=next_url, idp_entity_id=idp_entity_id
    )
    await sp.store.add_outstanding(request_id, next_url, sp.settings.outstanding_ttl)
    return RedirectResponse(location, status_code=303)


def build_router(sp: SamlSP) -> APIRouter:
    """Build the /login, /acs, /metadata and /disco routes bound to this SamlSP."""
    router = APIRouter()

    @router.get("/login")
    async def login(next: str = "/", idp: str | None = None) -> Response:
        safe_next = is_safe_redirect(next, sp.settings.allowed_redirect_hosts)

        # WAYF selection (embedded page or manual `?idp=`) always wins, regardless of mode.
        if idp is not None:
            return await _start_login(sp, safe_next, idp)

        if sp.settings.discovery_mode == "external":
            ds_url = sp.settings.ds_url
            if ds_url is None:  # pragma: no cover - settings validator guarantees this
                msg = "discovery_mode='external' requires ds_url"
                raise HTTPException(status_code=500, detail=msg)
            return_url = (
                f"{sp.settings.base_url.rstrip('/')}/saml/disco?{urlencode({'next': safe_next})}"
            )
            return RedirectResponse(
                ds_redirect_url(ds_url, sp.settings.entity_id, return_url), status_code=303
            )

        if sp.settings.discovery_mode == "embedded":
            idps = sp.engine.list_idps(sp.settings.metadata_langpref)
            html = render_wayf(idps, _WAYF_LOGIN_PATH, safe_next, sp._jinja)
            return Response(html, media_type="text/html")

        # passthrough: fixed IdP, straight to AuthnRequest.
        return await _start_login(sp, safe_next, None)

    @router.get("/disco")
    async def disco(request: Request, next: str = "/") -> RedirectResponse:
        safe_next = is_safe_redirect(next, sp.settings.allowed_redirect_hosts)
        entity_id = parse_ds_return(request.query_params)
        if entity_id is None:
            raise HTTPException(status_code=400, detail="Discovery Service did not return entityID")
        return await _start_login(sp, safe_next, entity_id)

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
