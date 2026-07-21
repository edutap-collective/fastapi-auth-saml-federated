"""FastAPI router factory for the SAML SP endpoints.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from saml2 import BINDING_HTTP_REDIRECT

from fastapi_auth.saml.discovery.embedded import render_wayf
from fastapi_auth.saml.discovery.external import ds_redirect_url, parse_ds_return
from fastapi_auth.saml.engine.enforcement import check_required_attributes
from fastapi_auth.saml.engine.errors import AttributeReleaseError, SamlResponseError
from fastapi_auth.saml.redirect import is_safe_redirect

if TYPE_CHECKING:
    from fastapi_auth.saml.sp import SamlSP

_METADATA_MEDIA_TYPE = "application/samlmetadata+xml"

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
            return_url = f"{sp.settings.absolute_url('/disco')}?{urlencode({'next': safe_next})}"
            return RedirectResponse(
                ds_redirect_url(ds_url, sp.settings.entity_id, return_url), status_code=303
            )

        if sp.settings.discovery_mode == "embedded":
            idps = sp.engine.list_idps(sp.settings.metadata_langpref)
            html = render_wayf(idps, sp.settings.wayf_login_path, safe_next, sp._jinja)
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
        RelayState: Annotated[str | None, Form()] = None,
    ) -> RedirectResponse:
        outstanding = await sp.store.outstanding()
        try:
            identity, in_response_to = await sp.engine.parse_response(SAMLResponse, outstanding)
        except SamlResponseError as err:
            logger.warning("SAML response rejected at ACS: %s", err)
            raise HTTPException(status_code=400, detail="Invalid SAML response") from err
        if in_response_to:
            # Solicited: the reqid was single-use and is now consumed, which is
            # itself the replay defense for this path (a second POST of the same
            # response has no matching outstanding request left).
            await sp.store.pop_outstanding(in_response_to)
            target = is_safe_redirect(RelayState or "/", sp.settings.allowed_redirect_hosts)
        else:
            # Unsolicited (IdP-initiated): only reachable when allow_idp_initiated
            # is True -- pysaml2 itself rejects unsolicited responses otherwise,
            # surfacing as SamlResponseError above. There is no outstanding reqid
            # to consume, so the assertion ID is replay-checked explicitly instead.
            if not identity.assertion_id or await sp.store.seen_assertion(
                identity.assertion_id, sp.settings.assertion_replay_ttl
            ):
                logger.warning("Unsolicited assertion replay or missing id")
                raise HTTPException(status_code=400, detail="Replayed or invalid assertion")
            target = is_safe_redirect(
                RelayState or sp.settings.idp_initiated_default_relay_state,
                sp.settings.allowed_redirect_hosts,
            )
        try:
            check_required_attributes(identity, sp.settings.required_attributes)
        except AttributeReleaseError as err:
            logger.warning("Attribute release insufficient, missing: %s", err.missing)
            raise HTTPException(status_code=403, detail=str(err)) from err
        response = RedirectResponse(target, status_code=303)
        await sp.backend.establish(identity, response)
        return response

    @router.get("/metadata")
    async def metadata() -> Response:
        return Response(sp.engine.sp_metadata(), media_type=_METADATA_MEDIA_TYPE)

    @router.get("/slo")
    async def slo(request: Request, next: str = "/") -> Response:
        safe_next = is_safe_redirect(next, sp.settings.allowed_redirect_hosts)
        identity = await sp.backend.load(request)

        target = safe_next
        if identity is not None:
            redirect_url = await sp.engine.create_logout_redirect(identity)
            if redirect_url is not None:
                target = redirect_url

        # The local session is ALWAYS invalidated, on the same response object
        # that is returned -- SLO towards the IdP is best-effort and must never
        # block or fail the local logout.
        response = RedirectResponse(target, status_code=303)
        await sp.backend.revoke(request, response)
        return response

    @router.get("/slo/return")
    async def slo_return(request: Request) -> RedirectResponse:
        saml_response = request.query_params.get("SAMLResponse")
        if saml_response is not None:
            try:
                await sp.engine.handle_logout_response(saml_response, BINDING_HTTP_REDIRECT)
            except Exception:  # pragma: no cover - handle_logout_response never raises
                logger.warning("Unexpected error handling SLO LogoutResponse", exc_info=True)
        return RedirectResponse("/", status_code=303)

    return router
