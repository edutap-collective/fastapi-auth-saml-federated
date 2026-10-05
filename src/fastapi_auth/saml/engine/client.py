"""Async wrapper around a pysaml2 Saml2Client for one service provider.

pysaml2 is synchronous; every blocking call runs in a worker thread.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import anyio.to_thread
from pydantic import BaseModel
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string

from fastapi_auth.saml.engine.authn_context import (
    RequestedAuthnContext,
    asserted_class_refs,
    check_authn_context,
)
from fastapi_auth.saml.engine.config import build_sp_config
from fastapi_auth.saml.engine.errors import SamlResponseError
from fastapi_auth.saml.engine.logout import build_logout_redirect, parse_logout_response
from fastapi_auth.saml.identity.mapper import map_attributes
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings

logger = logging.getLogger("fastapi_auth.saml")


class IdPChoice(BaseModel):
    """One identity provider offered to the user on a WAYF/discovery page."""

    entity_id: str
    display_name: str


def _extract_authn_instant(authn_info: list[Any]) -> datetime | None:
    """Best-effort extraction of the authn instant from pysaml2's authn_info.

    ``authn_info`` is a list of ``(class_ref, authn_authorities, authn_instant)``
    tuples. Defensive because pysaml2 is untyped and the shape is not
    guaranteed across versions; never raises on unexpected input.
    """
    if not authn_info:
        return None
    entry = authn_info[0]
    if not isinstance(entry, tuple) or len(entry) < 3:
        return None
    raw = entry[2]
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None
    return None


def to_identity(resp: Any) -> FederatedIdentity:
    """Map a validated pysaml2 AuthnResponse onto a FederatedIdentity.

    ``resp`` is typed ``Any`` because pysaml2 is untyped; its ``session_info()``,
    ``issuer()`` and ``assertion`` are plain dynamic attribute accesses.
    """
    info = resp.session_info()
    name_id = info.get("name_id")
    authn_info = info.get("authn_info") or []
    authn_class = authn_info[0][0] if authn_info else None
    return map_attributes(
        info.get("ava", {}),
        name_id=name_id.text if name_id is not None else None,
        name_id_format=name_id.format if name_id is not None else None,
        idp_entity_id=resp.issuer(),
        authn_instant=_extract_authn_instant(authn_info),
        authn_context_class=authn_class,
        assertion_id=resp.assertion.id if resp.assertion is not None else None,
    )


class SamlEngine:
    """Owns the pysaml2 client and exposes async SSO operations."""

    def __init__(self, settings: SamlSettings) -> None:
        """Build the pysaml2 SPConfig and client once from the given settings."""
        self._settings = settings
        self._config = SPConfig().load(build_sp_config(settings))
        self._client = Saml2Client(config=self._config)

    async def create_authn_request(
        self,
        relay_state: str,
        idp_entity_id: str | None = None,
        *,
        requested_authn_context: RequestedAuthnContext | None = None,
    ) -> tuple[str, str]:
        """Build a signed AuthnRequest; return (request_id, redirect URL).

        ``idp_entity_id`` selects the target IdP for federation discovery
        (embedded/external WAYF); it defaults to ``settings.fixed_idp_entity_id``
        for the single-IdP passthrough case.

        ``requested_authn_context`` adds a ``<samlp:RequestedAuthnContext>`` to
        this one request only. The IdP may ignore it, so pass the same object
        to :meth:`parse_response` to have the result checked.
        """
        resolved_idp = idp_entity_id or self._settings.fixed_idp_entity_id
        return await anyio.to_thread.run_sync(
            self._prepare, relay_state, resolved_idp, requested_authn_context
        )

    def _prepare(
        self,
        relay_state: str,
        idp_entity_id: str,
        requested_authn_context: RequestedAuthnContext | None = None,
    ) -> tuple[str, str]:
        extra: dict[str, Any] = {}
        if requested_authn_context is not None:
            extra["requested_authn_context"] = requested_authn_context.to_saml()
        reqid, info = self._client.prepare_for_authenticate(
            entityid=idp_entity_id,
            relay_state=relay_state,
            binding=BINDING_HTTP_REDIRECT,
            sign=self._settings.authn_requests_signed,
            **extra,
        )
        location = dict(info["headers"])["Location"]
        return reqid, location

    async def parse_response(
        self,
        saml_response: str,
        outstanding: dict[str, str],
        *,
        requested_authn_context: RequestedAuthnContext | None = None,
    ) -> tuple[FederatedIdentity, str]:
        """Validate a base64 SAML response; return (identity, in_response_to).

        Raises :class:`SamlResponseError` for an invalid response. With
        ``requested_authn_context``, a valid response whose
        ``AuthnContextClassRef`` does not satisfy it raises
        :class:`~fastapi_auth.saml.engine.authn_context.AuthnContextError`.
        """
        return await anyio.to_thread.run_sync(
            self._parse, saml_response, outstanding, requested_authn_context
        )

    def _parse(
        self,
        saml_response: str,
        outstanding: dict[str, str],
        requested_authn_context: RequestedAuthnContext | None,
    ) -> tuple[FederatedIdentity, str]:
        try:
            resp = self._client.parse_authn_request_response(
                saml_response, BINDING_HTTP_POST, outstanding=outstanding
            )
        except Exception as err:  # pysaml2 raises many types on bad/forged input
            logger.warning("SAML response parse/validation failed: %s", err)
            raise SamlResponseError(str(err)) from err
        if resp is None:
            raise SamlResponseError("SAML response could not be parsed")
        if requested_authn_context is not None:
            check_authn_context(requested_authn_context, asserted_class_refs(resp.assertion))
        in_response_to = resp.in_response_to or ""  # pysaml2 untyped
        return to_identity(resp), in_response_to

    async def create_logout_redirect(self, identity: FederatedIdentity) -> str | None:
        """Best-effort: build a signed LogoutRequest redirect URL for ``identity``'s IdP.

        Returns ``None`` (never raises) if ``identity.name_id`` is missing, the
        IdP advertises no Single Logout Service, or pysaml2 fails to build the
        request for any other reason -- SLO is best-effort, local logout must
        never depend on it.
        """
        return await anyio.to_thread.run_sync(
            build_logout_redirect, self._client, self._settings, identity
        )

    async def handle_logout_response(
        self, saml_response: str, binding: str = BINDING_HTTP_REDIRECT
    ) -> bool:
        """Best-effort: parse a LogoutResponse the IdP sent back after SLO.

        Returns whether the response parsed; never raises.
        """
        return await anyio.to_thread.run_sync(
            parse_logout_response, self._client, saml_response, binding
        )

    def sp_metadata(self) -> str:
        """Return this SP's metadata XML."""
        return create_metadata_string(None, config=self._config, sign=False).decode()

    def list_idps(self, langpref: str | None = None) -> list[IdPChoice]:
        """Enumerate the IdPs known from the configured federation metadata.

        Used to render a WAYF ("Where Are You From") discovery page for
        ``discovery_mode="embedded"``. One :class:`IdPChoice` per entity found
        by pysaml2's ``identity_providers()``, with a human-readable
        ``display_name`` resolved defensively (see :meth:`_idp_display_name`).
        """
        mds = self._client.config.metadata  # pysaml2 untyped: saml2.mdstore.MetadataStore
        return [
            IdPChoice(entity_id=entity_id, display_name=self._idp_display_name(entity_id, langpref))
            for entity_id in mds.identity_providers()
        ]

    def _idp_display_name(self, entity_id: str, langpref: str | None) -> str:
        """Best-effort human-readable name for an IdP entity ID.

        Preference order: MDUI ``UIInfo/DisplayName`` (localized, first match),
        then the organization display name, then the entity ID itself. Both
        pysaml2 lookups are defensive: MDUI values may be empty/None for
        entities that publish no such metadata.
        """
        mds = self._client.config.metadata  # pysaml2 untyped: saml2.mdstore.MetadataStore
        mdui_names = [name for name in mds.mdui_uiinfo_display_name(entity_id, langpref) if name]
        if mdui_names:
            return str(mdui_names[0])
        org_name = mds.name(entity_id, langpref or "en")
        if org_name:
            return str(org_name)
        return entity_id
