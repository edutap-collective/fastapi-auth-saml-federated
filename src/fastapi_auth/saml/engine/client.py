"""Async wrapper around a pysaml2 Saml2Client for one service provider.

pysaml2 is synchronous; every blocking call runs in a worker thread.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import anyio.to_thread
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string

from fastapi_auth.saml.engine.config import build_sp_config
from fastapi_auth.saml.identity.mapper import map_attributes
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings


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

    async def create_authn_request(self, relay_state: str) -> tuple[str, str]:
        """Build a signed AuthnRequest; return (request_id, redirect URL)."""
        return await anyio.to_thread.run_sync(self._prepare, relay_state)

    def _prepare(self, relay_state: str) -> tuple[str, str]:
        reqid, info = self._client.prepare_for_authenticate(
            entityid=self._settings.fixed_idp_entity_id,
            relay_state=relay_state,
            binding=BINDING_HTTP_REDIRECT,
            sign=self._settings.authn_requests_signed,
        )
        location = dict(info["headers"])["Location"]
        return reqid, location

    async def parse_response(
        self, saml_response: str, outstanding: dict[str, str]
    ) -> FederatedIdentity:
        """Validate a base64 SAML response and map it onto a FederatedIdentity."""
        return await anyio.to_thread.run_sync(self._parse, saml_response, outstanding)

    def _parse(self, saml_response: str, outstanding: dict[str, str]) -> FederatedIdentity:
        resp = self._client.parse_authn_request_response(
            saml_response, BINDING_HTTP_POST, outstanding=outstanding
        )
        if resp is None:
            msg = "SAML response could not be parsed"
            raise ValueError(msg)
        return to_identity(resp)

    def sp_metadata(self) -> str:
        """Return this SP's metadata XML."""
        return create_metadata_string(None, config=self._config, sign=False).decode()
