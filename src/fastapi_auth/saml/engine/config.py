"""Build the pysaml2 SP configuration and load IdP metadata.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from saml2 import BINDING_HTTP_POST

from fastapi_auth.saml.engine.entity_categories import resolve_entity_categories
from fastapi_auth.saml.settings import SamlSettings


def load_idp_metadata(settings: SamlSettings) -> str:
    """Return the IdP metadata XML from the configured direct source.

    Exactly one of ``idp_metadata_file`` / ``idp_metadata_url`` must be set.
    The HTTP fetch is synchronous; it runs at ``SamlEngine.__init__`` time
    (application startup), not on the async request path.
    """
    if settings.idp_metadata_file:
        return Path(settings.idp_metadata_file).read_text(encoding="utf-8")
    if settings.idp_metadata_url:
        resp = httpx.get(settings.idp_metadata_url, timeout=httpx.Timeout(10.0, connect=5.0))
        resp.raise_for_status()
        return resp.text
    msg = "No IdP metadata source configured (set idp_metadata_file or idp_metadata_url)"
    raise ValueError(msg)


def build_sp_config(settings: SamlSettings) -> dict[str, Any]:
    """Assemble the pysaml2 SPConfig dict for this service provider.

    The ``service.sp`` block carries the optional GDPR/mdui profile
    (``required_attributes``/``optional_attributes``/``ui_info``), only for
    the keys that are actually set in ``settings`` -- an empty profile
    produces the same config as before this profile support was added.
    The top level always carries ``encryption_keypairs`` (so the SP can
    decrypt EncryptedAssertions) and, if configured, ``entity_category``.
    """
    idp_metadata = load_idp_metadata(settings)

    sp: dict[str, Any] = {
        "endpoints": {
            "assertion_consumer_service": [(settings.acs_url, BINDING_HTTP_POST)],
        },
        "allow_unsolicited": False,
        "authn_requests_signed": settings.authn_requests_signed,
        "want_assertions_signed": settings.want_assertions_signed,
        "want_response_signed": False,
    }
    if settings.required_attributes:
        sp["required_attributes"] = settings.required_attributes
    if settings.optional_attributes:
        sp["optional_attributes"] = settings.optional_attributes

    ui_info: dict[str, str] = {}
    if settings.sp_display_name:
        ui_info["display_name"] = settings.sp_display_name
    if settings.sp_description:
        ui_info["description"] = settings.sp_description
    if settings.privacy_statement_url:
        ui_info["privacy_statement_url"] = settings.privacy_statement_url
    if ui_info:
        sp["ui_info"] = ui_info

    config: dict[str, Any] = {
        "entityid": settings.entity_id,
        "xmlsec_binary": settings.xmlsec_binary,
        "allow_unknown_attributes": True,
        "service": {"sp": sp},
        "key_file": settings.key_file,
        "cert_file": settings.cert_file,
        "encryption_keypairs": [
            {"key_file": settings.enc_key_file, "cert_file": settings.enc_cert_file}
        ],
        "metadata": {"inline": [idp_metadata]},
    }
    if settings.entity_categories:
        config["entity_category"] = resolve_entity_categories(settings.entity_categories)
    return config
