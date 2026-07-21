"""Build the pysaml2 SP configuration and load IdP metadata.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

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


def build_metadata_config(settings: SamlSettings) -> dict[str, Any]:
    """Return the pysaml2 ``metadata`` dict for the configured metadata source.

    - ``direct``: inline IdP metadata XML, loaded via :func:`load_idp_metadata`
      (the original single-IdP behavior).
    - ``aggregate`` with ``aggregate_file``: a local federation aggregate file.
    - ``aggregate`` with ``aggregate_url``: a remote federation aggregate,
      verified against ``trust_anchor_cert``.
    - ``mdq``: a Metadata Query Protocol endpoint, verified against
      ``trust_anchor_cert``.
    """
    if settings.metadata_source == "aggregate":
        if settings.aggregate_file:
            return {"local": [settings.aggregate_file]}
        return {"remote": [{"url": settings.aggregate_url, "cert": settings.trust_anchor_cert}]}
    if settings.metadata_source == "mdq":
        return {"mdq": [{"url": settings.mdq_url, "cert": settings.trust_anchor_cert}]}
    return {"inline": [load_idp_metadata(settings)]}


def build_sp_config(settings: SamlSettings) -> dict[str, Any]:
    """Assemble the pysaml2 SPConfig dict for this service provider.

    The ``service.sp`` block carries the optional GDPR/mdui profile
    (``required_attributes``/``optional_attributes``/``ui_info``), only for
    the keys that are actually set in ``settings`` -- an empty profile
    produces the same config as before this profile support was added.
    The top level always carries ``encryption_keypairs`` (so the SP can
    decrypt EncryptedAssertions) and, if configured, ``entity_category``.
    The ``metadata`` block is dispatched per ``settings.metadata_source`` by
    :func:`build_metadata_config`.
    """
    slo_url = settings.absolute_url("/slo/return")
    sp: dict[str, Any] = {
        "endpoints": {
            "assertion_consumer_service": [(settings.acs_url, BINDING_HTTP_POST)],
            "single_logout_service": [(slo_url, BINDING_HTTP_REDIRECT)],
        },
        "allow_unsolicited": settings.allow_idp_initiated,
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
        "metadata": build_metadata_config(settings),
    }
    if settings.entity_categories:
        config["entity_category"] = resolve_entity_categories(settings.entity_categories)
    return config
