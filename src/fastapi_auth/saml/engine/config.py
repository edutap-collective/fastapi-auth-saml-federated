"""Build the pysaml2 SP configuration and load IdP metadata.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from saml2 import BINDING_HTTP_POST

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
    """Assemble the pysaml2 SPConfig dict for this service provider."""
    idp_metadata = load_idp_metadata(settings)
    return {
        "entityid": settings.entity_id,
        "xmlsec_binary": settings.xmlsec_binary,
        "allow_unknown_attributes": True,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(settings.acs_url, BINDING_HTTP_POST)],
                },
                "allow_unsolicited": False,
                "authn_requests_signed": settings.authn_requests_signed,
                "want_assertions_signed": settings.want_assertions_signed,
                "want_response_signed": False,
            },
        },
        "key_file": settings.key_file,
        "cert_file": settings.cert_file,
        "metadata": {"inline": [idp_metadata]},
    }
