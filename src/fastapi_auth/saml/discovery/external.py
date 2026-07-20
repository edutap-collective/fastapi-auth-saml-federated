"""External SAML2 Discovery Service (DS) protocol: redirect-URL building and return parsing.

Implements the plain part of the SAML V2.0 Identity Provider Discovery Service
Protocol and Profile (the SP-facing half): the SP redirects the browser to the
DS with its own entityID and a return URL, and later reads the chosen IdP's
entityID back off the return request's query parameters.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlencode


def ds_redirect_url(ds_url: str, sp_entity_id: str, return_url: str) -> str:
    """Build the URL to redirect the browser to the external Discovery Service.

    Appends ``entityID`` (the SP's own entityID) and ``return`` (where the DS
    should send the browser back to, with the chosen IdP's entityID attached)
    as URL-encoded query parameters. If ``ds_url`` already has a query string,
    the new parameters are appended with ``&`` rather than replacing it.
    """
    query = urlencode({"entityID": sp_entity_id, "return": return_url})
    separator = "&" if "?" in ds_url else "?"
    return f"{ds_url}{separator}{query}"


def parse_ds_return(query_params: Mapping[str, str]) -> str | None:
    """Extract the chosen IdP's entityID from the Discovery Service's return request."""
    return query_params.get("entityID")
