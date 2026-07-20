"""Embedded Where-Are-You-From (WAYF) renderer: a self-hosted IdP picker page.

Renders a minimal HTML list of IdPs as an alternative to redirecting the
browser to an external Discovery Service. Each entry links back to the SP's
own login endpoint with the chosen IdP's entityID attached.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from urllib.parse import quote

from jinja2 import Environment

from fastapi_auth.saml.engine.client import IdPChoice

TEMPLATE_NAME = "wayf.html"


def render_wayf(
    idps: list[IdPChoice], login_path: str, next_url: str, jinja_env: Environment
) -> str:
    """Render the embedded WAYF page listing ``idps`` as links to ``login_path``.

    Each link is ``{login_path}?idp=<url-encoded entityID>&next=<url-encoded next_url>``.
    IdP display names and entityIDs originate from federation metadata and are
    therefore untrusted; the template must render with autoescape enabled
    (the caller is responsible for constructing ``jinja_env`` that way).
    """
    encoded_next = quote(next_url, safe="")
    entries = [
        {
            "display_name": idp.display_name,
            "href": f"{login_path}?idp={quote(idp.entity_id, safe='')}&next={encoded_next}",
        }
        for idp in idps
    ]
    template = jinja_env.get_template(TEMPLATE_NAME)
    return template.render(idps=entries)
