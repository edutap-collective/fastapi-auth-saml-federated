"""Select the stable identifier for a service provider.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi_auth.saml.identity.model import FederatedIdentity


def select_identifier(
    identity: FederatedIdentity,
    primary: str,
    fallback: Sequence[str] = (),
) -> str | None:
    """Return the first non-empty identifier field value in preference order.

    Each name is a FederatedIdentity field (e.g. ``"subject_id"``, ``"eppn"``,
    ``"name_id"``). For list-valued fields the first element is used.
    """
    for name in (primary, *fallback):
        value = getattr(identity, name, None)
        if isinstance(value, list):
            value = value[0] if value else None
        if value:
            return str(value)
    return None
