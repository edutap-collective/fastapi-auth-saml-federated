"""Enforce that mandatory attributes were released (GDPR data-minimisation).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.saml.engine.errors import AttributeReleaseError
from fastapi_auth.saml.identity import registry
from fastapi_auth.saml.identity.model import FederatedIdentity


def _is_present(identity: FederatedIdentity, friendly: str) -> bool:
    definition = registry.resolve(friendly)
    if definition is not None:
        value = getattr(identity, definition.field, None)
        return bool(value)
    return bool(identity.attributes.get(friendly))


def check_required_attributes(identity: FederatedIdentity, required: list[str]) -> None:
    """Raise AttributeReleaseError if any required friendly-named attribute is absent."""
    missing = [name for name in required if not _is_present(identity, name)]
    if missing:
        raise AttributeReleaseError(missing=missing)
