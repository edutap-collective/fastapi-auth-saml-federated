"""Map a raw (already extracted) SAML attribute dict onto FederatedIdentity.

Pure function — no XML, no network. The caller (engine layer, later milestone)
passes attributes keyed by OID or friendly name, plus assertion metadata.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from datetime import datetime

from fastapi_auth.saml.identity import registry
from fastapi_auth.saml.identity.model import FederatedIdentity


def map_attributes(
    raw: dict[str, list[str]],
    *,
    name_id: str | None = None,
    name_id_format: str | None = None,
    idp_entity_id: str | None = None,
    authn_instant: datetime | None = None,
    authn_context_class: str | None = None,
    assertion_id: str | None = None,
) -> FederatedIdentity:
    """Build a FederatedIdentity from released attributes and assertion metadata."""
    fields: dict[str, str | list[str]] = {}
    attributes: dict[str, list[str]] = {}

    for key, values in raw.items():
        if not values:
            continue
        definition = registry.resolve(key)
        if definition is None:
            attributes[key] = list(values)
            continue
        attributes[definition.friendly] = list(values)
        fields[definition.field] = list(values) if definition.multivalued else values[0]

    return FederatedIdentity(
        name_id=name_id,
        name_id_format=name_id_format,
        idp_entity_id=idp_entity_id,
        authn_instant=authn_instant,
        authn_context_class=authn_context_class,
        assertion_id=assertion_id,
        attributes=attributes,
        **fields,  # ty: ignore[invalid-argument-type]  # dynamic kwargs: keys are validated registry fields; types are str|list[str]
    )
