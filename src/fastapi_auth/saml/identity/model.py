"""Typed identity assembled from a SAML assertion.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FederatedIdentity(BaseModel):
    """Curated view of the attributes released by an IdP.

    Well-known attributes are typed fields; the full set of released
    attributes (friendly-name keyed) is always available under ``attributes``.
    """

    # --- stable identifiers ---
    subject_id: str | None = None
    pairwise_id: str | None = None
    eppn: str | None = None
    unique_id: str | None = None

    # --- affiliation / authorization ---
    affiliation: list[str] = Field(default_factory=list)
    scoped_affiliation: list[str] = Field(default_factory=list)
    entitlement: list[str] = Field(default_factory=list)
    assurance: list[str] = Field(default_factory=list)

    # --- personal / core ---
    mail: list[str] = Field(default_factory=list)
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    common_name: str | None = None
    orcid: list[str] = Field(default_factory=list)
    preferred_language: str | None = None

    # --- SCHAC / organization ---
    home_organization: str | None = None
    home_organization_type: list[str] = Field(default_factory=list)
    personal_unique_code: list[str] = Field(default_factory=list)

    # --- SAML metadata ---
    name_id: str | None = None
    name_id_format: str | None = None
    idp_entity_id: str | None = None
    authn_instant: datetime | None = None
    authn_context_class: str | None = None
    assertion_id: str | None = None

    # --- escape hatch: all released attributes (friendly-name -> values) ---
    attributes: dict[str, list[str]] = Field(default_factory=dict)
