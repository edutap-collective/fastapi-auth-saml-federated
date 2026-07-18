"""Registry mapping SAML attribute names/OIDs to FederatedIdentity fields.

Covers modern SAML Subject Identifiers (subject-id, pairwise-id), eduPerson,
SCHAC and core LDAP attributes. Each attribute is resolvable by its OID
(``urn:oid:…`` / ``urn:oasis:…``), its friendly short name and its MACE URN.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from dataclasses import dataclass

_MACE_PREFIX = "urn:mace:dir:attribute-def:"


@dataclass(frozen=True)
class AttributeDef:
    """A single known attribute and how it maps onto FederatedIdentity."""

    field: str
    friendly: str
    oid: str
    multivalued: bool


REGISTRY: tuple[AttributeDef, ...] = (
    # --- Modern SAML V2.0 Subject Identifiers (preferred) ---
    AttributeDef(
        "subject_id",
        "subject-id",
        "urn:oasis:names:tc:SAML:attribute:subject-id",
        False,
    ),
    AttributeDef(
        "pairwise_id",
        "pairwise-id",
        "urn:oasis:names:tc:SAML:attribute:pairwise-id",
        False,
    ),
    # --- eduPerson ---
    AttributeDef(
        "eppn",
        "eduPersonPrincipalName",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
        False,
    ),
    AttributeDef(
        "unique_id",
        "eduPersonUniqueId",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.13",
        False,
    ),
    AttributeDef(
        "affiliation",
        "eduPersonAffiliation",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
        True,
    ),
    AttributeDef(
        "scoped_affiliation",
        "eduPersonScopedAffiliation",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
        True,
    ),
    AttributeDef(
        "entitlement",
        "eduPersonEntitlement",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
        True,
    ),
    AttributeDef(
        "assurance",
        "eduPersonAssurance",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.11",
        True,
    ),
    AttributeDef(
        "orcid",
        "eduPersonOrcid",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.16",
        True,
    ),
    # --- SCHAC ---
    AttributeDef(
        "home_organization",
        "schacHomeOrganization",
        "urn:oid:1.3.6.1.4.1.25178.1.2.9",
        False,
    ),
    AttributeDef(
        "home_organization_type",
        "schacHomeOrganizationType",
        "urn:oid:1.3.6.1.4.1.25178.1.2.10",
        True,
    ),
    AttributeDef(
        "personal_unique_code",
        "schacPersonalUniqueCode",
        "urn:oid:1.3.6.1.4.1.25178.1.2.14",
        True,
    ),
    # --- Core / LDAP ---
    AttributeDef("mail", "mail", "urn:oid:0.9.2342.19200300.100.1.3", True),
    AttributeDef("display_name", "displayName", "urn:oid:2.16.840.1.113730.3.1.241", False),
    AttributeDef("given_name", "givenName", "urn:oid:2.5.4.42", False),
    AttributeDef("surname", "sn", "urn:oid:2.5.4.4", False),
    AttributeDef("common_name", "cn", "urn:oid:2.5.4.3", False),
    AttributeDef(
        "preferred_language",
        "preferredLanguage",
        "urn:oid:2.16.840.1.113730.3.1.39",
        False,
    ),
)

_BY_KEY: dict[str, AttributeDef] = {}
for _d in REGISTRY:
    _BY_KEY[_d.oid] = _d
    _BY_KEY[_d.friendly] = _d
    _BY_KEY[f"{_MACE_PREFIX}{_d.friendly}"] = _d


def resolve(name: str) -> AttributeDef | None:
    """Resolve an attribute by OID, friendly short name or MACE URN."""
    return _BY_KEY.get(name)
