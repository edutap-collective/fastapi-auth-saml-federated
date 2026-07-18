"""Tests for the eduPerson/SCHAC attribute registry."""

import pytest

from fastapi_auth.saml.identity import registry


def test_resolve_by_oid():
    d = registry.resolve("urn:oid:1.3.6.1.4.1.5923.1.1.1.6")
    assert d is not None
    assert d.field == "eppn"
    assert d.multivalued is False


def test_resolve_by_friendly_name():
    d = registry.resolve("eduPersonPrincipalName")
    assert d is not None
    assert d.field == "eppn"


def test_resolve_by_mace_urn():
    d = registry.resolve("urn:mace:dir:attribute-def:eduPersonPrincipalName")
    assert d is not None
    assert d.field == "eppn"


def test_resolve_subject_id_and_pairwise_id():
    subject_id = registry.resolve("urn:oasis:names:tc:SAML:attribute:subject-id")
    pairwise_id = registry.resolve("urn:oasis:names:tc:SAML:attribute:pairwise-id")
    assert subject_id is not None
    assert pairwise_id is not None
    assert subject_id.field == "subject_id"
    assert pairwise_id.field == "pairwise_id"


def test_scoped_affiliation_is_multivalued():
    d = registry.resolve("urn:oid:1.3.6.1.4.1.5923.1.1.1.9")
    assert d is not None
    assert d.multivalued is True


def test_unknown_returns_none():
    assert registry.resolve("urn:oid:9.9.9") is None


def test_resolve_organization_by_oid():
    d = registry.resolve("urn:oid:2.5.4.10")
    assert d is not None
    assert d.field == "organization"
    assert d.multivalued is True


def test_resolve_organization_by_friendly_name():
    d = registry.resolve("o")
    assert d is not None
    assert d.field == "organization"


def test_resolve_organization_by_mace_urn():
    d = registry.resolve("urn:mace:dir:attribute-def:o")
    assert d is not None
    assert d.field == "organization"


def test_resolve_personal_unique_id_by_oid():
    d = registry.resolve("urn:oid:1.3.6.1.4.1.25178.1.2.15")
    assert d is not None
    assert d.field == "personal_unique_id"
    assert d.multivalued is True


def test_resolve_personal_unique_id_by_friendly_name():
    d = registry.resolve("schacPersonalUniqueID")
    assert d is not None
    assert d.field == "personal_unique_id"


def test_resolve_personal_unique_id_by_mace_urn():
    d = registry.resolve("urn:mace:dir:attribute-def:schacPersonalUniqueID")
    assert d is not None
    assert d.field == "personal_unique_id"


@pytest.mark.parametrize(
    "field",
    [
        "eppn",
        "subject_id",
        "mail",
        "scoped_affiliation",
        "home_organization",
        "organization",
        "personal_unique_id",
    ],
)
def test_every_expected_field_present(field):
    assert any(d.field == field for d in registry.REGISTRY)
