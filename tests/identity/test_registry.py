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


@pytest.mark.parametrize(
    "field", ["eppn", "subject_id", "mail", "scoped_affiliation", "home_organization"]
)
def test_every_expected_field_present(field):
    assert any(d.field == field for d in registry.REGISTRY)
