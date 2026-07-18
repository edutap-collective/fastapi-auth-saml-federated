"""Tests for the eduPerson/SCHAC attribute registry."""

import pytest

from fastapi_auth.saml.identity import registry


def test_resolve_by_oid():
    d = registry.resolve("urn:oid:1.3.6.1.4.1.5923.1.1.1.6")
    assert d is not None
    assert d.field == "eppn"
    assert d.multivalued is False


def test_resolve_by_friendly_name():
    assert registry.resolve("eduPersonPrincipalName").field == "eppn"


def test_resolve_by_mace_urn():
    d = registry.resolve("urn:mace:dir:attribute-def:eduPersonPrincipalName")
    assert d.field == "eppn"


def test_resolve_subject_id_and_pairwise_id():
    assert registry.resolve("urn:oasis:names:tc:SAML:attribute:subject-id").field == "subject_id"
    assert registry.resolve("urn:oasis:names:tc:SAML:attribute:pairwise-id").field == "pairwise_id"


def test_scoped_affiliation_is_multivalued():
    assert registry.resolve("urn:oid:1.3.6.1.4.1.5923.1.1.1.9").multivalued is True


def test_unknown_returns_none():
    assert registry.resolve("urn:oid:9.9.9") is None


@pytest.mark.parametrize(
    "field", ["eppn", "subject_id", "mail", "scoped_affiliation", "home_organization"]
)
def test_every_expected_field_present(field):
    assert any(d.field == field for d in registry.REGISTRY)
