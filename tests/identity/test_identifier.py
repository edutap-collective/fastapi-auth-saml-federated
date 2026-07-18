"""Tests for stable identifier selection."""

from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.model import FederatedIdentity


def test_primary_wins_when_present():
    ident = FederatedIdentity(subject_id="sub@lmu.de", eppn="u@lmu.de")
    assert select_identifier(ident, "subject_id", ["pairwise_id", "eppn"]) == "sub@lmu.de"


def test_falls_back_when_primary_missing():
    ident = FederatedIdentity(eppn="u@lmu.de")
    assert select_identifier(ident, "subject_id", ["pairwise_id", "eppn"]) == "u@lmu.de"


def test_returns_none_when_nothing_matches():
    ident = FederatedIdentity()
    assert select_identifier(ident, "subject_id", ["eppn"]) is None


def test_list_field_uses_first_value():
    ident = FederatedIdentity(mail=["first@lmu.de", "second@lmu.de"])
    assert select_identifier(ident, "mail") == "first@lmu.de"


def test_public_api_reexports():
    from fastapi_auth import saml

    assert hasattr(saml, "FederatedIdentity")
    assert hasattr(saml, "map_attributes")
    assert hasattr(saml, "select_identifier")
