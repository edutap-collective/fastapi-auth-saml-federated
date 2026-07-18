"""Tests for the FederatedIdentity model."""

from fastapi_auth.saml.identity.model import FederatedIdentity


def test_empty_identity_has_sane_defaults():
    ident = FederatedIdentity()
    assert ident.eppn is None
    assert ident.mail == []
    assert ident.scoped_affiliation == []
    assert ident.attributes == {}


def test_identity_holds_values():
    ident = FederatedIdentity(
        eppn="u123@lmu.de",
        scoped_affiliation=["staff@lmu.de", "member@lmu.de"],
        mail=["a@lmu.de"],
        attributes={"eduPersonPrincipalName": ["u123@lmu.de"]},
    )
    assert ident.eppn == "u123@lmu.de"
    assert ident.scoped_affiliation == ["staff@lmu.de", "member@lmu.de"]
    assert ident.attributes["eduPersonPrincipalName"] == ["u123@lmu.de"]


def test_multivalue_lists_are_independent_between_instances():
    a = FederatedIdentity()
    a.mail.append("x@lmu.de")
    b = FederatedIdentity()
    assert b.mail == []
