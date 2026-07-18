"""Tests for mapping a raw attribute dict onto FederatedIdentity."""

from datetime import UTC, datetime

from fastapi_auth.saml.identity.mapper import map_attributes

_EPPN = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
_SCOPED = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
_SUBJECT_ID = "urn:oasis:names:tc:SAML:attribute:subject-id"
_MAIL = "urn:oid:0.9.2342.19200300.100.1.3"


def test_single_valued_takes_first_value():
    ident = map_attributes({_EPPN: ["u123@lmu.de"]})
    assert ident.eppn == "u123@lmu.de"


def test_multi_valued_keeps_full_list():
    ident = map_attributes({_SCOPED: ["staff@lmu.de", "member@lmu.de"]})
    assert ident.scoped_affiliation == ["staff@lmu.de", "member@lmu.de"]


def test_subject_id_maps():
    ident = map_attributes({_SUBJECT_ID: ["abc@lmu.de"]})
    assert ident.subject_id == "abc@lmu.de"


def test_attributes_escape_hatch_uses_friendly_names():
    ident = map_attributes({_EPPN: ["u@lmu.de"], _MAIL: ["a@lmu.de", "b@lmu.de"]})
    assert ident.attributes["eduPersonPrincipalName"] == ["u@lmu.de"]
    assert ident.attributes["mail"] == ["a@lmu.de", "b@lmu.de"]


def test_unknown_attribute_kept_under_raw_key():
    ident = map_attributes({"urn:oid:9.9.9": ["x"]})
    assert ident.attributes["urn:oid:9.9.9"] == ["x"]


def test_empty_value_list_is_skipped():
    ident = map_attributes({_EPPN: []})
    assert ident.eppn is None
    assert "eduPersonPrincipalName" not in ident.attributes


def test_saml_metadata_is_carried_through():
    ts = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
    ident = map_attributes(
        {_EPPN: ["u@lmu.de"]},
        name_id="nameid-123",
        name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        idp_entity_id="urn:lmu.de:testidp",
        authn_instant=ts,
        authn_context_class="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        assertion_id="_abc",
    )
    assert ident.idp_entity_id == "urn:lmu.de:testidp"
    assert ident.authn_instant == ts
    assert ident.assertion_id == "_abc"
