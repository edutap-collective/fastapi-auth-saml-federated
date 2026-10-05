"""Raw ``<saml:Attribute>`` elements, including their XML attributes, from a validated assertion."""

from pathlib import Path

import pytest
from saml2 import saml
from tests.conftest import IDP_EID, mint_response

from fastapi_auth.saml import akdb
from fastapi_auth.saml.engine.attributes import SamlAttribute, assertion_attributes
from fastapi_auth.saml.engine.client import ParsedAuthnResponse, SamlEngine
from fastapi_auth.saml.engine.errors import SamlResponseError
from fastapi_auth.saml.settings import SamlSettings

EPPN_OID = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
GIVEN_NAME = "urn:oid:2.5.4.42"


def _engine(certs, idp_metadata_file) -> SamlEngine:
    return SamlEngine(
        SamlSettings(
            entity_id="urn:test:sp",
            base_url="https://sp.example",
            key_file=certs["sp_key"],
            cert_file=certs["sp_crt"],
            idp_metadata_file=idp_metadata_file,
            fixed_idp_entity_id=IDP_EID,
            session_secret="s3cr3t",
        )
    )


# --- SamlAttribute / assertion_attributes (pure) ---


def _assertion(*attributes: saml.Attribute) -> saml.Assertion:
    return saml.Assertion(attribute_statement=[saml.AttributeStatement(attribute=list(attributes))])


def test_reads_name_format_friendly_name_values_and_xml_attributes():
    attribute = saml.Attribute(
        name=GIVEN_NAME,
        name_format=URI,
        friendly_name="givenName",
        attribute_value=[saml.AttributeValue(text="LUDWIG"), saml.AttributeValue(text="MAX")],
    )
    attribute.extension_attributes[akdb.TRUST_LEVEL] = "HOCH"

    assert assertion_attributes(_assertion(attribute)) == (
        SamlAttribute(
            name=GIVEN_NAME,
            name_format=URI,
            friendly_name="givenName",
            values=("LUDWIG", "MAX"),
            xml_attributes={akdb.TRUST_LEVEL: "HOCH"},
        ),
    )


def test_empty_attribute_value_is_an_empty_string():
    attribute = saml.Attribute(name=GIVEN_NAME, attribute_value=[saml.AttributeValue()])

    (raw,) = assertion_attributes(_assertion(attribute))

    assert raw.values == ("",)


def test_attributes_of_all_statements_in_document_order():
    first = saml.AttributeStatement(attribute=[saml.Attribute(name="urn:a")])
    second = saml.AttributeStatement(attribute=[saml.Attribute(name="urn:b")])

    raw = assertion_attributes(saml.Assertion(attribute_statement=[first, second]))

    assert [attribute.name for attribute in raw] == ["urn:a", "urn:b"]


def test_no_assertion_means_no_attributes():
    assert assertion_attributes(None) == ()


def test_xml_attribute_lookup_by_namespace_and_local_name():
    raw = SamlAttribute(name=GIVEN_NAME, xml_attributes={akdb.TRUST_LEVEL: "NORMAL"})

    assert raw.xml_attribute("TrustLevel", namespace=akdb.AKDB_NAMESPACE) == "NORMAL"
    assert raw.xml_attribute("TrustLevel") is None


def test_saml_attribute_is_immutable():
    raw = SamlAttribute(name=GIVEN_NAME)

    with pytest.raises(ValueError, match="frozen"):
        raw.name = "urn:other"  # ty: ignore[invalid-assignment]  # the point of the test


# --- SamlEngine.parse_response_details ---


async def test_trust_level_survives_signature_validation(certs, idp_metadata_file, make_idp):
    engine = _engine(certs, idp_metadata_file)
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    idp = make_idp(engine.sp_metadata())
    response = mint_response(
        idp,
        reqid,
        ava={"eduPersonPrincipalName": ["u@test.de"], akdb.BPK2: ["bpk2-value"]},
        attribute_xml_attributes={akdb.BPK2: {akdb.TRUST_LEVEL: "HOCH"}},
    )

    result = await engine.parse_response_details(response, outstanding={reqid: "/app"})

    assert isinstance(result, ParsedAuthnResponse)
    assert result.in_response_to == reqid
    bpk2 = result.attribute(akdb.BPK2)
    assert bpk2 is not None
    assert bpk2.values == ("bpk2-value",)
    assert akdb.trust_level(bpk2) is akdb.TrustLevel.HOCH
    eppn = result.attribute(EPPN_OID)
    assert eppn is not None
    assert eppn.xml_attributes == {}
    assert result.identity.eppn == "u@test.de"


async def test_attribute_lookup_by_friendly_name(certs, idp_metadata_file, make_idp):
    engine = _engine(certs, idp_metadata_file)
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    idp = make_idp(engine.sp_metadata())
    response = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"]})

    result = await engine.parse_response_details(response, outstanding={reqid: "/app"})

    assert result.attribute("eduPersonPrincipalName") == result.attribute(EPPN_OID)
    assert result.attribute("urn:oid:0.0.0") is None


async def test_xml_attributes_of_an_encrypted_assertion(certs, idp_metadata_file, make_idp):
    engine = _engine(certs, idp_metadata_file)
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    idp = make_idp(engine.sp_metadata())
    response = mint_response(
        idp,
        reqid,
        ava={akdb.BPK2: ["bpk2-value"]},
        encrypt_cert=Path(certs["sp_crt"]).read_text(),
        attribute_xml_attributes={akdb.BPK2: {akdb.TRUST_LEVEL: "SUBSTANTIELL"}},
    )

    result = await engine.parse_response_details(response, outstanding={reqid: "/app"})

    bpk2 = result.attribute(akdb.BPK2)
    assert bpk2 is not None
    assert akdb.trust_level(bpk2) is akdb.TrustLevel.SUBSTANTIELL


async def test_parse_response_still_returns_identity_and_in_response_to(
    certs, idp_metadata_file, make_idp
):
    engine = _engine(certs, idp_metadata_file)
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    idp = make_idp(engine.sp_metadata())
    response = mint_response(
        idp,
        reqid,
        ava={"eduPersonPrincipalName": ["u@test.de"]},
        attribute_xml_attributes={EPPN_OID: {akdb.TRUST_LEVEL: "HOCH"}},
    )

    identity, in_response_to = await engine.parse_response(response, outstanding={reqid: "/app"})

    assert identity.eppn == "u@test.de"
    assert in_response_to == reqid
    assert "raw_attributes" not in identity.model_dump()


async def test_unsigned_assertion_yields_no_raw_attributes(certs, idp_metadata_file, make_idp):
    engine = _engine(certs, idp_metadata_file)
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    idp = make_idp(engine.sp_metadata())
    response = mint_response(
        idp,
        reqid,
        ava={akdb.BPK2: ["bpk2-value"]},
        sign_response=False,
        sign_assertion=False,
        attribute_xml_attributes={akdb.BPK2: {akdb.TRUST_LEVEL: "HOCH"}},
    )

    with pytest.raises(SamlResponseError):
        await engine.parse_response_details(response, outstanding={reqid: "/app"})
