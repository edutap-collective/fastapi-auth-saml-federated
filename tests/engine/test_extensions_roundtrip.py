"""SamlEngine: per-login ``<samlp:Extensions>`` in the AuthnRequest, BundID structure end to end."""

from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

from defusedxml.ElementTree import fromstring
from saml2.s_utils import decode_base64_and_inflate
from tests.conftest import IDP_EID

from fastapi_auth.saml import akdb
from fastapi_auth.saml.engine.authn_context import RequestedAuthnContext
from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.engine.extensions import extension_element_from_xml
from fastapi_auth.saml.settings import SamlSettings

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS = "https://www.akdb.de/request/2018/09"
UI = "https://www.akdb.de/request/2018/09/classic-ui/v1"

BUNDID = akdb.AuthenticationRequest(
    requested_attributes=(akdb.RequestedAttribute(name=akdb.BPK2, required=True),),
    display_information=akdb.DisplayInformation(
        organization_display_name="LMU München", online_service_id="lmu-promotion"
    ),
    authn_methods=akdb.AuthnMethods(eid=True, eidas=True, benutzername=False),
)
LEVEL_4 = RequestedAuthnContext(
    class_refs=("STORK-QAA-Level-4",), comparison="minimum", ranking=akdb.STORK_QAA_LEVELS
)


def _q(namespace: str, tag: str) -> str:
    return f"{{{namespace}}}{tag}"


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


def _authn_request_xml(location: str) -> ElementTree.Element:
    saml_request = parse_qs(urlparse(location).query)["SAMLRequest"][0]
    return fromstring(decode_base64_and_inflate(saml_request))


async def test_authn_request_carries_the_bundid_structure(certs, idp_metadata_file):
    engine = _engine(certs, idp_metadata_file)

    _reqid, location = await engine.create_authn_request(
        relay_state="/app", extensions=[BUNDID], requested_authn_context=LEVEL_4
    )

    request = _authn_request_xml(location)
    extensions = request.find(_q(SAMLP, "Extensions"))
    assert extensions is not None
    assert [child.tag for child in extensions] == [_q(NS, "AuthenticationRequest")]
    auth_request = extensions[0]
    assert auth_request.attrib == {"Version": "2"}
    assert [child.tag for child in auth_request] == [
        _q(NS, "AuthnMethods"),
        _q(NS, "RequestedAttributes"),
        _q(NS, "DisplayInformation"),
    ]
    requested = auth_request.find(_q(NS, "RequestedAttributes"))
    assert requested is not None
    assert [child.attrib for child in requested] == [
        {"Name": "urn:oid:1.3.6.1.4.1.25484.494450.3", "RequiredAttribute": "true"}
    ]
    version = auth_request.find(f"{_q(NS, 'DisplayInformation')}/{_q(UI, 'Version')}")
    assert version is not None
    assert [(child.tag, child.text) for child in version] == [
        (_q(UI, "OrganizationDisplayName"), "LMU München"),
        (_q(UI, "OnlineServiceId"), "lmu-promotion"),
    ]
    # SAML 2.0 Core 3.2.1 / 3.4.1: Extensions precede RequestedAuthnContext.
    tags = [child.tag for child in request]
    assert tags.index(_q(SAMLP, "Extensions")) < tags.index(_q(SAMLP, "RequestedAuthnContext"))
    rac = request.find(_q(SAMLP, "RequestedAuthnContext"))
    assert rac is not None
    assert rac.attrib == {"Comparison": "minimum"}
    assert [ref.text for ref in rac.findall(_q(SAML, "AuthnContextClassRef"))] == [
        "STORK-QAA-Level-4"
    ]


async def test_signed_request_with_extensions_keeps_its_signature(certs, idp_metadata_file):
    engine = _engine(certs, idp_metadata_file)

    _reqid, location = await engine.create_authn_request(relay_state="/app", extensions=[BUNDID])

    query = parse_qs(urlparse(location).query)
    assert "Signature" in query
    assert "SigAlg" in query


async def test_extensions_are_per_login_not_global(certs, idp_metadata_file):
    engine = _engine(certs, idp_metadata_file)
    await engine.create_authn_request(relay_state="/app", extensions=[BUNDID])

    _reqid, location = await engine.create_authn_request(relay_state="/app")

    assert _authn_request_xml(location).find(_q(SAMLP, "Extensions")) is None


async def test_arbitrary_elements_are_passed_through_in_order(certs, idp_metadata_file):
    engine = _engine(certs, idp_metadata_file)
    first = extension_element_from_xml('<a:One xmlns:a="urn:example:a" k="v"/>')
    second = extension_element_from_xml('<b:Two xmlns:b="urn:example:b">t</b:Two>')

    _reqid, location = await engine.create_authn_request(
        relay_state="/app", extensions=[first, second]
    )

    extensions = _authn_request_xml(location).find(_q(SAMLP, "Extensions"))
    assert extensions is not None
    assert [(child.tag, child.attrib, child.text) for child in extensions] == [
        ("{urn:example:a}One", {"k": "v"}, None),
        ("{urn:example:b}Two", {}, "t"),
    ]
