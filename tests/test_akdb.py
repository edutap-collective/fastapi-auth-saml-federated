"""akdb: the BundID ``akdb:AuthenticationRequest`` extension and ``akdb:TrustLevel``.

The expected structure is the one a production BundID SP sends, as documented
in the public source of ``ba-itsys/keycloak-extension-bundid``.
"""

from typing import Any
from xml.etree import ElementTree

import pytest
from defusedxml.ElementTree import fromstring
from pydantic import ValidationError

from fastapi_auth.saml import akdb
from fastapi_auth.saml.engine.attributes import SamlAttribute

NS = "https://www.akdb.de/request/2018/09"
UI = "https://www.akdb.de/request/2018/09/classic-ui/v1"


def _q(namespace: str, tag: str) -> str:
    return f"{{{namespace}}}{tag}"


def _request(**overrides) -> akdb.AuthenticationRequest:
    values: dict[str, Any] = {
        "requested_attributes": (
            akdb.RequestedAttribute(name=akdb.BPK2, required=True),
            akdb.RequestedAttribute(name="urn:oid:2.5.4.42"),
        ),
        "display_information": akdb.DisplayInformation(
            organization_display_name="LMU München", online_service_id="lmu-promotion"
        ),
    }
    values.update(overrides)
    return akdb.AuthenticationRequest(**values)


def _tree(request: akdb.AuthenticationRequest) -> ElementTree.Element:
    return fromstring(request.to_extension_element().to_string())


# --- structure ---


def test_root_is_authentication_request_version_2():
    root = _tree(_request())

    assert root.tag == _q(NS, "AuthenticationRequest")
    assert root.attrib == {"Version": "2"}


def test_children_without_authn_methods():
    children = [child.tag for child in _tree(_request())]

    assert children == [_q(NS, "RequestedAttributes"), _q(NS, "DisplayInformation")]


def test_requested_attributes_by_oid_with_required_flag():
    requested = _tree(_request()).find(_q(NS, "RequestedAttributes"))
    assert requested is not None

    assert [(child.tag, child.attrib) for child in requested] == [
        (
            _q(NS, "RequestedAttribute"),
            {"Name": "urn:oid:1.3.6.1.4.1.25484.494450.3", "RequiredAttribute": "true"},
        ),
        (_q(NS, "RequestedAttribute"), {"Name": "urn:oid:2.5.4.42", "RequiredAttribute": "false"}),
    ]


def test_display_information_in_classic_ui_namespace():
    display = _tree(_request()).find(_q(NS, "DisplayInformation"))
    assert display is not None
    version = display.find(_q(UI, "Version"))
    assert version is not None

    assert [(child.tag, child.text) for child in version] == [
        (_q(UI, "OrganizationDisplayName"), "LMU München"),
        (_q(UI, "OnlineServiceId"), "lmu-promotion"),
    ]


def test_authn_methods_come_first_and_only_list_set_methods():
    request = _request(authn_methods=akdb.AuthnMethods(eid=True, eidas=True, benutzername=False))

    root = _tree(request)
    methods = root.find(_q(NS, "AuthnMethods"))
    assert methods is not None

    assert root[0].tag == _q(NS, "AuthnMethods")
    enabled = {child.tag: [(grand.tag, grand.text) for grand in child] for child in methods}
    assert enabled == {
        _q(NS, "Benutzername"): [(_q(NS, "Enabled"), "false")],
        _q(NS, "eID"): [(_q(NS, "Enabled"), "true")],
        _q(NS, "eIDAS"): [(_q(NS, "Enabled"), "true")],
    }


def test_authn_methods_use_the_reference_element_order():
    every = akdb.AuthnMethods(
        authega=True, benutzername=True, diia=True, eid=True, eidas=True, elster=True, fink=True
    )

    methods = _tree(_request(authn_methods=every)).find(_q(NS, "AuthnMethods"))
    assert methods is not None

    assert [child.tag for child in methods] == [
        _q(NS, tag) for tag in ("Authega", "Benutzername", "Diia", "eID", "eIDAS", "Elster", "FINK")
    ]


def test_serializes_with_akdb_and_classic_ui_prefixes():
    xml = _request().to_extension_element().to_string().decode()

    assert "<akdb:AuthenticationRequest" in xml
    assert "<classic-ui:Version" in xml


# --- validation ---


def test_requires_at_least_one_requested_attribute():
    with pytest.raises(ValidationError):
        _request(requested_attributes=())


def test_rejects_duplicate_requested_attributes():
    with pytest.raises(ValidationError):
        _request(
            requested_attributes=(
                akdb.RequestedAttribute(name=akdb.BPK2),
                akdb.RequestedAttribute(name=akdb.BPK2, required=True),
            )
        )


@pytest.mark.parametrize("name", ["", "  "])
def test_rejects_blank_attribute_names(name):
    with pytest.raises(ValidationError):
        akdb.RequestedAttribute(name=name)


@pytest.mark.parametrize("field", ["organization_display_name", "online_service_id"])
def test_display_information_fields_must_not_be_blank(field):
    values = {"organization_display_name": "LMU", "online_service_id": "svc", field: " "}
    with pytest.raises(ValidationError):
        akdb.DisplayInformation(**values)


def test_authn_methods_need_at_least_one_entry():
    with pytest.raises(ValidationError):
        akdb.AuthnMethods()


# --- TrustLevel ---


def _attribute(**xml_attributes: str) -> SamlAttribute:
    return SamlAttribute(name=akdb.BPK2, values=("x",), xml_attributes=xml_attributes)


@pytest.mark.parametrize(
    ("raw", "level", "stork"),
    [
        ("UNTERGEORDNET", akdb.TrustLevel.UNTERGEORDNET, "STORK-QAA-Level-1"),
        ("NORMAL", akdb.TrustLevel.NORMAL, "STORK-QAA-Level-2"),
        ("SUBSTANTIELL", akdb.TrustLevel.SUBSTANTIELL, "STORK-QAA-Level-3"),
        ("HOCH", akdb.TrustLevel.HOCH, "STORK-QAA-Level-4"),
    ],
)
def test_trust_level_is_read_from_the_attribute(raw, level, stork):
    found = akdb.trust_level(_attribute(**{akdb.TRUST_LEVEL: raw}))

    assert found is level
    assert found.stork_level == stork


def test_missing_trust_level_is_none():
    assert akdb.trust_level(_attribute()) is None


def test_unknown_trust_level_is_none():
    assert akdb.trust_level(_attribute(**{akdb.TRUST_LEVEL: "EXTREM"})) is None


def test_trust_level_without_namespace_is_not_trusted():
    assert akdb.trust_level(_attribute(TrustLevel="HOCH")) is None


def test_trust_levels_are_ordered():
    assert akdb.TrustLevel.NORMAL < akdb.TrustLevel.HOCH
    assert akdb.STORK_QAA_LEVELS == tuple(f"STORK-QAA-Level-{n}" for n in range(1, 5))
