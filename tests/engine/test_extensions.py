"""AuthnRequest extensions: arbitrary namespaced XML elements for ``<samlp:Extensions>``."""

import pytest
from saml2 import ExtensionElement

from fastapi_auth.saml.engine.extensions import (
    build_extensions,
    extension_element_from_xml,
)

NS = "urn:example:ext"


class _Builder:
    def to_extension_element(self) -> ExtensionElement:
        return ExtensionElement("Hint", namespace=NS, text="from builder")


def test_parses_a_namespaced_element_from_xml():
    element = extension_element_from_xml(
        f'<x:Hint xmlns:x="{NS}" Level="2"><x:Child>text</x:Child></x:Hint>'
    )

    assert (element.namespace, element.tag, element.attributes) == (NS, "Hint", {"Level": "2"})
    assert [(c.namespace, c.tag, c.text) for c in element.children] == [(NS, "Child", "text")]


def test_rejects_xml_without_namespace():
    with pytest.raises(ValueError, match="namespace"):
        extension_element_from_xml("<Hint/>")


def test_rejects_malformed_xml():
    with pytest.raises(ValueError, match="XML"):
        extension_element_from_xml("<x:Hint xmlns:x='urn:a'>")


def test_rejects_entity_declarations():
    evil = (
        f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><x:Hint xmlns:x="{NS}">&e;</x:Hint>'
    )
    with pytest.raises(ValueError, match="XML"):
        extension_element_from_xml(evil)


def test_build_extensions_keeps_order_and_accepts_builders():
    plain = ExtensionElement("First", namespace=NS)

    extensions = build_extensions([plain, _Builder()])

    assert extensions is not None
    assert [(e.tag, e.text) for e in extensions.extension_elements] == [
        ("First", None),
        ("Hint", "from builder"),
    ]


def test_build_extensions_of_nothing_is_none():
    assert build_extensions([]) is None


@pytest.mark.parametrize(
    "namespace",
    [
        None,
        "",
        "urn:oasis:names:tc:SAML:2.0:protocol",
        "urn:oasis:names:tc:SAML:2.0:assertion",
        "urn:oasis:names:tc:SAML:2.0:metadata",
        "urn:oasis:names:tc:SAML:1.0:protocol",
        "urn:oasis:names:tc:SAML:1.0:assertion",
    ],
)
def test_build_extensions_rejects_unqualified_or_saml_namespaced_elements(namespace):
    with pytest.raises(ValueError, match="namespace"):
        build_extensions([ExtensionElement("Hint", namespace=namespace)])


def test_build_extensions_allows_oasis_extension_namespaces():
    # OASIS extension specs define namespaces meant for <samlp:Extensions>.
    element = ExtensionElement(
        "RequestedAttribute", namespace="urn:oasis:names:tc:SAML:protocol:ext:req-attr"
    )

    extensions = build_extensions([element])

    assert extensions is not None
    assert extensions.extension_elements == [element]
