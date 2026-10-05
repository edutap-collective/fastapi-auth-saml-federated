"""AuthnRequest extensions: arbitrary namespaced XML in ``<samlp:Extensions>``.

SAML 2.0 Core, section 3.2.1, lets a requester add ``<samlp:Extensions>`` to
any request; its children must be namespace-qualified in a non-SAML
namespace. Some IdPs require such an extension -- BundID, for example, an
``akdb:AuthenticationRequest`` (see :mod:`fastapi_auth.saml.akdb`).

An extension is either a pysaml2 :class:`saml2.ExtensionElement` or any
object with a ``to_extension_element()`` method returning one
(:class:`AuthnRequestExtension`). :func:`extension_element_from_xml` turns an
XML string into an element.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable
from xml.etree.ElementTree import ParseError

from saml2 import ExtensionElement, extension_element_from_string, samlp
from saml2.saml import NAMESPACE as SAML_NAMESPACE

#: Namespaces an extension element must not use (SAML 2.0 Core, section 3.2.1).
_SAML_NAMESPACES = frozenset({samlp.NAMESPACE, SAML_NAMESPACE})


@runtime_checkable
class AuthnRequestExtension(Protocol):
    """Anything that renders itself as one ``<samlp:Extensions>`` child."""

    def to_extension_element(self) -> ExtensionElement:
        """Return the pysaml2 element to place inside ``<samlp:Extensions>``."""
        ...


def extension_element_from_xml(xml: str) -> ExtensionElement:
    """Parse one namespaced XML element into a pysaml2 :class:`~saml2.ExtensionElement`.

    Parsing goes through pysaml2's ``defusedxml``-based parser, so DTDs and
    entity declarations are refused. Raises :class:`ValueError` for malformed
    XML and for a root element without a namespace.
    """
    try:
        element = extension_element_from_string(xml)
    except (ParseError, ValueError) as err:  # defusedxml raises ValueError subclasses
        msg = f"invalid extension XML: {err}"
        raise ValueError(msg) from err
    _check_namespace(element)
    return element


def build_extensions(
    extensions: Iterable[ExtensionElement | AuthnRequestExtension],
) -> samlp.Extensions | None:
    """Return a ``<samlp:Extensions>`` holding ``extensions`` in order, or ``None`` if empty.

    Raises :class:`ValueError` if an element has no namespace or uses a SAML
    namespace.
    """
    elements: list[ExtensionElement] = []
    for item in extensions:
        element = item if isinstance(item, ExtensionElement) else item.to_extension_element()
        _check_namespace(element)
        elements.append(element)
    if not elements:
        return None
    return samlp.Extensions(extension_elements=elements)


def _check_namespace(element: ExtensionElement) -> None:
    namespace = element.namespace
    if not namespace:
        msg = f"extension element <{element.tag}> must be namespace-qualified"
        raise ValueError(msg)
    if namespace in _SAML_NAMESPACES:
        msg = f"extension element <{element.tag}> must not use the SAML namespace {namespace}"
        raise ValueError(msg)
