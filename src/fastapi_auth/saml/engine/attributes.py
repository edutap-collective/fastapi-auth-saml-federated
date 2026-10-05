"""Raw ``<saml:Attribute>`` elements of a validated assertion, XML attributes included.

:class:`~fastapi_auth.saml.identity.model.FederatedIdentity` keeps only
attribute values, keyed by friendly name. Some IdPs put meaning into XML
attributes on ``<saml:Attribute>`` itself -- BundID, for example, rates each
attribute with ``akdb:TrustLevel``. :class:`SamlAttribute` keeps that
information; :func:`assertion_attributes` reads it from the assertion pysaml2
has already verified (and decrypted).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class SamlAttribute(BaseModel):
    """One ``<saml:Attribute>`` as the IdP sent it.

    ``xml_attributes`` holds every XML attribute beyond ``Name``,
    ``NameFormat`` and ``FriendlyName``. Keys of namespaced attributes use
    Clark notation, ``{namespace}local-name``; unqualified ones are bare.
    ``values`` holds the text of each ``<saml:AttributeValue>`` (``""`` for an
    empty one).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    name_format: str | None = None
    friendly_name: str | None = None
    values: tuple[str, ...] = ()
    xml_attributes: dict[str, str] = {}

    def xml_attribute(self, local_name: str, namespace: str | None = None) -> str | None:
        """Return the XML attribute ``local_name`` in ``namespace``, or ``None`` if absent.

        Without ``namespace``, only an unqualified attribute matches.
        """
        key = f"{{{namespace}}}{local_name}" if namespace else local_name
        return self.xml_attributes.get(key)


def assertion_attributes(assertion: Any) -> tuple[SamlAttribute, ...]:
    """Return every ``<saml:Attribute>`` of every ``AttributeStatement``, in document order.

    ``assertion`` is pysaml2's validated ``saml.Assertion`` (untyped, hence
    ``Any``); ``None`` yields no attributes.
    """
    found: list[SamlAttribute] = []
    for statement in getattr(assertion, "attribute_statement", None) or []:
        for attribute in getattr(statement, "attribute", None) or []:
            found.append(
                SamlAttribute(
                    name=attribute.name,
                    name_format=attribute.name_format,
                    friendly_name=attribute.friendly_name,
                    values=tuple(
                        value.text if isinstance(value.text, str) else ""
                        for value in attribute.attribute_value or []
                    ),
                    xml_attributes=dict(attribute.extension_attributes or {}),
                )
            )
    return tuple(found)
