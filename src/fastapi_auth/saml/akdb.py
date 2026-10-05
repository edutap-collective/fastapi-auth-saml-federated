"""BundID (AKDB) helpers: the ``akdb:AuthenticationRequest`` extension and ``akdb:TrustLevel``.

BundID, the German federal citizen account, expects an
``akdb:AuthenticationRequest`` in the AuthnRequest's ``<samlp:Extensions>``
and rates each released attribute with an ``akdb:TrustLevel`` XML attribute.
Nothing here is required for other IdPs; the generic mechanisms are
:mod:`fastapi_auth.saml.engine.extensions` and
:mod:`fastapi_auth.saml.engine.attributes`.

Element names, namespaces, order and the trust-level values follow what a
production BundID service provider sends and reads, as published in the
source of `keycloak-extension-bundid
<https://github.com/ba-itsys/keycloak-extension-bundid>`_ (Apache-2.0):
``extension/model/*.java`` and ``mapper/BundIdUserSessionAttributeMapper.java``.
The operator's own integration guide is not public; check it before going
live.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import enum
import functools
from xml.etree import ElementTree

from pydantic import BaseModel, ConfigDict, Field, model_validator
from saml2 import ExtensionElement

from fastapi_auth.saml.engine.attributes import SamlAttribute

#: Namespace of ``akdb:AuthenticationRequest`` and ``akdb:TrustLevel``.
AKDB_NAMESPACE = "https://www.akdb.de/request/2018/09"
#: Namespace of the ``DisplayInformation`` content.
CLASSIC_UI_NAMESPACE = "https://www.akdb.de/request/2018/09/classic-ui/v1"

#: ``akdb:TrustLevel`` in Clark notation, as a key of ``SamlAttribute.xml_attributes``.
TRUST_LEVEL = f"{{{AKDB_NAMESPACE}}}TrustLevel"

#: bPK2, the service-provider-specific person identifier.
BPK2 = "urn:oid:1.3.6.1.4.1.25484.494450.3"

#: STORK QAA levels, weakest first -- a ``ranking`` for ``RequestedAuthnContext``.
STORK_QAA_LEVELS = tuple(f"STORK-QAA-Level-{n}" for n in range(1, 5))

# Serialize with the prefixes the reference implementation uses. pysaml2
# registers its own prefixes with ElementTree the same way.
ElementTree.register_namespace("akdb", AKDB_NAMESPACE)
ElementTree.register_namespace("classic-ui", CLASSIC_UI_NAMESPACE)


def _akdb(
    tag: str,
    *,
    attributes: dict[str, str] | None = None,
    children: list[ExtensionElement] | None = None,
    text: str | None = None,
) -> ExtensionElement:
    return ExtensionElement(
        tag, namespace=AKDB_NAMESPACE, attributes=attributes, children=children, text=text
    )


def _bool(value: bool) -> str:
    return "true" if value else "false"


def _not_blank(value: str, field: str) -> str:
    if not value.strip():
        msg = f"{field} must not be blank"
        raise ValueError(msg)
    return value


class RequestedAttribute(BaseModel):
    """One attribute requested by OID (``Name="urn:oid:..."``)."""

    model_config = ConfigDict(frozen=True)

    name: str
    required: bool = False

    @model_validator(mode="after")
    def _check_name(self) -> RequestedAttribute:
        """Reject a blank attribute name."""
        _not_blank(self.name, "name")
        return self

    def to_extension_element(self) -> ExtensionElement:
        """Return ``<akdb:RequestedAttribute Name=... RequiredAttribute=...>``."""
        return _akdb(
            "RequestedAttribute",
            attributes={"Name": self.name, "RequiredAttribute": _bool(self.required)},
        )


class DisplayInformation(BaseModel):
    """What BundID shows the person: the organization and the online service."""

    model_config = ConfigDict(frozen=True)

    organization_display_name: str
    online_service_id: str

    @model_validator(mode="after")
    def _check_values(self) -> DisplayInformation:
        """Reject blank values."""
        _not_blank(self.organization_display_name, "organization_display_name")
        _not_blank(self.online_service_id, "online_service_id")
        return self

    def to_extension_element(self) -> ExtensionElement:
        """Return ``<akdb:DisplayInformation>`` with its ``classic-ui:Version`` content."""
        version = ExtensionElement(
            "Version",
            namespace=CLASSIC_UI_NAMESPACE,
            children=[
                ExtensionElement(
                    "OrganizationDisplayName",
                    namespace=CLASSIC_UI_NAMESPACE,
                    text=self.organization_display_name,
                ),
                ExtensionElement(
                    "OnlineServiceId", namespace=CLASSIC_UI_NAMESPACE, text=self.online_service_id
                ),
            ],
        )
        return _akdb("DisplayInformation", children=[version])


#: Field name -> element name, in the reference implementation's order.
_AUTHN_METHOD_ELEMENTS = {
    "authega": "Authega",
    "benutzername": "Benutzername",
    "diia": "Diia",
    "eid": "eID",
    "eidas": "eIDAS",
    "elster": "Elster",
    "fink": "FINK",
}


class AuthnMethods(BaseModel):
    """Enable (``True``) or disable (``False``) login methods; ``None`` leaves the IdP default.

    ``eid`` is the online ID card function, ``benutzername`` username and
    password, ``elster`` the tax certificate. At least one must be set.
    """

    model_config = ConfigDict(frozen=True)

    authega: bool | None = None
    benutzername: bool | None = None
    diia: bool | None = None
    eid: bool | None = None
    eidas: bool | None = None
    elster: bool | None = None
    fink: bool | None = None

    @model_validator(mode="after")
    def _check_any(self) -> AuthnMethods:
        """Reject an empty ``AuthnMethods``: it would say nothing."""
        if all(getattr(self, field) is None for field in _AUTHN_METHOD_ELEMENTS):
            msg = "set at least one authentication method"
            raise ValueError(msg)
        return self

    def to_extension_element(self) -> ExtensionElement:
        """Return ``<akdb:AuthnMethods>`` with one ``<akdb:Enabled>`` per set method."""
        children = []
        for field, tag in _AUTHN_METHOD_ELEMENTS.items():
            enabled = getattr(self, field)
            if enabled is not None:
                children.append(_akdb(tag, children=[_akdb("Enabled", text=_bool(enabled))]))
        return _akdb("AuthnMethods", children=children)


class AuthenticationRequest(BaseModel):
    """``akdb:AuthenticationRequest`` for the AuthnRequest's ``<samlp:Extensions>``.

    Pass it to ``SamlEngine.create_authn_request(extensions=[...])``.
    """

    model_config = ConfigDict(frozen=True)

    requested_attributes: tuple[RequestedAttribute, ...] = Field(min_length=1)
    display_information: DisplayInformation
    authn_methods: AuthnMethods | None = None
    version: str = "2"

    @model_validator(mode="after")
    def _check_unique(self) -> AuthenticationRequest:
        """Reject an attribute requested twice."""
        names = [attribute.name for attribute in self.requested_attributes]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            msg = f"requested_attributes contain duplicates: {', '.join(duplicates)}"
            raise ValueError(msg)
        return self

    def to_extension_element(self) -> ExtensionElement:
        """Return the element: ``AuthnMethods``, ``RequestedAttributes``, ``DisplayInformation``."""
        children = []
        if self.authn_methods is not None:
            children.append(self.authn_methods.to_extension_element())
        children.append(
            _akdb(
                "RequestedAttributes",
                children=[a.to_extension_element() for a in self.requested_attributes],
            )
        )
        children.append(self.display_information.to_extension_element())
        return _akdb(
            "AuthenticationRequest", attributes={"Version": self.version}, children=children
        )


@functools.total_ordering
class TrustLevel(enum.Enum):
    """Value of ``akdb:TrustLevel``; ordered from weakest to strongest."""

    UNTERGEORDNET = "UNTERGEORDNET"
    NORMAL = "NORMAL"
    SUBSTANTIELL = "SUBSTANTIELL"
    HOCH = "HOCH"

    @property
    def stork_level(self) -> str:
        """Return the matching ``STORK-QAA-Level-1`` ... ``-4``."""
        return STORK_QAA_LEVELS[_TRUST_LEVEL_ORDER.index(self)]

    def __lt__(self, other: object) -> bool:
        """Compare by strength, not by name."""
        if not isinstance(other, TrustLevel):
            return NotImplemented
        return _TRUST_LEVEL_ORDER.index(self) < _TRUST_LEVEL_ORDER.index(other)


_TRUST_LEVEL_ORDER = tuple(TrustLevel)


def trust_level(attribute: SamlAttribute) -> TrustLevel | None:
    """Return the attribute's ``akdb:TrustLevel``, or ``None`` if absent or unknown.

    Only the namespace-qualified XML attribute counts; an unknown value is
    never mapped to a level.
    """
    raw = attribute.xml_attributes.get(TRUST_LEVEL)
    if raw is None:
        return None
    try:
        return TrustLevel(raw)
    except ValueError:
        return None
