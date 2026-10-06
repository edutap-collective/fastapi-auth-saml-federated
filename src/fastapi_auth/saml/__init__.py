"""Federated SAML2 Service Provider for FastAPI.

Public entry point of the ``fastapi_auth.saml`` package.
Import via ``from fastapi_auth import saml``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.saml.engine.attributes import SamlAttribute
from fastapi_auth.saml.engine.authn_context import (
    REFEDS_MFA,
    AuthnContextError,
    RequestedAuthnContext,
)
from fastapi_auth.saml.engine.client import ParsedAuthnResponse, SamlEngine
from fastapi_auth.saml.engine.extensions import AuthnRequestExtension, extension_element_from_xml
from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.mapper import map_attributes
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP

__all__ = [
    "REFEDS_MFA",
    "AuthnContextError",
    "AuthnRequestExtension",
    "FederatedIdentity",
    "ParsedAuthnResponse",
    "RequestedAuthnContext",
    "SamlAttribute",
    "SamlEngine",
    "SamlSP",
    "SamlSettings",
    "__version__",
    "extension_element_from_xml",
    "map_attributes",
    "select_identifier",
]

__version__ = "0.4.0"
