"""Federated SAML2 Service Provider for FastAPI.

Public entry point of the ``fastapi_auth.saml`` package.
Import via ``from fastapi_auth import saml``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.mapper import map_attributes
from fastapi_auth.saml.identity.model import FederatedIdentity

__all__ = [
    "FederatedIdentity",
    "__version__",
    "map_attributes",
    "select_identifier",
]

__version__ = "0.1.0.dev0"
