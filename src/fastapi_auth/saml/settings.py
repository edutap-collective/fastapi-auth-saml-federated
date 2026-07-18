"""Configuration for the SAML2 service provider (pydantic-settings).

Milestone 2 scope: single-IdP direct metadata + passthrough discovery only.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import shutil
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_xmlsec() -> str:
    return shutil.which("xmlsec1") or "/usr/bin/xmlsec1"


class SamlSettings(BaseSettings):
    """Service-provider settings, populated from environment (prefix ``SAML_``)."""

    model_config = SettingsConfigDict(env_prefix="SAML_", env_file=".env", extra="ignore")

    # --- service provider ---
    entity_id: str
    base_url: str
    acs_path: str = "/saml/acs"
    key_file: str
    cert_file: str

    # --- metadata / trust (this milestone: single-IdP direct only) ---
    metadata_source: Literal["direct"] = "direct"
    idp_metadata_file: str | None = None
    idp_metadata_url: str | None = None

    # --- discovery (this milestone: passthrough only) ---
    discovery_mode: Literal["passthrough"] = "passthrough"
    fixed_idp_entity_id: str

    # --- session ---
    session_cookie_name: str = "fa_saml_session"
    session_secret: str
    session_ttl: int = 28800
    cookie_secure: bool = True

    # --- crypto / security ---
    xmlsec_binary: str = Field(default_factory=_default_xmlsec)
    want_assertions_signed: bool = True
    authn_requests_signed: bool = True

    @property
    def acs_url(self) -> str:
        """Absolute assertion-consumer-service URL."""
        return f"{self.base_url.rstrip('/')}{self.acs_path}"
