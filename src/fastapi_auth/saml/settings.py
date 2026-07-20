"""Configuration for the SAML2 service provider (pydantic-settings).

Supports single-IdP direct metadata as well as federation metadata sources
(aggregate, MDQ) and discovery modes (passthrough, external, embedded).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import shutil
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_xmlsec() -> str:
    return shutil.which("xmlsec1") or "/usr/bin/xmlsec1"


class SamlSettings(BaseSettings):
    """Service-provider settings, populated from environment (prefix ``SAML_``)."""

    model_config = SettingsConfigDict(env_prefix="SAML_", env_file=".env", extra="ignore")

    # --- service provider ---
    entity_id: str
    base_url: str
    mount_path: str = "/saml"
    key_file: str
    cert_file: str

    # --- metadata / trust ---
    metadata_source: Literal["direct", "aggregate", "mdq"] = "direct"
    idp_metadata_file: str | None = None
    idp_metadata_url: str | None = None
    aggregate_file: str | None = None
    aggregate_url: str | None = None
    mdq_url: str | None = None
    trust_anchor_cert: str | None = None

    # --- discovery ---
    discovery_mode: Literal["passthrough", "external", "embedded"] = "passthrough"
    fixed_idp_entity_id: str
    ds_url: str | None = None
    metadata_langpref: str = "en"

    # --- session ---
    session_cookie_name: str = "fa_saml_session"
    session_secret: str
    session_ttl: int = 28800
    cookie_secure: bool = True
    # In-flight AuthnRequest lifetime (seconds); short-lived, unrelated to session_ttl.
    outstanding_ttl: int = 300

    # --- session backend / store selection ---
    backend: Literal["cookie", "jwt"] = "cookie"
    store: Literal["memory", "redis", "postgres"] = "memory"
    redis_url: str = "redis://localhost:6379/0"
    db_url: str = "sqlite+aiosqlite:///:memory:"

    # --- JWT backend (opt-in) ---
    jwt_alg: str = "HS256"
    jwt_ttl: int = 3600
    jwt_secret: str | None = None

    # --- crypto / security ---
    xmlsec_binary: str = Field(default_factory=_default_xmlsec)
    want_assertions_signed: bool = True
    authn_requests_signed: bool = True

    # --- SP profile: identifier selection (Spec §5.1) ---
    identifier: str = "subject_id"
    identifier_fallback: list[str] = Field(default_factory=lambda: ["pairwise_id", "eppn"])

    # --- SP profile: requested attributes (friendly names) ---
    required_attributes: list[str] = Field(default_factory=list)
    optional_attributes: list[str] = Field(default_factory=list)

    # --- SP profile: metadata UI / GDPR ---
    entity_categories: list[str] = Field(default_factory=list)
    sp_display_name: str | None = None
    sp_description: str | None = None
    privacy_statement_url: str | None = None

    # --- security ---
    allowed_redirect_hosts: list[str] = Field(default_factory=list)

    # --- decryption (defaults to the signing key/cert pair) ---
    encryption_key_file: str | None = None
    encryption_cert_file: str | None = None

    @property
    def acs_path(self) -> str:
        """Path (relative to the mount root) of the assertion-consumer-service endpoint."""
        return f"{self.mount_path}/acs"

    @property
    def acs_url(self) -> str:
        """Absolute assertion-consumer-service URL."""
        return f"{self.base_url.rstrip('/')}{self.acs_path}"

    @property
    def wayf_login_path(self) -> str:
        """Path (relative to the mount root) of the embedded-discovery login endpoint."""
        return f"{self.mount_path}/login"

    def absolute_url(self, subpath: str) -> str:
        """Build an absolute SP URL for ``subpath`` under ``mount_path`` (e.g. ``/disco``)."""
        return f"{self.base_url.rstrip('/')}{self.mount_path}{subpath}"

    @property
    def enc_key_file(self) -> str:
        """Private key used to decrypt EncryptedAssertions (defaults to signing key)."""
        return self.encryption_key_file or self.key_file

    @property
    def enc_cert_file(self) -> str:
        """Certificate advertised for assertion encryption (defaults to signing cert)."""
        return self.encryption_cert_file or self.cert_file

    @property
    def jwt_signing_secret(self) -> str:
        """Secret/key used to sign app JWTs (defaults to the session secret)."""
        return self.jwt_secret or self.session_secret

    @model_validator(mode="after")
    def _check_jwt_secret_strength(self) -> SamlSettings:
        """Validate that JWT backend has a strong enough secret."""
        if self.backend == "jwt" and len(self.jwt_signing_secret.encode()) < 32:
            msg = "JWT backend requires jwt_secret/session_secret of at least 32 bytes"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _check_federation_config(self) -> SamlSettings:
        """Validate that metadata-source and discovery-mode selections have required inputs."""
        if self.metadata_source == "mdq" and not self.mdq_url:
            msg = "metadata_source='mdq' requires mdq_url"
            raise ValueError(msg)
        if self.metadata_source == "mdq" and not self.trust_anchor_cert:
            msg = "metadata_source='mdq' requires trust_anchor_cert (metadata must be verified)"
            raise ValueError(msg)
        if self.metadata_source == "aggregate" and not (self.aggregate_file or self.aggregate_url):
            msg = "metadata_source='aggregate' requires aggregate_file or aggregate_url"
            raise ValueError(msg)
        if (
            self.metadata_source == "aggregate"
            and self.aggregate_url
            and not self.trust_anchor_cert
        ):
            msg = "metadata_source='aggregate' with aggregate_url requires trust_anchor_cert"
            raise ValueError(msg)
        if self.discovery_mode == "external" and not self.ds_url:
            msg = "discovery_mode='external' requires ds_url"
            raise ValueError(msg)
        return self
