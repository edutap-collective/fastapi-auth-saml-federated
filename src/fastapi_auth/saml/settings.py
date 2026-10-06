"""Configuration for the SAML2 service provider (pydantic-settings).

Supports single-IdP direct metadata as well as federation metadata sources
(aggregate, MDQ) and discovery modes (passthrough, external, embedded).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_xmlsec() -> str:
    return shutil.which("xmlsec1") or "/usr/bin/xmlsec1"


def check_signature_requirement(settings: SamlSettings) -> None:
    """Raise ``ValueError`` unless an IdP signature is required on the assertion or response.

    Called when ``SamlSettings`` is validated and again when the pysaml2
    config is built, because the settings stay mutable after validation.
    """
    if not (settings.want_assertions_signed or settings.want_response_signed):
        msg = (
            "At least one of want_assertions_signed or want_response_signed must be True; "
            "otherwise unsigned SAML responses are accepted"
        )
        raise ValueError(msg)


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
    # Asymmetric algorithms (RS256, EdDSA, ...) sign with a private key and
    # verify with the corresponding public key, so parties that only hold the
    # public key can verify tokens without being able to mint them.
    jwt_private_key_file: str | None = None
    jwt_public_key_file: str | None = None
    # Data-minimisation: when set, only these FederatedIdentity field names are
    # carried in the token's "attrs" claim (smaller cookies, less PII in transit).
    jwt_attributes: list[str] | None = None

    # --- crypto / security ---
    xmlsec_binary: str = Field(default_factory=_default_xmlsec)
    # Which IdP signature the SP demands: on the assertion (default), on the
    # response, or on both. At least one must be True (see _check_signature_requirement).
    want_assertions_signed: bool = True
    want_response_signed: bool = False
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

    # --- IdP-initiated (unsolicited) login (opt-in; defaults keep it disabled) ---
    allow_idp_initiated: bool = False
    # Landing target used when the IdP does not send a RelayState.
    idp_initiated_default_relay_state: str = "/"
    # Replay-cache window (seconds), sized to the assertion's validity period.
    assertion_replay_ttl: int = 300

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

    @property
    def slo_path(self) -> str:
        """Path (relative to the mount root) of the logout endpoint (POST target)."""
        return f"{self.mount_path}/slo"

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

    def jwt_is_symmetric(self) -> bool:
        """Return whether ``jwt_alg`` is a symmetric (HMAC) algorithm."""
        return self.jwt_alg.startswith("HS")

    @property
    def jwt_signing_key(self) -> str:
        """Key used to sign app JWTs: the shared secret, or the PEM private key."""
        if self.jwt_is_symmetric():
            return self.jwt_signing_secret
        if self.jwt_private_key_file is None:
            # Unreachable when backend="jwt": _check_jwt_secret_strength enforces this.
            msg = "jwt_private_key_file is required for an asymmetric jwt_alg"
            raise ValueError(msg)
        return Path(self.jwt_private_key_file).read_text()

    @property
    def jwt_verifying_key(self) -> str:
        """Key used to verify app JWTs: the shared secret, or the PEM public key."""
        if self.jwt_is_symmetric():
            return self.jwt_signing_secret
        if self.jwt_public_key_file is None:
            # Unreachable when backend="jwt": _check_jwt_secret_strength enforces this.
            msg = "jwt_public_key_file is required for an asymmetric jwt_alg"
            raise ValueError(msg)
        return Path(self.jwt_public_key_file).read_text()

    @model_validator(mode="after")
    def _check_jwt_secret_strength(self) -> SamlSettings:
        """Validate that the JWT backend has strong-enough key material.

        Symmetric algorithms (HS*) need a shared secret of at least 32 bytes;
        asymmetric algorithms (RS256, EdDSA, ...) need both a private and a
        public key file. Files are only checked for presence here, never
        read -- reading happens lazily via ``jwt_signing_key``/``jwt_verifying_key``.
        """
        if self.backend != "jwt":
            return self
        if self.jwt_is_symmetric():
            if len(self.jwt_signing_secret.encode()) < 32:
                msg = "JWT backend requires jwt_secret/session_secret of at least 32 bytes"
                raise ValueError(msg)
        elif not (self.jwt_private_key_file and self.jwt_public_key_file):
            msg = (
                "JWT backend with an asymmetric jwt_alg requires both "
                "jwt_private_key_file and jwt_public_key_file"
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _check_signature_requirement(self) -> SamlSettings:
        """Refuse a configuration that would accept unsigned SAML responses.

        With neither ``want_assertions_signed`` nor ``want_response_signed``,
        pysaml2 accepts a response in which nothing is signed -- anyone could
        then post a forged login to the ACS.
        """
        check_signature_requirement(self)
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
