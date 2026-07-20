"""Tests for asymmetric JWT (RS256/EdDSA) file-based keys and alg pinning.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from pathlib import Path
from typing import Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi import Request, Response
from pydantic import ValidationError

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.jwt import JWTBackend
from fastapi_auth.saml.settings import SamlSettings

_BASE: dict[str, Any] = dict(
    entity_id="urn:test:sp",
    base_url="https://sp.example",
    key_file="/tmp/k",
    cert_file="/tmp/c",
    fixed_idp_entity_id="urn:test:idp",
    session_secret="s" * 40,
    backend="jwt",
    cookie_secure=False,
)


def _write_rsa_keypair(tmp_path: Path) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / "rsa_private.pem"
    pub_path = tmp_path / "rsa_public.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return str(priv_path), str(pub_path)


def _write_ed25519_keypair(tmp_path: Path) -> tuple[str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / "ed25519_private.pem"
    pub_path = tmp_path / "ed25519_public.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return str(priv_path), str(pub_path)


@pytest.fixture
def rsa_keys(tmp_path: Path) -> tuple[str, str]:
    return _write_rsa_keypair(tmp_path)


@pytest.fixture
def ed25519_keys(tmp_path: Path) -> tuple[str, str]:
    return _write_ed25519_keypair(tmp_path)


def _request(headers: list[tuple[bytes, bytes]]) -> Request:
    return Request({"type": "http", "headers": headers})


def _settings(jwt_alg: str, private_key_file: str, public_key_file: str) -> SamlSettings:
    return SamlSettings(
        **cast(
            dict[str, Any],
            {
                **_BASE,
                "jwt_alg": jwt_alg,
                "jwt_private_key_file": private_key_file,
                "jwt_public_key_file": public_key_file,
            },
        )
    )


@pytest.mark.parametrize("jwt_alg", ["RS256", "EdDSA"])
async def test_establish_and_load_roundtrip(
    jwt_alg: str, rsa_keys: tuple[str, str], ed25519_keys: tuple[str, str]
) -> None:
    priv, pub = rsa_keys if jwt_alg == "RS256" else ed25519_keys
    backend = JWTBackend(_settings(jwt_alg, priv, pub))
    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), response)
    token = response.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    req = _request([(b"cookie", f"fa_saml_session={token}".encode())])

    loaded = await backend.load(req)

    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"
    assert loaded.mail == ["u@lmu.de"]


@pytest.mark.parametrize("jwt_alg", ["RS256", "EdDSA"])
async def test_load_rejects_token_signed_with_wrong_key(
    jwt_alg: str, rsa_keys: tuple[str, str], ed25519_keys: tuple[str, str], tmp_path: Path
) -> None:
    priv, pub = rsa_keys if jwt_alg == "RS256" else ed25519_keys
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_priv, _other_pub = (
        _write_rsa_keypair(other_dir) if jwt_alg == "RS256" else _write_ed25519_keypair(other_dir)
    )
    backend = JWTBackend(_settings(jwt_alg, priv, pub))

    # Mint a token with an unrelated key, matching alg/claims shape.
    forged = jwt.encode(
        {"sub": "attacker", "attrs": {"eppn": "attacker@evil.example"}},
        Path(other_priv).read_text(),
        algorithm=jwt_alg,
    )
    req = _request([(b"authorization", f"Bearer {forged}".encode())])

    assert await backend.load(req) is None


async def test_load_rejects_tampered_token(rsa_keys: tuple[str, str]) -> None:
    priv, pub = rsa_keys
    backend = JWTBackend(_settings("RS256", priv, pub))
    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de"), response)
    token = response.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    header, payload, signature = token.split(".")
    # Flip a character in the middle of the payload (not the last char of a
    # base64url group, whose low bits can be padding-insignificant and thus
    # decode unchanged) so the signature verification is guaranteed to fail.
    mid = len(payload) // 2
    flipped = "A" if payload[mid] != "A" else "B"
    tampered_payload = payload[:mid] + flipped + payload[mid + 1 :]
    tampered = f"{header}.{tampered_payload}.{signature}"
    req = _request([(b"authorization", f"Bearer {tampered}".encode())])

    assert await backend.load(req) is None


def test_asymmetric_backend_without_key_files_raises(rsa_keys: tuple[str, str]) -> None:
    with pytest.raises(ValidationError):
        SamlSettings(**cast(dict[str, Any], {**_BASE, "jwt_alg": "RS256"}))


def test_asymmetric_backend_with_only_private_key_raises(rsa_keys: tuple[str, str]) -> None:
    priv, _pub = rsa_keys
    with pytest.raises(ValidationError):
        SamlSettings(
            **cast(
                dict[str, Any],
                {**_BASE, "jwt_alg": "RS256", "jwt_private_key_file": priv},
            )
        )


def test_symmetric_backend_ignores_missing_key_files() -> None:
    s = SamlSettings(**cast(dict[str, Any], {**_BASE, "jwt_alg": "HS256"}))
    assert s.jwt_is_symmetric() is True
    assert s.jwt_signing_key == s.jwt_signing_secret
    assert s.jwt_verifying_key == s.jwt_signing_secret
