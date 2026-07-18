"""Tests for the actionable RuntimeError when an optional store extra is missing.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import builtins
from typing import Any

import pytest

from fastapi_auth.saml.settings import SamlSettings

_BASE: dict[str, Any] = dict(
    entity_id="urn:test:sp",
    base_url="https://sp.example",
    key_file="/tmp/k",
    cert_file="/tmp/c",
    fixed_idp_entity_id="urn:test:idp",
    session_secret="x",
)


def test_postgres_extra_missing_raises_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    """make_store(store='postgres') without sqlalchemy raises an actionable RuntimeError."""
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("fastapi_auth.saml.session.postgres_store") or name == "sqlalchemy":
            raise ModuleNotFoundError("No module named 'sqlalchemy'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    from fastapi_auth.saml.factory import make_store

    settings = SamlSettings(**_BASE, store="postgres")
    with pytest.raises(RuntimeError, match="postgres") as exc_info:
        make_store(settings)

    # Make sure we hit the factory's actionable RuntimeError, not some other
    # error accidentally matching "postgres" (e.g. a re-raised ModuleNotFoundError).
    assert exc_info.type is RuntimeError
    assert "postgres" in str(exc_info.value)
    assert "extra" in str(exc_info.value)
    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, ModuleNotFoundError)


def test_redis_extra_missing_raises_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    """make_store(store='redis') without the redis package raises an actionable RuntimeError."""
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("fastapi_auth.saml.session.redis_store") or name == "redis":
            raise ModuleNotFoundError("No module named 'redis'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    from fastapi_auth.saml.factory import make_store

    settings = SamlSettings(**_BASE, store="redis")
    with pytest.raises(RuntimeError, match="redis") as exc_info:
        make_store(settings)

    assert exc_info.type is RuntimeError
    assert "redis" in str(exc_info.value)
    assert "extra" in str(exc_info.value)
    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, ModuleNotFoundError)
