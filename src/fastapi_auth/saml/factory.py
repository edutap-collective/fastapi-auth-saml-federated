"""Build the Store and SessionBackend from settings.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.saml.session.base import SessionBackend
from fastapi_auth.saml.session.cookie import CookieBackend
from fastapi_auth.saml.session.jwt import JWTBackend
from fastapi_auth.saml.session.store import MemoryStore, Store
from fastapi_auth.saml.settings import SamlSettings


def make_store(settings: SamlSettings) -> Store:
    """Construct the configured Store backend."""
    if settings.store == "redis":
        try:
            from fastapi_auth.saml.session.redis_store import RedisStore
        except ModuleNotFoundError as err:
            msg = (
                "RedisStore requires the 'redis' extra: "
                "pip install 'fastapi-auth-saml-federated[redis]'"
            )
            raise RuntimeError(msg) from err
        return RedisStore.from_url(settings.redis_url)
    if settings.store == "postgres":
        try:
            from fastapi_auth.saml.session.postgres_store import PostgresStore
        except ModuleNotFoundError as err:
            msg = (
                "PostgresStore requires the 'postgres' extra: "
                "pip install 'fastapi-auth-saml-federated[postgres]'"
            )
            raise RuntimeError(msg) from err
        return PostgresStore.from_url(settings.db_url)
    return MemoryStore()


def make_backend(settings: SamlSettings, store: Store) -> SessionBackend:
    """Construct the configured SessionBackend."""
    if settings.backend == "jwt":
        return JWTBackend(settings)
    return CookieBackend(settings, store)
