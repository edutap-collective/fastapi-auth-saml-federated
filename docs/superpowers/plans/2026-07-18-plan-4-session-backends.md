# Plan 4 — Session-Backends & Scale-out (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Das Session-Layer produktionstauglich & wählbar machen: ein sauberes
`Store`-Protocol mit **Memory / Redis / Postgres**-Implementierungen (via Settings
wählbar) und ein **JWT-Backend** (opt-in, stateless) neben dem bestehenden
Cookie-Backend — beides über eine Factory in `SamlSP` verdrahtet.

**Architecture:** Der `Store` wird zum Protocol mit relativer TTL auf Schreib-Ops und
einer injizierten Clock (lazy expiry beim Lesen — kein `purge_expired`/`now` mehr in
der öffentlichen API). `MemoryStore` wird darauf refactored; `RedisStore`
(redis.asyncio, native TTL) und `PostgresStore` (SQLModel async, `expires_at`-Spalten)
kommen dazu. Das `JWTBackend` (PyJWT) trägt die Identität stateless im Token
(Cookie *und* `Authorization: Bearer`). Eine Factory baut aus den Settings Store +
Backend. Baut additiv auf Plan 1–3.

**Tech Stack:** wie Plan 3 + **PyJWT** (core), **redis** (Extra `[redis]`),
**SQLModel + asyncpg** (Extra `[postgres]`); Tests: **fakeredis** (async), **aiosqlite**.
Alle drei Backend-Mechaniken im Spike verifiziert (fakeredis async, SQLModel+aiosqlite, PyJWT).

## Global Constraints

- Baut additiv auf Plan 1–3; deren öffentliche API/Verhalten NICHT brechen (Cookie-Default bleibt Default).
- Namespace `fastapi_auth` bleibt PEP-420-implizit (kein `src/fastapi_auth/__init__.py`).
- async-first: Redis via `redis.asyncio`, Postgres via SQLAlchemy/SQLModel async; keine blockierenden Calls im Event-Loop.
- Milestone-Scope: JWT-Backend + Store-Backends (Memory/Redis/Postgres) + Auswahl-Factory. **NICHT** hier:
  MDQ/Aggregat/DS/WAYF/SLO (Plan 5), Docker/CI/Doku (Plan 6).
- **JWT-Secret ≥ 32 Byte** wenn `backend="jwt"` (Validator) — sonst löst PyJWTs `InsecureKeyLengthWarning`
  unter `filterwarnings=["error"]` einen Fehler aus, und der Key wäre real zu schwach. Cookie-Backend bleibt unberührt (itsdangerous).
- Redis/Postgres sind **optionale Extras** (`pip install ...[redis]` / `[postgres]`); Import erst bei Nutzung,
  klare Fehlermeldung wenn das Extra fehlt.
- `FederatedIdentity` wird für Redis/Postgres via `model_dump_json()` / `model_validate_json()` (de)serialisiert.
- English code/docstrings; SPDX header `SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2` in neuen Quelldateien.
- ruff `E,F,W,B,UP,I,D,S` (Tests ignorieren `S101`/`D`); `ty` 0 Diagnosen; `make lint` exit 0; `# ty: ignore[<code>]` nur gezielt mit Begründung.
- Commit auf `main` (user-autorisiert), Conventional Commits **Deutsch**, kein `git push`. Autor-Schreibweise: **Loechel** (oe).
- TDD: erst Test (rot), dann Implementierung (grün), dann Commit. Vor jedem Commit: `make lint` grün + volle Suite grün. Lint-Ausgabe im Report belegen (nicht nur behaupten).

## File Structure

```text
src/fastapi_auth/saml/
  settings.py                 # + backend/store/jwt-Felder + jwt-secret-Validator (erweitern)
  session/
    store.py                  # Store (Protocol) + MemoryStore refactor (ttl + Clock, lazy expiry)
    redis_store.py            # NEU: RedisStore (redis.asyncio, native TTL)
    postgres_store.py         # NEU: PostgresStore (SQLModel async, expires_at)
    cookie.py                 # establish: save_session(sid, identity, ttl) (anpassen)
    jwt.py                    # NEU: JWTBackend (PyJWT; Cookie + Bearer)
    factory.py                # NEU: make_store(settings) + make_backend(settings, store)
  sp.py                       # Store/Backend via Factory statt fest (anpassen)
  router.py                   # /login: add_outstanding(reqid, next, ttl); kein purge/now mehr (anpassen)
tests/
  session/test_store.py             # an neue Store-API anpassen (ttl + FakeClock, lazy expiry)
  session/test_redis_store.py       # NEU (fakeredis)
  session/test_postgres_store.py    # NEU (aiosqlite)
  session/test_jwt_backend.py       # NEU (PyJWT)
  test_factory.py                   # NEU: Auswahl memory/redis/postgres, cookie/jwt
  test_router_jwt_flow.py           # NEU: end-to-end Login mit backend="jwt"
```

---

## Task 1: Dependencies + Session-Settings

**Files:**
- Modify: `pyproject.toml`, `src/fastapi_auth/saml/settings.py`
- Test: `tests/test_settings.py`

**Interfaces:**
- Consumes: bestehende `SamlSettings`.
- Produces: neue Felder:
  - `backend: Literal["cookie", "jwt"] = "cookie"`
  - `store: Literal["memory", "redis", "postgres"] = "memory"`
  - `redis_url: str = "redis://localhost:6379/0"`
  - `db_url: str = "sqlite+aiosqlite:///:memory:"`
  - `jwt_alg: str = "HS256"`, `jwt_ttl: int = 3600`
  - `jwt_secret: str | None = None`; Property `jwt_signing_secret -> str` (= `jwt_secret or session_secret`)
  - `model_validator(mode="after")`: wenn `backend == "jwt"` und `len(jwt_signing_secret) < 32` → `ValueError`.
- pyproject: `pyjwt>=2.8` in core `dependencies`; Extras `redis = ["redis>=5"]`, `postgres = ["sqlmodel>=0.0.22", "asyncpg>=0.29"]`; dev-Extra + `"fakeredis>=2.20"`, `"aiosqlite>=0.20"`, `"redis>=5"`, `"sqlmodel>=0.0.22"`.

- [ ] **Step 1: Failing test schreiben**

Ergänze in `tests/test_settings.py`:

```python
import pytest
from pydantic import ValidationError


def test_backend_store_defaults():
    s = SamlSettings(**_BASE)
    assert s.backend == "cookie"
    assert s.store == "memory"
    assert s.jwt_alg == "HS256"


def test_jwt_signing_secret_defaults_to_session_secret():
    s = SamlSettings(**{**_BASE, "session_secret": "x" * 40})
    assert s.jwt_signing_secret == "x" * 40


def test_jwt_backend_requires_strong_secret():
    with pytest.raises(ValidationError, match="32"):
        SamlSettings(**{**_BASE, "backend": "jwt", "session_secret": "short"})


def test_jwt_backend_accepts_strong_secret():
    s = SamlSettings(**{**_BASE, "backend": "jwt", "session_secret": "s" * 32})
    assert s.backend == "jwt"
```

> `_BASE` in `tests/test_settings.py` nutzt `session_secret="s3cr3t"` (6 Byte) — das ist für den
> Cookie-Default ok; nur die JWT-Tests setzen ein ≥32-Byte-Secret.

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_settings.py -v -k "backend or jwt"`
Expected: FAIL (Felder/Validator fehlen).

- [ ] **Step 3: Dependencies + Settings**

`pyproject.toml`: `dependencies` um `"pyjwt>=2.8"` ergänzen; unter `[project.optional-dependencies]`:

```toml
redis = ["redis>=5"]
postgres = ["sqlmodel>=0.0.22", "asyncpg>=0.29"]
```

und im `dev`-Extra ergänzen: `"fakeredis>=2.20"`, `"aiosqlite>=0.20"`, `"redis>=5"`, `"sqlmodel>=0.0.22"`.

Run danach: `uv pip install -U -e ".[dev]"`.

In `settings.py` neue Felder (nach den Session-Feldern) + Validator:

```python
    # --- session backend / store selection ---
    backend: Literal["cookie", "jwt"] = "cookie"
    store: Literal["memory", "redis", "postgres"] = "memory"
    redis_url: str = "redis://localhost:6379/0"
    db_url: str = "sqlite+aiosqlite:///:memory:"

    # --- JWT backend (opt-in) ---
    jwt_alg: str = "HS256"
    jwt_ttl: int = 3600
    jwt_secret: str | None = None
```

Property + Validator (Import `model_validator` aus pydantic):

```python
    @property
    def jwt_signing_secret(self) -> str:
        """Secret/key used to sign app JWTs (defaults to the session secret)."""
        return self.jwt_secret or self.session_secret

    @model_validator(mode="after")
    def _check_jwt_secret_strength(self) -> "SamlSettings":
        if self.backend == "jwt" and len(self.jwt_signing_secret) < 32:
            msg = "JWT backend requires jwt_secret/session_secret of at least 32 bytes"
            raise ValueError(msg)
        return self
```

- [ ] **Step 4: Test grün + lint**

Run: `uv run pytest tests/test_settings.py -v && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: passed; clean; ty 0. Belege die ruff/ty-Ausgabe im Report.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/fastapi_auth/saml/settings.py tests/test_settings.py
git commit -m "feat(settings): Backend-/Store-Auswahl + JWT-Config + Secret-Stärke-Validator; pyjwt/redis/postgres-Extras"
```

---

## Task 2: Store-Protocol + MemoryStore-Refactor (relative TTL + Clock)

**Files:**
- Modify: `src/fastapi_auth/saml/session/store.py`, `src/fastapi_auth/saml/session/cookie.py`, `src/fastapi_auth/saml/router.py`
- Test: `tests/session/test_store.py`, `tests/session/test_cookie.py`, `tests/test_router_login_flow.py`, `tests/test_router_enforcement_flow.py`

**Interfaces:**
- Produces `Store` (Protocol) — alle Methoden async:
  - `save_session(sid: str, identity: FederatedIdentity, ttl: int) -> None`
  - `load_session(sid: str) -> FederatedIdentity | None`
  - `delete_session(sid: str) -> None`
  - `add_outstanding(request_id: str, return_url: str, ttl: int) -> None`
  - `outstanding() -> dict[str, str]` (nur nicht-abgelaufene)
  - `pop_outstanding(request_id: str) -> str | None`
- `MemoryStore(clock: Callable[[], float] = time.monotonic)` erfüllt `Store`; speichert Werte mit `expires_at = clock() + ttl`; lazy expiry beim Lesen (`load_session`/`outstanding`/`pop_outstanding` filtern abgelaufene und entfernen sie).
- **Migration (kein `purge_expired`/`now` mehr):**
  - `cookie.py` `establish`: `await self._store.save_session(sid, identity, self._settings.session_ttl)`.
  - `router.py` `/login`: `await sp.store.add_outstanding(request_id, safe_next, sp.settings.outstanding_ttl)`; `/acs`: entferne den `purge_expired(...)`-Aufruf und den `time.monotonic()`-Aufruf für Outstanding (lazy expiry im Store); `pop_outstanding(in_response_to)` bleibt.
  - Tests, die die alte Signatur nutzen (`add_outstanding(rid, url, now)`, `purge_expired`, `save_session(sid, identity)`), auf die neue API umstellen; `MemoryStore(clock=fake_clock)` mit steuerbarer Zeit für Expiry-Tests.

- [ ] **Step 1: Store-Tests auf neue API + Expiry umschreiben (rot)**

Ersetze `tests/session/test_store.py` durch:

```python
"""Tests for the in-memory Store (ttl + injectable clock, lazy expiry)."""

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.store import MemoryStore


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


async def test_session_roundtrip():
    store = MemoryStore()
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de"), ttl=300)
    loaded = await store.load_session("s1")
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_session_expires():
    clock = _Clock()
    store = MemoryStore(clock=clock)
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de"), ttl=100)
    clock.t = 101.0
    assert await store.load_session("s1") is None


async def test_delete_session():
    store = MemoryStore()
    await store.save_session("s1", FederatedIdentity(), ttl=300)
    await store.delete_session("s1")
    assert await store.load_session("s1") is None


async def test_outstanding_roundtrip_and_pop():
    store = MemoryStore()
    await store.add_outstanding("r1", "/app", ttl=300)
    await store.add_outstanding("r2", "/other", ttl=300)
    assert await store.outstanding() == {"r1": "/app", "r2": "/other"}
    assert await store.pop_outstanding("r1") == "/app"
    assert await store.outstanding() == {"r2": "/other"}
    assert await store.pop_outstanding("gone") is None


async def test_outstanding_expires():
    clock = _Clock()
    store = MemoryStore(clock=clock)
    await store.add_outstanding("r1", "/app", ttl=100)
    clock.t = 101.0
    assert await store.outstanding() == {}
    assert await store.pop_outstanding("r1") is None
```

- [ ] **Step 2: Rot** — `uv run pytest tests/session/test_store.py -v` → FAIL (neue Signaturen fehlen).

- [ ] **Step 3: `store.py` refactor**

```python
"""In-memory Store + Store protocol (ttl-based, injectable clock, lazy expiry).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from fastapi_auth.saml.identity.model import FederatedIdentity


class Store(Protocol):
    """Session + outstanding-request storage backend."""

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None: ...
    async def load_session(self, sid: str) -> FederatedIdentity | None: ...
    async def delete_session(self, sid: str) -> None: ...
    async def add_outstanding(self, request_id: str, return_url: str, ttl: int) -> None: ...
    async def outstanding(self) -> dict[str, str]: ...
    async def pop_outstanding(self, request_id: str) -> str | None: ...


class MemoryStore:
    """Non-persistent Store (single process) with lazy TTL expiry."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._sessions: dict[str, tuple[FederatedIdentity, float]] = {}
        self._outstanding: dict[str, tuple[str, float]] = {}

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        self._sessions[sid] = (identity, self._clock() + ttl)

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        item = self._sessions.get(sid)
        if item is None:
            return None
        identity, expires_at = item
        if self._clock() > expires_at:
            self._sessions.pop(sid, None)
            return None
        return identity

    async def delete_session(self, sid: str) -> None:
        self._sessions.pop(sid, None)

    async def add_outstanding(self, request_id: str, return_url: str, ttl: int) -> None:
        self._outstanding[request_id] = (return_url, self._clock() + ttl)

    async def outstanding(self) -> dict[str, str]:
        now = self._clock()
        live = {rid: url for rid, (url, exp) in self._outstanding.items() if now <= exp}
        self._outstanding = {rid: self._outstanding[rid] for rid in live}
        return live

    async def pop_outstanding(self, request_id: str) -> str | None:
        item = self._outstanding.pop(request_id, None)
        if item is None:
            return None
        url, expires_at = item
        return url if self._clock() <= expires_at else None
```

- [ ] **Step 4: `cookie.py` + `router.py` migrieren**

- `cookie.py` `establish`: `await self._store.save_session(sid, identity, self._settings.session_ttl)`.
- `router.py` `/login`: `await sp.store.add_outstanding(request_id, safe_next, sp.settings.outstanding_ttl)`.
- `router.py` `/acs`: entferne `await sp.store.purge_expired(...)` und den zugehörigen `time.monotonic()`; `outstanding = await sp.store.outstanding()` bleibt; `pop_outstanding(in_response_to)` bleibt. Falls dadurch `import time` in `router.py` ungenutzt wird, entfernen.

- [ ] **Step 5: betroffene Tests migrieren**

`tests/session/test_cookie.py`: der Aufruf `establish` bleibt gleich (nutzt intern `save_session` mit ttl) — nur prüfen, dass es grün ist. Falls ein Test `save_session(sid, identity)` (ohne ttl) direkt aufruft, ttl ergänzen.
`tests/test_router_login_flow.py` / `tests/test_router_enforcement_flow.py`: falls sie `sp.store._outstanding[reqid]` white-box lesen, ist das Tupel weiterhin `(url, expires_at)` — Index `[0]` bleibt korrekt. Reqid-Auslesen via `list(sp.store._outstanding)` bleibt. Keine `purge_expired`-Aufrufe in Tests.

- [ ] **Step 6: Grün + volle Suite + lint**

Run: `uv run pytest && uv run ruff format . && uv run ruff check . && uv run ty check src tests && make lint`
Expected: alle Tests grün (Plan 1–3 inklusive); ruff clean; ty 0; make lint exit 0. Belege im Report.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(session): Store-Protocol + MemoryStore auf ttl/Clock (lazy expiry); Cookie/Router migriert"
```

---

## Task 3: RedisStore

**Files:**
- Create: `src/fastapi_auth/saml/session/redis_store.py`
- Test: `tests/session/test_redis_store.py`

**Interfaces:**
- `RedisStore(client, *, session_prefix="fa:sess:", outstanding_prefix="fa:out:")` erfüllt `Store`. Nutzt `redis.asyncio.Redis`. Sessions/Outstanding als Keys mit **nativer TTL** (`await client.set(key, value, ex=ttl)`); `FederatedIdentity` via `model_dump_json()`; `outstanding()` via `SCAN` über `outstanding_prefix`.
- Klassenmethode `from_url(url: str) -> RedisStore` (importiert `redis.asyncio`; wirf klare Fehlermeldung wenn `redis` fehlt).

- [ ] **Step 1: Failing test (fakeredis)**

`tests/session/test_redis_store.py`:

```python
"""Tests for RedisStore using fakeredis (no real server)."""

import fakeredis.aioredis
import pytest

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.redis_store import RedisStore


@pytest.fixture
def store():
    return RedisStore(fakeredis.aioredis.FakeRedis())


async def test_session_roundtrip(store):
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), ttl=300)
    loaded = await store.load_session("s1")
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"
    assert loaded.mail == ["u@lmu.de"]


async def test_missing_session(store):
    assert await store.load_session("nope") is None


async def test_delete_session(store):
    await store.save_session("s1", FederatedIdentity(), ttl=300)
    await store.delete_session("s1")
    assert await store.load_session("s1") is None


async def test_outstanding_roundtrip_and_pop(store):
    await store.add_outstanding("r1", "/app", ttl=300)
    await store.add_outstanding("r2", "/other", ttl=300)
    assert await store.outstanding() == {"r1": "/app", "r2": "/other"}
    assert await store.pop_outstanding("r1") == "/app"
    assert await store.outstanding() == {"r2": "/other"}
    assert await store.pop_outstanding("gone") is None
```

- [ ] **Step 2: Rot** — `uv run pytest tests/session/test_redis_store.py -v` → FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

```python
"""Redis-backed Store (redis.asyncio, native key TTL).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Any

from fastapi_auth.saml.identity.model import FederatedIdentity


class RedisStore:
    """Store backed by Redis; sessions/outstanding are keys with native TTL."""

    def __init__(
        self,
        client: Any,
        *,
        session_prefix: str = "fa:sess:",
        outstanding_prefix: str = "fa:out:",
    ) -> None:
        self._r = client
        self._sp = session_prefix
        self._op = outstanding_prefix

    @classmethod
    def from_url(cls, url: str) -> RedisStore:
        try:
            import redis.asyncio as redis_async
        except ModuleNotFoundError as err:  # pragma: no cover - import guard
            msg = "RedisStore requires the 'redis' extra: pip install 'fastapi-auth-saml-federated[redis]'"
            raise RuntimeError(msg) from err
        return cls(redis_async.from_url(url))

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        await self._r.set(f"{self._sp}{sid}", identity.model_dump_json(), ex=ttl)

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        raw = await self._r.get(f"{self._sp}{sid}")
        if raw is None:
            return None
        return FederatedIdentity.model_validate_json(raw)

    async def delete_session(self, sid: str) -> None:
        await self._r.delete(f"{self._sp}{sid}")

    async def add_outstanding(self, request_id: str, return_url: str, ttl: int) -> None:
        await self._r.set(f"{self._op}{request_id}", return_url, ex=ttl)

    async def outstanding(self) -> dict[str, str]:
        result: dict[str, str] = {}
        async for key in self._r.scan_iter(match=f"{self._op}*"):
            rid = (key.decode() if isinstance(key, bytes) else key)[len(self._op) :]
            value = await self._r.get(key)
            if value is not None:
                result[rid] = value.decode() if isinstance(value, bytes) else value
        return result

    async def pop_outstanding(self, request_id: str) -> str | None:
        key = f"{self._op}{request_id}"
        value = await self._r.get(key)
        if value is None:
            return None
        await self._r.delete(key)
        return value.decode() if isinstance(value, bytes) else value
```

- [ ] **Step 4: Grün + lint** — `uv run pytest tests/session/test_redis_store.py -v && uv run ruff check . && uv run ty check src tests` (belegen). `client: Any` → falls ty an `redis`-Aufrufen meckert, ist `Any` bereits permissiv; sonst gezielt kommentieren.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/session/redis_store.py tests/session/test_redis_store.py
git commit -m "feat(session): RedisStore (redis.asyncio, native TTL)"
```

---

## Task 4: PostgresStore (SQLModel async)

**Files:**
- Create: `src/fastapi_auth/saml/session/postgres_store.py`
- Test: `tests/session/test_postgres_store.py`

**Interfaces:**
- `PostgresStore(engine)` erfüllt `Store` (engine = SQLAlchemy async engine). Tabellen `SamlSession(sid PK, data, expires_at)` und `SamlOutstanding(request_id PK, return_url, expires_at)`; `expires_at` als Unix-Sekunde (`float`). Lazy expiry beim Lesen (Zeilen mit `expires_at < time.time()` werden als abwesend behandelt/gelöscht). `FederatedIdentity` via `model_dump_json`/`model_validate_json`.
- Klassenmethoden: `from_url(url) -> PostgresStore`; `async def create_all(self) -> None` (Tabellen anlegen — im Test genutzt).

> Zeitbasis hier bewusst `time.time()` (Wall-Clock), da persistent/cross-process; für Tests wird
> Ablauf über kurze `ttl` + reales Warten NICHT getestet (langsam) — stattdessen Roundtrip + Delete;
> ein Expiry-Test setzt `expires_at` direkt in der Vergangenheit.

- [ ] **Step 1: Failing test (aiosqlite)**

`tests/session/test_postgres_store.py`:

```python
"""Tests for PostgresStore against in-memory SQLite (aiosqlite)."""

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.postgres_store import PostgresStore


@pytest.fixture
async def store():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    s = PostgresStore(engine)
    await s.create_all()
    yield s
    await engine.dispose()


async def test_session_roundtrip(store):
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de"), ttl=300)
    loaded = await store.load_session("s1")
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_delete_session(store):
    await store.save_session("s1", FederatedIdentity(), ttl=300)
    await store.delete_session("s1")
    assert await store.load_session("s1") is None


async def test_expired_session_is_absent(store):
    await store.save_session("s1", FederatedIdentity(), ttl=-1)  # already expired
    assert await store.load_session("s1") is None


async def test_outstanding_roundtrip_and_pop(store):
    await store.add_outstanding("r1", "/app", ttl=300)
    assert await store.outstanding() == {"r1": "/app"}
    assert await store.pop_outstanding("r1") == "/app"
    assert await store.pop_outstanding("r1") is None
```

- [ ] **Step 2: Rot** — FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

```python
"""Postgres-backed Store via SQLModel async (test: SQLite/aiosqlite).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel, select

from fastapi_auth.saml.identity.model import FederatedIdentity


class SamlSession(SQLModel, table=True):
    sid: str = Field(primary_key=True)
    data: str
    expires_at: float


class SamlOutstanding(SQLModel, table=True):
    request_id: str = Field(primary_key=True)
    return_url: str
    expires_at: float


class PostgresStore:
    """Store backed by an async SQLAlchemy engine (Postgres in prod, SQLite in tests)."""

    def __init__(self, engine: Any) -> None:
        self._engine = engine

    @classmethod
    def from_url(cls, url: str) -> PostgresStore:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
        except ModuleNotFoundError as err:  # pragma: no cover - import guard
            msg = "PostgresStore requires the 'postgres' extra: pip install 'fastapi-auth-saml-federated[postgres]'"
            raise RuntimeError(msg) from err
        return cls(create_async_engine(url))

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        async with AsyncSession(self._engine) as s:
            await s.merge(SamlSession(sid=sid, data=identity.model_dump_json(), expires_at=time.time() + ttl))
            await s.commit()

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        async with AsyncSession(self._engine) as s:
            row = await s.get(SamlSession, sid)
            if row is None:
                return None
            if row.expires_at < time.time():
                await s.delete(row)
                await s.commit()
                return None
            return FederatedIdentity.model_validate_json(row.data)

    async def delete_session(self, sid: str) -> None:
        async with AsyncSession(self._engine) as s:
            row = await s.get(SamlSession, sid)
            if row is not None:
                await s.delete(row)
                await s.commit()

    async def add_outstanding(self, request_id: str, return_url: str, ttl: int) -> None:
        async with AsyncSession(self._engine) as s:
            await s.merge(SamlOutstanding(request_id=request_id, return_url=return_url, expires_at=time.time() + ttl))
            await s.commit()

    async def outstanding(self) -> dict[str, str]:
        now = time.time()
        async with AsyncSession(self._engine) as s:
            await s.execute(delete(SamlOutstanding).where(SamlOutstanding.expires_at < now))
            await s.commit()
            rows = (await s.execute(select(SamlOutstanding))).scalars().all()
            return {r.request_id: r.return_url for r in rows}

    async def pop_outstanding(self, request_id: str) -> str | None:
        async with AsyncSession(self._engine) as s:
            row = await s.get(SamlOutstanding, request_id)
            if row is None:
                return None
            url, expires_at = row.return_url, row.expires_at
            await s.delete(row)
            await s.commit()
            return url if expires_at >= time.time() else None
```

> Hinweis: SQLModel-`table=True`-Klassen sind global registriert; falls die Testsuite mehrfach importiert,
> genügt ein Import. Prüfe, dass `create_all` gegen aiosqlite die Tabellen anlegt (Spike bestätigt SQLModel async).

- [ ] **Step 4: Grün + lint** — `uv run pytest tests/session/test_postgres_store.py -v && uv run ruff check . && uv run ty check src tests` (belegen).

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/session/postgres_store.py tests/session/test_postgres_store.py
git commit -m "feat(session): PostgresStore (SQLModel async, expires_at)"
```

---

## Task 5: JWTBackend

**Files:**
- Create: `src/fastapi_auth/saml/session/jwt.py`
- Test: `tests/session/test_jwt_backend.py`

**Interfaces:**
- `JWTBackend(settings)` erfüllt `SessionBackend`. `establish`: baut Claims aus `FederatedIdentity` (`sub` = `select_identifier(...)` bzw. `identity.name_id`; `exp` = jetzt + `jwt_ttl`; `attrs` = `identity.model_dump(mode="json")`), signiert mit `jwt_signing_secret`/`jwt_alg`, setzt Cookie (Name `settings.session_cookie_name`, HttpOnly, Secure, SameSite=lax) **und** ist als Bearer nutzbar. `load`: liest Token aus Cookie ODER `Authorization: Bearer`, `jwt.decode(...)`, rekonstruiert `FederatedIdentity.model_validate(payload["attrs"])`; bei `InvalidTokenError` → `None`. `revoke`: löscht Cookie (stateless → keine Server-Invalidierung).

- [ ] **Step 1: Failing test**

`tests/session/test_jwt_backend.py`:

```python
"""Tests for the stateless JWT backend."""

from fastapi import Request, Response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.jwt import JWTBackend
from fastapi_auth.saml.settings import SamlSettings


def _settings() -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp", base_url="https://sp.example",
        key_file="/tmp/k", cert_file="/tmp/c", fixed_idp_entity_id="urn:test:idp",
        session_secret="s" * 40, backend="jwt", cookie_secure=False,
    )


def _request(headers: list[tuple[bytes, bytes]]) -> Request:
    return Request({"type": "http", "headers": headers})


async def test_establish_sets_cookie_and_load_from_cookie():
    backend = JWTBackend(_settings())
    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), response)
    set_cookie = response.headers["set-cookie"]
    token = set_cookie.split(";")[0].split("=", 1)[1]
    req = _request([(b"cookie", f"fa_saml_session={token}".encode())])
    loaded = await backend.load(req)
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"
    assert loaded.mail == ["u@lmu.de"]


async def test_load_from_bearer_header():
    backend = JWTBackend(_settings())
    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de"), response)
    token = response.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    req = _request([(b"authorization", f"Bearer {token}".encode())])
    loaded = await backend.load(req)
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_load_without_token_returns_none():
    assert await JWTBackend(_settings()).load(_request([])) is None


async def test_load_tampered_token_returns_none():
    backend = JWTBackend(_settings())
    req = _request([(b"authorization", b"Bearer not.a.jwt")])
    assert await backend.load(req) is None
```

- [ ] **Step 2: Rot** — FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

```python
"""Stateless JWT session backend (PyJWT).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time

import jwt
from fastapi import Request, Response

from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings


class JWTBackend:
    """Carries the identity in a signed JWT (cookie or Authorization: Bearer)."""

    def __init__(self, settings: SamlSettings) -> None:
        self._settings = settings

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        subject = select_identifier(identity, self._settings.identifier, self._settings.identifier_fallback)
        payload = {
            "sub": subject or identity.name_id or "",
            "exp": int(time.time()) + self._settings.jwt_ttl,
            "attrs": identity.model_dump(mode="json"),
        }
        token = jwt.encode(payload, self._settings.jwt_signing_secret, algorithm=self._settings.jwt_alg)
        response.set_cookie(
            self._settings.session_cookie_name,
            token,
            max_age=self._settings.jwt_ttl,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    async def load(self, request: Request) -> FederatedIdentity | None:
        token = self._token_from(request)
        if token is None:
            return None
        try:
            payload = jwt.decode(token, self._settings.jwt_signing_secret, algorithms=[self._settings.jwt_alg])
        except jwt.InvalidTokenError:
            return None
        return FederatedIdentity.model_validate(payload.get("attrs", {}))

    async def revoke(self, request: Request, response: Response) -> None:
        response.delete_cookie(self._settings.session_cookie_name)

    def _token_from(self, request: Request) -> str | None:
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:]
        return request.cookies.get(self._settings.session_cookie_name)
```

- [ ] **Step 4: Grün + lint** — `uv run pytest tests/session/test_jwt_backend.py -v && uv run ruff check . && uv run ty check src tests` (belegen). Achte darauf, dass das Test-Secret ≥32 Byte ist (sonst PyJWT-`InsecureKeyLengthWarning` → Fehler unter warnings-as-errors).

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/session/jwt.py tests/session/test_jwt_backend.py
git commit -m "feat(session): JWTBackend (stateless, Cookie + Bearer)"
```

---

## Task 6: Factory + SamlSP-Verdrahtung + End-to-End

**Files:**
- Create: `src/fastapi_auth/saml/factory.py`
- Modify: `src/fastapi_auth/saml/sp.py`
- Test: `tests/test_factory.py`, `tests/test_router_jwt_flow.py`

**Interfaces:**
- `factory.py`:
  - `make_store(settings) -> Store`: `memory` → `MemoryStore()`; `redis` → `RedisStore.from_url(settings.redis_url)`; `postgres` → `PostgresStore.from_url(settings.db_url)`.
  - `make_backend(settings, store) -> SessionBackend`: `cookie` → `CookieBackend(settings, store)`; `jwt` → `JWTBackend(settings)`.
- `sp.py`: `SamlSP.__init__` nutzt `self.store = make_store(settings)` und `self.backend = make_backend(settings, self.store)` (statt fest MemoryStore/CookieBackend). Default (`cookie`+`memory`) = bisheriges Verhalten → Plan 1–3-Tests bleiben grün.

- [ ] **Step 1: Failing tests**

`tests/test_factory.py`:

```python
"""Tests for store/backend selection."""

from fastapi_auth.saml.factory import make_backend, make_store
from fastapi_auth.saml.session.cookie import CookieBackend
from fastapi_auth.saml.session.jwt import JWTBackend
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings

_BASE = dict(
    entity_id="urn:test:sp", base_url="https://sp.example",
    key_file="/tmp/k", cert_file="/tmp/c", fixed_idp_entity_id="urn:test:idp",
)


def test_make_store_memory_default():
    assert isinstance(make_store(SamlSettings(**_BASE, session_secret="x")), MemoryStore)


def test_make_backend_cookie_default():
    s = SamlSettings(**_BASE, session_secret="x")
    assert isinstance(make_backend(s, make_store(s)), CookieBackend)


def test_make_backend_jwt():
    s = SamlSettings(**_BASE, session_secret="s" * 40, backend="jwt")
    assert isinstance(make_backend(s, make_store(s)), JWTBackend)
```

`tests/test_router_jwt_flow.py`:

```python
"""End-to-end login flow with backend='jwt'."""

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from tests.conftest import IDP_EID, mint_response
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def test_jwt_login_flow(certs, idp_metadata_file, make_idp):
    settings = SamlSettings(
        entity_id="urn:test:sp", base_url="https://sp.example",
        key_file=certs["sp_key"], cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file, fixed_idp_entity_id=IDP_EID,
        session_secret="s" * 40, backend="jwt", cookie_secure=False,
    )
    sp = SamlSP(settings)
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")

    @app.get("/me")
    async def me(user: FederatedIdentity = Depends(sp.current_user())):  # noqa: B008
        return {"eppn": user.eppn}

    client = TestClient(app)
    client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    reqid = next(iter(sp.store._outstanding))  # noqa: SLF001
    idp = make_idp(sp.engine.sp_metadata())
    resp = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"]})
    acs = client.post("/saml/acs", data={"SAMLResponse": resp, "RelayState": "/app"}, follow_redirects=False)
    assert acs.status_code == 303
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")
    assert client.get("/me").json()["eppn"] == "u@test.de"
```

- [ ] **Step 2: Rot** — FAIL (`ModuleNotFoundError` / falsche Backends).

- [ ] **Step 3: `factory.py` + `sp.py`**

`factory.py`:

```python
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
        from fastapi_auth.saml.session.redis_store import RedisStore

        return RedisStore.from_url(settings.redis_url)
    if settings.store == "postgres":
        from fastapi_auth.saml.session.postgres_store import PostgresStore

        return PostgresStore.from_url(settings.db_url)
    return MemoryStore()


def make_backend(settings: SamlSettings, store: Store) -> SessionBackend:
    """Construct the configured SessionBackend."""
    if settings.backend == "jwt":
        return JWTBackend(settings)
    return CookieBackend(settings, store)
```

`sp.py`: ersetze die festen `MemoryStore()`/`CookieBackend(...)`-Zeilen durch:

```python
        self.store = make_store(settings)
        self.backend = make_backend(settings, self.store)
```

(Import `from fastapi_auth.saml.factory import make_backend, make_store`.)

> Reihenfolge in `SamlSP.__init__`: erst `settings`/`engine`, dann `store = make_store(...)`,
> dann `backend = make_backend(settings, store)`, dann `router = build_router(self)`.

- [ ] **Step 4: Grün + volle Suite + lint**

Run: `uv run pytest && uv run ruff format . && uv run ruff check . && uv run ty check src tests && make lint`
Expected: alles grün (Plan 1–3-Suiten + neue Factory/JWT-Flow-Tests); ty 0; make lint exit 0. Belegen.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/factory.py src/fastapi_auth/saml/sp.py tests/test_factory.py tests/test_router_jwt_flow.py
git commit -m "feat(saml): Store-/Backend-Factory + SamlSP-Auswahl (cookie/jwt, memory/redis/postgres)"
```

---

## Self-Review

**Spec-Abdeckung (Spec §6):**
- Pluggable `SessionBackend`: Cookie (Default) + JWT (opt-in) → Task 5 + Task 6 ✅
- `Store`: memory | redis | postgres → Task 2/3/4 + Auswahl Task 6 ✅
- JWT stateless (Cookie + Bearer), Claims aus `FederatedIdentity` → Task 5 ✅
- Redis/Postgres via optionale Extras, `model_dump_json`-Serialisierung → Task 1/3/4 ✅
- Default bleibt Cookie+Memory (Plan 1–3 unverändert grün) → Task 6 ✅

**Bewusst NICHT in Plan 4:** MDQ/Aggregat/DS/WAYF/SLO (Plan 5); Docker-Compose mit echtem
Redis/Postgres + `make test-integration` (Plan 6). Der bestehende `sp.identifier()` wird vom
JWTBackend als `sub` genutzt (schließt den Plan-3-„dead code"-Minor).

**Platzhalter-Scan:** kein TBD/TODO; jeder Code-Schritt vollständig.

**Typ-Konsistenz:** `Store`-Protocol-Signaturen (Task 2) = Memory/Redis/Postgres-Implementierungen
(Task 2/3/4); `make_store -> Store`, `make_backend -> SessionBackend`; `JWTBackend`/`CookieBackend`
erfüllen `SessionBackend`. `save_session(sid, identity, ttl)` durchgängig (Cookie-Backend + Router migriert).

**Bekannte Risiken:**
- Store-Refactor (Task 2) berührt Plan-2/3-Aufrufstellen (Cookie/Router/Tests) → im selben Task grün halten.
- SQLModel-`table=True`-Klassen sind global registriert (nur einmal importieren).
- Redis `outstanding()` via `SCAN` ist O(n) über offene Requests — akzeptabel (kurze TTL, wenige gleichzeitige Logins).
- JWT-Secret-Länge: Validator + ≥32-Byte-Test-Secrets (sonst PyJWT-Warnung → Fehler unter warnings-as-errors).

---

## Nächste Meilensteine (eigene Pläne)

- **Plan 5 — Föderation & Discovery:** MDQ + Aggregat-Metadaten, externer DS + embedded WAYF, best-effort SLO.
- **Plan 6 — Docker/CI/Doku:** SimpleSAMLphp-Compose + echtes Redis/Postgres (`make test-integration`),
  GitHub Actions + tox, Sphinx-Doku, How-tos (`lmuidp-container`, DFN-AAI-Testföderation).
