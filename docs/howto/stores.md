# Choosing a session backend and store

The SP separates two independent choices: how the session is *carried* between
browser and server (the **backend**), and where server-side session state is
*persisted* (the **store**). Both are configured on `SamlSettings`
(`from fastapi_auth import saml; saml.SamlSettings(...)`).

## Backend: `cookie` vs `jwt`

```python
from fastapi_auth import saml

settings = saml.SamlSettings(
    ...,
    backend="cookie",  # or "jwt"
)
```

`backend="cookie"` (the default)
: The session cookie carries only a signed, opaque session id (via `itsdangerous`).
  The actual `FederatedIdentity` is kept server-side in the configured **store**.
  Revoking a session (logout) means deleting it from the store — the cookie alone
  is useless without it.

`backend="jwt"`
: The session cookie (or an `Authorization: Bearer` header) carries the full
  identity, signed as a JWT (via `PyJWT`). Nothing is looked up server-side to
  authenticate a request — this is what "stateless" means here. The trade-off:
  a JWT cannot be revoked before its `jwt_ttl` expires, and the attributes travel
  in plaintext inside the token (signed, not encrypted), which can approach the
  ~4 KB cookie size limit for attribute-rich identities.

  The JWT backend requires a strong signing secret. `SamlSettings` validates this
  at construction time:

  ```python
  saml.SamlSettings(..., backend="jwt", session_secret="short")
  # ValueError: JWT backend requires jwt_secret/session_secret of at least 32 bytes
  ```

  Set `jwt_secret` explicitly (recommended) or rely on `session_secret` if it is
  already ≥ 32 bytes; `jwt_alg` defaults to `HS256`.

  Note that even with `backend="jwt"`, the SP still needs a **store** — not for
  the session itself, but to track in-flight `AuthnRequest`s between `/login` and
  `/acs` (the `outstanding_ttl`-bounded request-id/RelayState mapping).

## Store: `memory`, `redis`, `postgres`

```python
settings = saml.SamlSettings(
    ...,
    store="memory",  # or "redis" / "postgres"
)
```

`store="memory"` (the default)
: An in-process dict. Fine for a single-worker development server or for tests.
  Sessions and outstanding requests are lost on restart and are not shared across
  multiple worker processes — do not use this in a multi-worker production
  deployment.

`store="redis"`
: Sessions and outstanding requests are Redis keys with native TTL. Needs the
  `redis` extra and a `redis_url`:

  ```bash
  uv pip install "fastapi-auth-saml-federated[redis]"
  ```

  ```python
  saml.SamlSettings(..., store="redis", redis_url="redis://localhost:6379/0")
  ```

`store="postgres"`
: Sessions and outstanding requests are rows in two SQLModel tables, via an async
  SQLAlchemy engine. Needs the `postgres` extra and a `db_url`:

  ```bash
  uv pip install "fastapi-auth-saml-federated[postgres]"
  ```

  ```python
  saml.SamlSettings(
      ...,
      store="postgres",
      db_url="postgresql+asyncpg://postgres:pw@localhost:5432/fa",
  )
  ```

  The same store class also runs against SQLite (`sqlite+aiosqlite:///...`), which
  is what the default `db_url` (`sqlite+aiosqlite:///:memory:`) and the unit tests
  use — useful for local development without a Postgres server.

## Putting it together

Backend and store are chosen independently — pick the combination for your
deployment shape:

| Deployment | `backend` | `store` |
| --- | --- | --- |
| Single-process dev server | `cookie` | `memory` |
| Multi-worker / horizontally scaled service | `cookie` | `redis` or `postgres` |
| Stateless service, no shared session store | `jwt` | `redis` or `postgres` (for outstanding requests only) |

See {doc}`docker` for running a real Redis/Postgres locally to exercise the
`redis`/`postgres` stores against.
