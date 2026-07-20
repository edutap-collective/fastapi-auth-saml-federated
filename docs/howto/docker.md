# Docker: build, run, and integration-test

This how-to covers the `Dockerfile` and `compose.yml` shipped in the repository root —
useful both for running the package in a container and for the local
`make test-integration` workflow against real Redis/Postgres.

## The `xmlsec1` system dependency

`pysaml2` shells out to the `xmlsec1` binary to sign and verify SAML XML. It is not a
Python package, so it must be present on the `PATH` wherever the SP runs — in a
container or on bare metal alike. On Debian/Ubuntu-based images:

```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends xmlsec1 \
 && rm -rf /var/lib/apt/lists/*
```

The shipped `Dockerfile` bakes in a smoke check for exactly this at build time:

```dockerfile
RUN python -c "import fastapi_auth.saml; import shutil; assert shutil.which('xmlsec1'), 'xmlsec1 missing'"
```

If that step fails, the image is missing `xmlsec1` — check the base image and the
`apt-get install` step above.

## Build the image

The `Dockerfile` is a two-stage build (`build` installs dependencies with `uv`,
`runtime` is a slim image with only `xmlsec1` and the installed site-packages):

```bash
docker build -t fastapi-auth-saml-federated .
```

Run it to see the version/import smoke test:

```bash
docker run --rm fastapi-auth-saml-federated
```

This prints the installed version. It is a demonstration entrypoint, not an
application server — mount your own FastAPI app (see {doc}`../index`) as a base
image or copy this `Dockerfile`'s pattern into your own.

## `compose up`: Redis + Postgres for local testing

`compose.yml` starts a `redis:7-alpine` and a `postgres:17-alpine` container, both
with health checks, for exercising the Redis- and Postgres-backed session stores
(see {doc}`stores`) against the real thing rather than fakes:

```bash
docker compose up -d --wait
```

## `make test-integration`

The `test-integration` Makefile target wraps the whole cycle — start the
containers, point the store URLs at them, run only the tests marked
`@pytest.mark.integration`, then tear the containers down again (even on test
failure):

```bash
make test-integration
```

Equivalent to:

```bash
docker compose up -d --wait
IT_REDIS_URL=redis://localhost:6379/0 \
IT_DB_URL=postgresql+asyncpg://postgres:pw@localhost:5432/fa \
uv run pytest -m integration -v
docker compose down -v
```

Regular `make test-local` (or a bare `uv run pytest`) never touches Docker: the
`integration` marker is excluded by default (`addopts = "-ra -m 'not integration'"`
in `pyproject.toml`).

## Local port overrides

If the default ports `6379` (Redis) or `5432` (Postgres) are already taken on your
machine — for example by another project's containers — create a
`compose.override.yml` next to `compose.yml` to remap the host ports, without
touching the tracked `compose.yml`:

```yaml
services:
  redis:
    ports: ["6399:6379"]
  postgres:
    ports: ["5439:5432"]
```

Docker Compose picks up `compose.override.yml` automatically. Remember to also
override `IT_REDIS_URL`/`IT_DB_URL` (or the Makefile invocation) to match. This file
is intentionally listed in `.gitignore` — it is a local workaround, not part of the
committed configuration.

## Teardown

```bash
docker compose down -v
```

The `-v` also removes the anonymous volumes, so the next `compose up` starts from a
clean Redis/Postgres. `make test-integration` already does this for you, including
after a failed test run.
