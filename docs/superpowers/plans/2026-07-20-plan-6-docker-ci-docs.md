# Plan 6 — Docker, CI & Doku (Ops) (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Das Package produktionsreif machen: konfigurierbarer Mount-Prefix (Plan-5-Härtung),
**Docker-Image** (multi-stage, `xmlsec1`), **compose.yml** mit echtem Redis+Postgres +
`make test-integration` (Store-Tests gegen echte Dienste), **GitHub-Actions-CI** + **tox**-Matrix,
und **Doku/How-tos** (Docker, Redis/Postgres, SimpleSAMLphp, `lmuidp-container`, DFN-AAI-Testföderation).

**Architecture:** Ein neues `mount_path`-Setting ersetzt die hardcodierten `/saml/…`-Pfade
(Discovery/SLO/WAYF/ACS leiten sich daraus ab). Docker: schlankes Debian-slim-Image mit dem
`xmlsec1`-Binary. Integrationstests laufen über einen `integration`-pytest-Marker (der Standard-Lauf
schließt ihn aus) gegen die per compose bereitgestellten Redis/Postgres-Dienste — im Spike bestätigt
(RedisStore/PostgresStore-Roundtrip gegen echte Container grün). CI spiegelt lokal.

**Tech Stack:** Docker + compose (`redis:7-alpine`, `postgres:17-alpine`), `asyncpg`, tox
(py3.12/3.13/3.14), GitHub Actions, Sphinx + MyST (Diataxis) für die How-tos.

## Global Constraints

- Additiv/rückwärtskompatibel: Default `mount_path="/saml"` reproduziert alle bisherigen URLs → Plan 1–5-Suite bleibt grün.
- Namespace `fastapi_auth` bleibt PEP-420-implizit (kein `src/fastapi_auth/__init__.py`).
- **Kleine Images:** Multi-Stage, `-slim` Basis, nur nötige Artefakte; `xmlsec1`-Binary via `apt`.
- Integrationstests laufen NICHT im Standard-`pytest` (Marker `integration`, `addopts = -m "not integration"`); nur via `make test-integration`.
- Service-Versionen an unterstützten Ständen (endoflife.date): Redis 7.x, Postgres 17, Python 3.12–3.14.
- English code/comments/docstrings; SPDX in neuen Quelldateien. Doku (LMU-Kontext) auf **Deutsch** ist ok, aber die öffentliche Package-Doku (README/How-tos) auf **Englisch** halten (öffentliches PyPI-Package) — Commit-Messages **Deutsch**.
- ruff `E,F,W,B,UP,I,D,S`; `ty` 0; `make lint` exit 0; Commit auf `main`, Conventional Commits **Deutsch**, kein `git push`, Autor **Loechel**.
- TDD wo Code betroffen ist (Task 1); für Infra/Doku (Task 2–5): Artefakt erstellen + konkret verifizieren (Build/Lint/Run), im Report belegen.

## File Structure

```text
src/fastapi_auth/saml/settings.py   # + mount_path; acs/disco/slo/wayf-URLs daraus ableiten (Task 1)
src/fastapi_auth/saml/router.py     # hardcodierte /saml/-Pfade -> settings-abgeleitet (Task 1)
src/fastapi_auth/saml/engine/config.py  # SLO-Return-Endpoint -> settings-abgeleitet (Task 1)
Dockerfile                          # multi-stage, xmlsec1 (Task 2)
.dockerignore                       # (Task 2)
compose.yml                         # redis + postgres (+ optional app) (Task 3)
tests/integration/test_stores_integration.py  # @pytest.mark.integration, echte Dienste (Task 3)
Makefile                            # test-integration ausbauen (Task 3)
.github/workflows/ci.yml            # ruff+ty+pytest tox + docker build (Task 4)
tox.ini                             # py312/py313/py314 + lint (Task 4)
docs/                               # Sphinx + MyST How-tos (Task 5)
  conf.py, index.md, howto/{docker,stores,simplesamlphp,lmuidp,dfn-aai}.md
README.md                           # Docker/Integration/Doku-Verweise (Task 5)
pyproject.toml                      # pytest-Marker + docs-Extra (Task 3/5)
```

---

## Task 1: Konfigurierbarer Mount-Prefix (Plan-5-Härtung)

**Files:** Modify `settings.py`, `router.py`, `engine/config.py`; Test `tests/test_mount_path.py` (+ ggf. bestehende Tests).

**Interfaces:**
- `SamlSettings`: neues Feld `mount_path: str = "/saml"`. Neue Helfer:
  - `acs_url` (Property) → `f"{base_url.rstrip('/')}{mount_path}/acs"` (ersetzt die bisherige `acs_path`-Ableitung; Default identisch zu vorher).
  - `def absolute_url(self, subpath: str) -> str` → `f"{base_url.rstrip('/')}{mount_path}{subpath}"` (z. B. `/disco`, `/slo/return`).
  - `wayf_login_path` (Property) → `f"{mount_path}/login"`.
- `router.py`: `_WAYF_LOGIN_PATH` → `sp.settings.wayf_login_path`; DS-`return_url` → `sp.settings.absolute_url("/disco")`.
- `engine/config.py`: SLO-`single_logout_service` → `settings.absolute_url("/slo/return")`.
- Das bisherige `acs_path`-Feld: entfernen (durch `mount_path` ersetzt) ODER als Alias behalten. Prüfe alle Nutzungen (`grep acs_path`) und migriere; Default-Verhalten muss identisch bleiben.

- [ ] **Step 1: Failing test**

`tests/test_mount_path.py`:

```python
"""Mount-path drives all absolute SP URLs consistently."""

from fastapi_auth.saml.settings import SamlSettings

_BASE = dict(
    entity_id="urn:test:sp", base_url="https://sp.example",
    key_file="/tmp/k", cert_file="/tmp/c", fixed_idp_entity_id="urn:test:idp", session_secret="x",
)


def test_default_mount_path_reproduces_saml_prefix():
    s = SamlSettings(**_BASE)
    assert s.mount_path == "/saml"
    assert s.acs_url == "https://sp.example/saml/acs"
    assert s.absolute_url("/disco") == "https://sp.example/saml/disco"
    assert s.absolute_url("/slo/return") == "https://sp.example/saml/slo/return"
    assert s.wayf_login_path == "/saml/login"


def test_custom_mount_path_propagates():
    s = SamlSettings(**{**_BASE, "mount_path": "/auth/saml"})
    assert s.acs_url == "https://sp.example/auth/saml/acs"
    assert s.absolute_url("/disco") == "https://sp.example/auth/saml/disco"
    assert s.wayf_login_path == "/auth/saml/login"
```

- [ ] **Step 2: Rot** — `uv run pytest tests/test_mount_path.py -v` → FAIL.
- [ ] **Step 3: Implementieren** — `settings.py` (mount_path + Properties/`absolute_url`), `router.py` + `engine/config.py` migrieren; alle `acs_path`-Nutzungen entfernen/migrieren.
- [ ] **Step 4: Grün + volle Suite + lint** — `uv run pytest && uv run ruff format . && uv run ruff check . && uv run ty check src tests && make lint` (Plan 1–5 bleiben grün; belegen).
- [ ] **Step 5: Commit** — `refactor(saml): konfigurierbarer mount_path statt hardcodierter /saml-Pfade`.

---

## Task 2: Dockerfile (multi-stage, xmlsec1)

**Files:** Create `Dockerfile`, `.dockerignore`.

**Interfaces:** ein schlankes, lauffähiges Image, das das Package + `xmlsec1` enthält. Kein App-Entrypoint nötig (Library), aber ein Beispiel-Runner (`python -c "import fastapi_auth.saml"`) muss im Image funktionieren; das Image dient als Basis für Consumer-Apps + den compose-Integrationskontext.

- [ ] **Step 1: `.dockerignore`**

```text
.git
.venv
__pycache__
*.pyc
.superpowers
docs/_build
dist
build
tests/certs
```

- [ ] **Step 2: `Dockerfile` (multi-stage, Debian-slim + xmlsec1)**

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml README.md ./
COPY src ./src
RUN uv pip install --system --no-cache ".[redis,postgres]"

FROM python:3.13-slim AS runtime
ENV PYTHONUNBUFFERED=1
# xmlsec1 binary (pysaml2 shells out to it); libxml2 runtime deps come with it
RUN apt-get update \
 && apt-get install -y --no-install-recommends xmlsec1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
WORKDIR /app
COPY src ./src
# Smoke check baked in: import + xmlsec1 present
RUN python -c "import fastapi_auth.saml; import shutil; assert shutil.which('xmlsec1'), 'xmlsec1 missing'"
CMD ["python", "-c", "import fastapi_auth.saml as s; print('fastapi-auth-saml-federated', s.__version__)"]
```

> Verifikation: `xmlsec1` aus `apt` liefert `/usr/bin/xmlsec1`; unser `SamlSettings.xmlsec_binary`-Default
> (`shutil.which('xmlsec1')`) findet es. Der `RUN python -c ...`-Smoke-Check schlägt fehl, wenn Import
> oder xmlsec1 fehlen. Falls `python3.13` im Pfad abweicht, an das Basisimage anpassen.

- [ ] **Step 3: Build verifizieren**

Run: `docker build -t fa-saml:test .` — Expected: Build erfolgreich; der eingebettete Smoke-Check (Import + xmlsec1) passiert; `docker run --rm fa-saml:test` druckt die Version.

- [ ] **Step 4: Commit** — `build: Dockerfile (multi-stage slim + xmlsec1)` (+ `.dockerignore`). (Belege den erfolgreichen `docker build` + `docker run`-Output im Report.)

---

## Task 3: compose.yml + Integrationstest (echtes Redis+Postgres)

**Files:** Create `compose.yml`, `tests/integration/test_stores_integration.py`; Modify `Makefile`, `pyproject.toml`.

**Interfaces:**
- `pyproject.toml`: pytest-Marker `integration` registrieren; `addopts` um `-m "not integration"` erweitern (Standard-Lauf schließt Integration aus). `asyncpg>=0.29` sicherstellen (postgres-Extra hat es bereits).
- `compose.yml`: `redis` (`redis:7-alpine`, Port 6379) + `postgres` (`postgres:17-alpine`, DB/Passwort, Port 5432), beide mit Healthcheck.
- `tests/integration/test_stores_integration.py`: `@pytest.mark.integration`, liest `IT_REDIS_URL` (default `redis://localhost:6379/0`) und `IT_DB_URL` (default `postgresql+asyncpg://postgres:pw@localhost:5432/fa`); fährt für **RedisStore** und **PostgresStore** je einen echten Roundtrip (save/load/delete Session + add/outstanding/pop). **Spike-verifiziert** gegen echte Container.
- `Makefile` `test-integration`: `docker compose up -d --wait`, dann `uv run pytest -m integration`, dann `docker compose down -v` (auch bei Fehler via trap/`||`).

- [ ] **Step 1: pytest-Marker + addopts**

`pyproject.toml` `[tool.pytest.ini_options]`: `markers = ["integration: needs live redis/postgres (make test-integration)"]`; `addopts = "-ra -m 'not integration'"`.

- [ ] **Step 2: Failing integration test**

`tests/integration/test_stores_integration.py`:

```python
"""Integration: RedisStore + PostgresStore against live services (make test-integration)."""

import os

import pytest

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.postgres_store import PostgresStore
from fastapi_auth.saml.session.redis_store import RedisStore

pytestmark = pytest.mark.integration

_REDIS = os.environ.get("IT_REDIS_URL", "redis://localhost:6379/0")
_DB = os.environ.get("IT_DB_URL", "postgresql+asyncpg://postgres:pw@localhost:5432/fa")


async def test_redis_store_roundtrip_live():
    store = RedisStore.from_url(_REDIS)
    await store.save_session("s1", FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"]), ttl=300)
    loaded = await store.load_session("s1")
    assert loaded is not None and loaded.eppn == "u@lmu.de" and loaded.mail == ["u@lmu.de"]
    await store.add_outstanding("r1", "/app", ttl=300)
    assert await store.outstanding() == {"r1": "/app"}
    assert await store.pop_outstanding("r1") == "/app"


async def test_postgres_store_roundtrip_live():
    store = PostgresStore.from_url(_DB)
    await store.create_all()
    await store.save_session("s1", FederatedIdentity(eppn="p@lmu.de"), ttl=300)
    loaded = await store.load_session("s1")
    assert loaded is not None and loaded.eppn == "p@lmu.de"
    await store.add_outstanding("r1", "/app", ttl=300)
    assert await store.outstanding() == {"r1": "/app"}
    assert await store.pop_outstanding("r1") == "/app"
```

- [ ] **Step 3: `compose.yml`**

```yaml
services:
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 3s
      retries: 20
  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_PASSWORD: pw
      POSTGRES_DB: fa
    ports: ["5432:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 2s
      timeout: 3s
      retries: 20
```

- [ ] **Step 4: `Makefile` `test-integration`**

```make
test-integration:
	docker compose up -d --wait
	IT_REDIS_URL=redis://localhost:6379/0 \
	IT_DB_URL=postgresql+asyncpg://postgres:pw@localhost:5432/fa \
	uv run pytest -m integration -v; status=$$?; docker compose down -v; exit $$status
```

- [ ] **Step 5: Verifizieren**

Run: `uv run pytest` (Standard) → Integration wird übersprungen (Marker), Suite grün. Dann `make test-integration` → Redis+Postgres hoch, beide Integrationstests grün, compose runter. Belege beide Läufe im Report. `make lint` grün (der Integrationstest muss ruff/ty bestehen).

- [ ] **Step 6: Commit** — `test(integration): compose (Redis+Postgres) + Store-Integrationstests + make test-integration`.

---

## Task 4: GitHub Actions CI + tox

**Files:** Create `.github/workflows/ci.yml`, `tox.ini`.

**Interfaces:**
- `tox.ini`: envs `py312,py313,py314` (führt `uv run pytest` bzw. installiert `.[dev]` + pytest) und `lint` (ruff check + format --check + ty). Über `uvx tox` / `tox` lauffähig.
- `.github/workflows/ci.yml`: Jobs (1) **lint+test** Matrix Python 3.12/3.13/3.14 (uv setup, `uv pip install -e .[dev]`, ruff check + format --check, ty check, `pytest` [ohne Integration], System-`xmlsec1` via `apt` installieren); (2) **integration** (services: redis + postgres, `pytest -m integration`); (3) **docker** (`docker build`).

- [ ] **Step 1: `tox.ini`**

```ini
[tox]
env_list = py312, py313, py314, lint
skip_missing_interpreters = true

[testenv]
runner = uv-venv-runner
extras = dev
commands = pytest -m "not integration" {posargs}

[testenv:lint]
extras = dev
commands =
    ruff check .
    ruff format --check .
    ty check src tests
```

> Hinweis: `tox` braucht das `tox-uv`-Plugin für `uv-venv-runner` (via `uvx --with tox-uv tox` oder `uv tool install tox --with tox-uv`). Alternativ Standard-`testenv` mit `deps`/`pip`. Verifiziere `tox -e lint` lokal, dass es grün ist (mindestens der lint-Env; die py-Envs brauchen die jeweiligen Interpreter).

- [ ] **Step 2: `.github/workflows/ci.yml`**

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python: ["3.12", "3.13", "3.14"]
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y --no-install-recommends xmlsec1
      - uses: astral-sh/setup-uv@v5
      - run: uv python install ${{ matrix.python }}
      - run: uv pip install --system -e ".[dev]"
      - run: ruff check .
      - run: ruff format --check .
      - run: ty check src tests
      - run: pytest -m "not integration"
  integration:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports: ["6379:6379"]
        options: >-
          --health-cmd "redis-cli ping" --health-interval 2s --health-timeout 3s --health-retries 20
      postgres:
        image: postgres:17-alpine
        env: { POSTGRES_PASSWORD: pw, POSTGRES_DB: fa }
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U postgres" --health-interval 2s --health-timeout 3s --health-retries 20
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y --no-install-recommends xmlsec1
      - uses: astral-sh/setup-uv@v5
      - run: uv pip install --system -e ".[dev,postgres]"
      - run: pytest -m integration
        env:
          IT_REDIS_URL: redis://localhost:6379/0
          IT_DB_URL: postgresql+asyncpg://postgres:pw@localhost:5432/fa
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t fa-saml:ci .
```

- [ ] **Step 3: Verifizieren** — `tox -e lint` (via `uvx --with tox-uv tox -e lint`) grün; YAML syntaktisch valide (`python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"`). GitHub-Actions selbst laufen erst beim Push (dokumentieren). Belegen.
- [ ] **Step 4: Commit** — `ci: GitHub Actions (lint/test-Matrix + integration + docker) + tox`.

---

## Task 5: Doku & How-tos (Sphinx + MyST)

**Files:** Create `docs/conf.py`, `docs/index.md`, `docs/howto/{docker,stores,simplesamlphp,lmuidp,dfn-aai}.md`; Modify `README.md`, `pyproject.toml` (docs-Extra).

**Interfaces:** eine baubare Sphinx/MyST-Doku (Diataxis-How-to-Quadrant fokussiert), plus README-Verweise. Inhalt **Englisch** (öffentliches Package). Nutze den `plone-doc-style`-Stil (klar, explizit).

- [ ] **Step 1: docs-Extra + Sphinx-Konfig** — `pyproject.toml` `[project.optional-dependencies]` `docs = ["sphinx>=7", "myst-parser>=3", "furo>=2024.0"]`. `docs/conf.py` (myst_parser, furo-Theme, project metadata). `docs/index.md` mit Toctree auf die How-tos + Kurzüberblick (Install, Minimalbeispiel `from fastapi_auth import saml`).

- [ ] **Step 2: How-tos** (je eine MyST-Datei, knapp & konkret):
  - `howto/docker.md`: Image bauen/nutzen, `xmlsec1`-Systemabhängigkeit, `compose up`, `make test-integration`, Teardown.
  - `howto/stores.md`: Cookie vs. JWT, Memory/Redis/Postgres wählen (Settings + Extras `[redis]`/`[postgres]`), `db_url`/`redis_url`.
  - `howto/simplesamlphp.md`: lokalen SimpleSAMLphp-IdP als Test-Gegenstelle konfigurieren, SP-Metadaten austauschen, `metadata_source="direct"` + `passthrough`.
  - `howto/lmuidp.md`: gegen den echten `lmuidp-container` (Shibboleth) testen — EntityID `urn:lmu.de:testidp`, Port 10444, SP-Metadaten in dessen `metadata.xml` eintragen, Testlogin `i.reska`/`shampoo1` (Verweis auf das Repo).
  - `howto/dfn-aai.md`: SP in der DFN-AAI-Testföderation registrieren, `metadata_source="mdq"` + `trust_anchor_cert`, `discovery_mode="external"` mit dem DFN-DS.
- [ ] **Step 3: README** um Abschnitte Install/Docker/Docs/Backends ergänzen; Link auf `docs/`.
- [ ] **Step 4: Verifizieren** — `uv pip install -e ".[docs]"` && `uv run sphinx-build -W -b html docs docs/_build` baut ohne Fehler/Warnungen (`-W`). `docs/_build` ist bereits in `.gitignore`/`.dockerignore`. Belege den erfolgreichen Build im Report.
- [ ] **Step 5: Commit** — `docs: Sphinx/MyST How-tos (Docker, Stores, SimpleSAMLphp, lmuidp, DFN-AAI) + README`.

---

## Self-Review

**Abdeckung (Spec Docker/CI/Doku + Plan-5-Deferral):**
- Konfigurierbarer Mount-Prefix (Plan-5-Härtung) → Task 1 ✅
- Docker-Image (slim, xmlsec1) → Task 2 ✅
- compose + `make test-integration` gegen echtes Redis/Postgres → Task 3 (spike-verifiziert) ✅
- GitHub Actions + tox-Matrix → Task 4 ✅
- Doku/How-tos (Docker, Stores, SimpleSAMLphp, lmuidp, DFN-AAI) → Task 5 ✅

**Bewusst NICHT in Plan 6:** automatisierter SimpleSAMLphp-IdP-Integrationstest (nur How-to; der volle
SAML-Flow ist durch den In-Memory-pysaml2-IdP + echte Krypto bereits unit-getestet); RS256/EdDSA-JWT;
atomares `pop_outstanding` (Redis GETDEL / PG DELETE..RETURNING) — als offene Härtungen dokumentieren.

**Bekannte Risiken:**
- `mount_path`-Refactor (Task 1) berührt settings/router/config → im selben Task grün halten; `acs_path`-Migration prüfen.
- Docker-Basisimage-Pythonpfad (`python3.13`) an das gewählte Tag anpassen.
- `tox`-`uv`-Runner braucht `tox-uv` (Hinweis im Task); die py-Envs brauchen die Interpreter (lokal ggf. nur `lint` + `py313` verifizierbar).
- Sphinx `-W` (warnings-as-errors) kann bei MyST-Kleinigkeiten zicken → im Task sauber halten.

**Bekannte offene Punkte (nach Plan 6, für ein optionales Plan 7 „Härtung"):** RS256/EdDSA-JWT,
atomares Outstanding-Pop, JWT-Claims-Allowlist, `list_idps`-mdui-Test-Coverage, `build_signed_aggregate`-Rename,
automatisierter Fremd-IdP-Integrationstest (SimpleSAMLphp/Shibboleth).
```
