# Plan 2 — SSO-Kern (Minimal-Login) (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ein durchgängiger SP-initiierter SAML2-Login gegen einen *einzelnen* IdP
(`source='direct'` + `discovery='passthrough'`): AuthnRequest → IdP → ACS →
signierte Assertion prüfen → `FederatedIdentity` → Cookie-Session (Memory-Store) →
`current_user`.

**Architecture:** Dünner async-Layer über `pysaml2` 7.5.4. Synchrone pysaml2-Aufrufe
laufen in `anyio.to_thread.run_sync`. Der `engine`-Layer kapselt pysaml2 (Config,
AuthnRequest, Response-Validierung, Attribut→`FederatedIdentity`). Der `session`-Layer
(Protocol + Cookie-Backend + Memory-Store) kennt kein XML. Die `SamlSP`-Fassade
verdrahtet beides und liefert einen `APIRouter` (`/login`, `/acs`, `/metadata`).
Getestet wird end-to-end mit einem **In-Memory pysaml2-IdP** (`saml2.server.Server`),
der signierte Responses mintet — kein externer Dienst nötig (Muster verifiziert im
Spike, s. Task 3).

**Tech Stack:** Python 3.12+, pysaml2 7.5.4 (+ `xmlsec1`-Binary), FastAPI, Pydantic v2,
pydantic-settings, itsdangerous, anyio, httpx, pytest.

## Global Constraints

- Baut auf Plan 1 auf: `fastapi_auth.saml.identity` (`FederatedIdentity`, `map_attributes`,
  `select_identifier`, `registry`) existiert und ist stabil. NICHT verändern außer additiv.
- Namespace `fastapi_auth` bleibt PEP-420-implizit — **niemals** `src/fastapi_auth/__init__.py`.
- **Systemvoraussetzung `xmlsec1`** (Binary) muss installiert sein; Pfad via `shutil.which("xmlsec1")` ermitteln, per Settings überschreibbar. Ist bereits installiert (`/opt/homebrew/bin/xmlsec1`, xmlsec1 1.3.12).
- Krypto ausschließlich über pysaml2/xmlsec1 — keine eigene Krypto.
- Milestone-Scope: **nur** `source='direct'` und `discovery='passthrough'`. MDQ, Aggregat,
  externer DS, embedded WAYF, JWT, Redis/Postgres, SLO, Enforcement, RequestedAttributes
  gehören in Plan 3/4 — hier NICHT bauen.
- async-first: alle blockierenden pysaml2-Calls via `anyio.to_thread.run_sync`.
- English code/comments/docstrings; SPDX header `SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2` in jeder neuen Quelldatei.
- ruff `E,F,W,B,UP,I,D,S` (Tests ignorieren `S101`/`D`); `ty` muss grün bleiben (`make lint` exit 0); `# ty: ignore[<code>]` nur gezielt mit Begründung.
- Commit auf Branch `main` (user-autorisiert), Conventional Commits **Deutsch**, kein `git push`.
- TDD: erst Test (rot), dann Implementierung (grün), dann Commit. `make lint` grün vor jedem Commit.
- Keine Secrets loggen/committen. Test-Keys werden zur Testzeit erzeugt (nicht eingecheckt).

## File Structure

```text
src/fastapi_auth/saml/
  settings.py                 # SamlSettings (pydantic-settings) — SP, Metadaten(direct), Discovery(passthrough), Session, Krypto
  engine/
    __init__.py
    config.py                 # build_sp_config(settings) -> dict; load_idp_metadata(settings) -> str
    client.py                 # SamlEngine (async): create_authn_request, parse_response; to_identity()
  session/
    __init__.py
    store.py                  # MemoryStore: Sessions + Outstanding-Requests
    base.py                   # SessionBackend (Protocol) + current_user/optional_user Dependencies
    cookie.py                 # CookieBackend (signiertes Cookie via itsdangerous)
  sp.py                       # SamlSP-Fassade (verdrahtet settings+engine+session+store) + .router
  router.py                  # build_router(sp) -> APIRouter: /login /acs /metadata
tests/
  conftest.py                 # Fixtures: Test-Certs, In-Memory-IdP (saml2.server.Server), SamlSettings, TestClient-App
  engine/test_config.py
  engine/test_client_roundtrip.py
  session/test_store.py
  session/test_cookie.py
  test_router_login_flow.py   # end-to-end: /login -> IdP mint -> /acs -> current_user
tests/certs/                  # (gitignored) zur Testzeit erzeugte Keys/Certs
```

Ergänze `.gitignore`: `tests/certs/`.

---

## Task 1: Dependencies + `SamlSettings`

**Files:**
- Modify: `pyproject.toml` (Dependencies), `.gitignore`
- Create: `src/fastapi_auth/saml/settings.py`
- Test: `tests/test_settings.py`

**Interfaces:**
- Consumes: nichts.
- Produces: `SamlSettings` (pydantic-settings) mit Feldern (env-Prefix `SAML_`):
  - SP: `entity_id: str`, `base_url: str`, `acs_path: str = "/saml/acs"`, `key_file: str`, `cert_file: str`
  - Metadaten: `metadata_source: Literal["direct"] = "direct"`, `idp_metadata_file: str | None = None`, `idp_metadata_url: str | None = None`
  - Discovery: `discovery_mode: Literal["passthrough"] = "passthrough"`, `fixed_idp_entity_id: str`
  - Session: `session_cookie_name: str = "fa_saml_session"`, `session_secret: str`, `session_ttl: int = 28800`, `cookie_secure: bool = True`
  - Krypto/Security: `xmlsec_binary: str` (default `shutil.which("xmlsec1")`), `want_assertions_signed: bool = True`, `authn_requests_signed: bool = True`
  - Property `acs_url: str` → `f"{base_url.rstrip('/')}{acs_path}"`

- [ ] **Step 1: Dependencies ergänzen**

In `pyproject.toml` unter `[project]` `dependencies` erweitern zu:

```toml
dependencies = [
    "fastapi>=0.115",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "pysaml2>=7.5.4",
    "itsdangerous>=2.2",
    "anyio>=4",
    "httpx>=0.27",
]
```

Run: `uv pip install -U -e ".[dev]"` — Expected: installs pysaml2, itsdangerous ohne Fehler.

- [ ] **Step 2: `.gitignore` ergänzen**

Hänge an `.gitignore` an:

```text

# test-time generated SAML keys/certs — never commit
tests/certs/
```

- [ ] **Step 3: Failing test schreiben**

`tests/test_settings.py`:

```python
"""Tests for SamlSettings configuration."""

import pytest
from pydantic import ValidationError

from fastapi_auth.saml.settings import SamlSettings

_BASE = dict(
    entity_id="urn:test:sp",
    base_url="https://sp.example",
    key_file="/tmp/sp.key",
    cert_file="/tmp/sp.crt",
    fixed_idp_entity_id="urn:test:idp",
    session_secret="s3cr3t",
)


def test_defaults_and_acs_url():
    s = SamlSettings(**_BASE)
    assert s.acs_path == "/saml/acs"
    assert s.acs_url == "https://sp.example/saml/acs"
    assert s.metadata_source == "direct"
    assert s.discovery_mode == "passthrough"
    assert s.want_assertions_signed is True


def test_acs_url_strips_trailing_slash():
    s = SamlSettings(**{**_BASE, "base_url": "https://sp.example/"})
    assert s.acs_url == "https://sp.example/saml/acs"


def test_missing_required_field_raises():
    incomplete = {k: v for k, v in _BASE.items() if k != "entity_id"}
    with pytest.raises(ValidationError):
        SamlSettings(**incomplete)


def test_env_prefix(monkeypatch):
    for k, v in _BASE.items():
        monkeypatch.setenv(f"SAML_{k.upper()}", v)
    s = SamlSettings()
    assert s.entity_id == "urn:test:sp"
```

- [ ] **Step 4: Test rot laufen lassen**

Run: `uv run pytest tests/test_settings.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.saml.settings`).

- [ ] **Step 5: `settings.py` implementieren**

`src/fastapi_auth/saml/settings.py`:

```python
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
```

- [ ] **Step 6: Test grün + lint**

Run: `uv run pytest tests/test_settings.py -v && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: tests passed; ruff clean; ty 0 diagnostics.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml .gitignore src/fastapi_auth/saml/settings.py tests/test_settings.py
git commit -m "feat(saml): SamlSettings + pysaml2/itsdangerous-Dependencies"
```

---

## Task 2: Engine-Config + IdP-Metadaten (`engine/config.py`)

**Files:**
- Create: `src/fastapi_auth/saml/engine/__init__.py`, `src/fastapi_auth/saml/engine/config.py`
- Test: `tests/engine/test_config.py`

**Interfaces:**
- Consumes: `SamlSettings` (Task 1).
- Produces:
  - `load_idp_metadata(settings: SamlSettings) -> str` — liest IdP-Metadaten-XML aus `idp_metadata_file` (Datei) oder `idp_metadata_url` (via `httpx.get`, sync — wird vom Aufrufer im Thread genutzt); genau eine Quelle muss gesetzt sein, sonst `ValueError`.
  - `build_sp_config(settings: SamlSettings) -> dict` — pysaml2-SPConfig-Dict: entityid, xmlsec_binary, `allow_unknown_attributes=True`, service.sp mit `assertion_consumer_service=[(acs_url, BINDING_HTTP_POST)]`, `allow_unsolicited=False`, `authn_requests_signed`, `want_assertions_signed`, `want_response_signed=False`, key_file/cert_file, `metadata={"inline": [idp_metadata]}`.

- [ ] **Step 1: Failing test schreiben**

`tests/engine/test_config.py`:

```python
"""Tests for building the pysaml2 SP config from settings."""

import pytest
from saml2 import BINDING_HTTP_POST
from saml2.config import SPConfig

from fastapi_auth.saml.engine.config import build_sp_config, load_idp_metadata
from fastapi_auth.saml.settings import SamlSettings


def _settings(tmp_path, idp_md: str) -> SamlSettings:
    md = tmp_path / "idp.xml"
    md.write_text(idp_md)
    key = tmp_path / "sp.key"
    crt = tmp_path / "sp.crt"
    key.write_text("x")
    crt.write_text("x")
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=str(key),
        cert_file=str(crt),
        idp_metadata_file=str(md),
        fixed_idp_entity_id="urn:test:idp",
        session_secret="s3cr3t",
    )


MINIMAL_IDP_MD = (
    '<?xml version="1.0"?>'
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:test:idp">'
    "</EntityDescriptor>"
)


def test_load_idp_metadata_from_file(tmp_path):
    s = _settings(tmp_path, MINIMAL_IDP_MD)
    assert "urn:test:idp" in load_idp_metadata(s)


def test_load_idp_metadata_requires_a_source(tmp_path):
    s = _settings(tmp_path, MINIMAL_IDP_MD)
    s.idp_metadata_file = None
    with pytest.raises(ValueError, match="metadata"):
        load_idp_metadata(s)


def test_build_sp_config_shape(tmp_path):
    s = _settings(tmp_path, MINIMAL_IDP_MD)
    cfg = build_sp_config(s)
    assert cfg["entityid"] == "urn:test:sp"
    acs = cfg["service"]["sp"]["endpoints"]["assertion_consumer_service"]
    assert acs == [("https://sp.example/saml/acs", BINDING_HTTP_POST)]
    assert cfg["service"]["sp"]["want_assertions_signed"] is True
    assert cfg["metadata"]["inline"] == [MINIMAL_IDP_MD]


def test_build_sp_config_loads_in_pysaml2(tmp_path):
    # Real IdP metadata is needed for SPConfig().load to accept it; use a
    # generated descriptor so the config actually parses.
    from saml2 import BINDING_HTTP_REDIRECT
    from saml2.config import IdPConfig
    from saml2.metadata import create_metadata_string

    idp_cfg = IdPConfig().load(
        {
            "entityid": "urn:test:idp",
            "service": {"idp": {"endpoints": {"single_sign_on_service": [("https://idp/sso", BINDING_HTTP_REDIRECT)]}}},
        }
    )
    idp_md = create_metadata_string(None, config=idp_cfg, sign=False).decode()
    s = _settings(tmp_path, idp_md)
    cfg = build_sp_config(s)
    loaded = SPConfig().load(cfg)  # must not raise
    assert loaded.entityid == "urn:test:sp"
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/engine/test_config.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.saml.engine.config`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/saml/engine/__init__.py`:

```python
"""SAML engine layer: pysaml2 integration (config, client).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""
```

`src/fastapi_auth/saml/engine/config.py`:

```python
"""Build the pysaml2 SP configuration and load IdP metadata.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from saml2 import BINDING_HTTP_POST

from fastapi_auth.saml.settings import SamlSettings


def load_idp_metadata(settings: SamlSettings) -> str:
    """Return the IdP metadata XML from the configured direct source.

    Exactly one of ``idp_metadata_file`` / ``idp_metadata_url`` must be set.
    The HTTP fetch is synchronous; callers run it in a worker thread.
    """
    if settings.idp_metadata_file:
        return Path(settings.idp_metadata_file).read_text(encoding="utf-8")
    if settings.idp_metadata_url:
        resp = httpx.get(settings.idp_metadata_url, timeout=10.0)
        resp.raise_for_status()
        return resp.text
    msg = "No IdP metadata source configured (set idp_metadata_file or idp_metadata_url)"
    raise ValueError(msg)


def build_sp_config(settings: SamlSettings) -> dict[str, Any]:
    """Assemble the pysaml2 SPConfig dict for this service provider."""
    idp_metadata = load_idp_metadata(settings)
    return {
        "entityid": settings.entity_id,
        "xmlsec_binary": settings.xmlsec_binary,
        "allow_unknown_attributes": True,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(settings.acs_url, BINDING_HTTP_POST)],
                },
                "allow_unsolicited": False,
                "authn_requests_signed": settings.authn_requests_signed,
                "want_assertions_signed": settings.want_assertions_signed,
                "want_response_signed": False,
            },
        },
        "key_file": settings.key_file,
        "cert_file": settings.cert_file,
        "metadata": {"inline": [idp_metadata]},
    }
```

- [ ] **Step 4: Test grün + lint**

Run: `uv run pytest tests/engine/test_config.py -v && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: passed; clean; 0 ty diagnostics.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/engine/__init__.py src/fastapi_auth/saml/engine/config.py tests/engine/test_config.py
git commit -m "feat(engine): pysaml2-SPConfig-Builder + direct-IdP-Metadaten"
```

---

## Task 3: Async-Engine — AuthnRequest, Response-Validierung, Identity (`engine/client.py`)

**Files:**
- Create: `src/fastapi_auth/saml/engine/client.py`
- Create: `tests/conftest.py` (Fixtures: Test-Certs + In-Memory-IdP)
- Test: `tests/engine/test_client_roundtrip.py`

**Interfaces:**
- Consumes: `build_sp_config` (Task 2), `map_attributes`/`FederatedIdentity` (Plan 1).
- Produces:
  - `class SamlEngine` mit:
    - `__init__(self, settings: SamlSettings)` — baut `Saml2Client(config=SPConfig().load(build_sp_config(settings)))` einmalig.
    - `async def create_authn_request(self, relay_state: str) -> tuple[str, str]` — gibt `(request_id, redirect_location)` zurück (HTTP-Redirect-Binding, signiert gemäß Settings). Läuft via `anyio.to_thread.run_sync`.
    - `async def parse_response(self, saml_response: str, outstanding: dict[str, str]) -> FederatedIdentity` — validiert (Signatur/Conditions/InResponseTo gegen `outstanding`), mappt auf `FederatedIdentity`. `saml_response` = base64-String wie am ACS empfangen. Läuft via `anyio.to_thread.run_sync`.
    - `def sp_metadata(self) -> str` — SP-Metadaten-XML (für `/metadata`).
  - Modulfunktion `to_identity(resp) -> FederatedIdentity` (aus `resp.session_info()` + `resp.issuer()`).

**pysaml2-Referenz (im Spike verifiziert):** `prepare_for_authenticate(entityid, relay_state, binding=BINDING_HTTP_REDIRECT, sign=...) -> (reqid, info)`; `info["headers"]` enthält `("Location", url)`. `parse_authn_request_response(b64, BINDING_HTTP_POST, outstanding={reqid: return_url}) -> AuthnResponse`; `resp.session_info()` liefert `{"ava": {...friendly names...}, "name_id": <NameID>, ...}`; `resp.issuer()`.

- [ ] **Step 1: `tests/conftest.py` mit In-Memory-IdP-Fixtures schreiben**

Dieses Fixture-Set ist die Grundlage für Task 3 und Task 6. Muster aus dem verifizierten Spike:

```python
"""Shared test fixtures: test certs and an in-memory pysaml2 IdP."""

import base64
import subprocess
from pathlib import Path

import pytest
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.config import IdPConfig, SPConfig
from saml2.metadata import create_metadata_string
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NameID
from saml2.server import Server

SP_EID = "urn:test:sp"
IDP_EID = "urn:test:idp"
ACS = "https://sp.example/saml/acs"
SSO = "https://idp.example/sso"


def _make_cert(path_key: Path, path_crt: Path, cn: str) -> None:
    subprocess.run(  # noqa: S603
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(path_key), "-out", str(path_crt),
            "-days", "2", "-subj", f"/CN={cn}",
        ],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def certs(tmp_path):
    d = tmp_path / "certs"
    d.mkdir()
    idp_key, idp_crt = d / "idp.key", d / "idp.crt"
    sp_key, sp_crt = d / "sp.key", d / "sp.crt"
    _make_cert(idp_key, idp_crt, "test-idp")
    _make_cert(sp_key, sp_crt, "test-sp")
    return {
        "idp_key": str(idp_key), "idp_crt": str(idp_crt),
        "sp_key": str(sp_key), "sp_crt": str(sp_crt),
    }


@pytest.fixture
def idp_metadata_file(tmp_path, certs):
    idp_cfg = IdPConfig().load(
        {
            "entityid": IDP_EID,
            "service": {"idp": {"endpoints": {"single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)]}}},
            "key_file": certs["idp_key"], "cert_file": certs["idp_crt"],
        }
    )
    md = create_metadata_string(None, config=idp_cfg, sign=False).decode()
    path = tmp_path / "idp-metadata.xml"
    path.write_text(md)
    return str(path)


@pytest.fixture
def make_idp(certs):
    """Return a factory that builds an in-memory IdP Server bound to given SP metadata."""

    def _factory(sp_metadata_xml: str) -> Server:
        idp_cfg = {
            "entityid": IDP_EID,
            "xmlsec_binary": "/opt/homebrew/bin/xmlsec1",
            "service": {"idp": {"endpoints": {"single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)]}}},
            "key_file": certs["idp_key"], "cert_file": certs["idp_crt"],
            "metadata": {"inline": [sp_metadata_xml]},
        }
        return Server(config=IdPConfig().load(idp_cfg))

    return _factory


def mint_response(idp: Server, request_id: str, ava: dict[str, list[str]], name_id_text: str = "u123-persistent") -> str:
    """Mint a signed base64 SAML response as an IdP would POST to the ACS."""
    name_id = NameID(format=NAMEID_FORMAT_PERSISTENT, text=name_id_text)
    xml = idp.create_authn_response(
        identity=ava,
        in_response_to=request_id,
        destination=ACS,
        sp_entity_id=SP_EID,
        name_id=name_id,
        sign_response=True,
        sign_assertion=True,
        authn={"class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "authn_auth": IDP_EID},
    )
    return base64.b64encode(xml.encode()).decode()
```

> Note: der xmlsec1-Pfad `/opt/homebrew/bin/xmlsec1` ist auf dieser Maschine korrekt.
> Falls der Implementer auf einer anderen Umgebung läuft, `shutil.which("xmlsec1")` verwenden.

- [ ] **Step 2: Failing roundtrip-test schreiben**

`tests/engine/test_client_roundtrip.py`:

```python
"""End-to-end engine test: SP AuthnRequest -> in-memory IdP -> SP validates."""

from tests.conftest import IDP_EID, SSO, mint_response

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.settings import SamlSettings


def _settings(certs, idp_metadata_file) -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
    )


async def test_create_authn_request_returns_redirect(certs, idp_metadata_file):
    engine = SamlEngine(_settings(certs, idp_metadata_file))
    reqid, location = await engine.create_authn_request(relay_state="/app")
    assert reqid
    assert location.startswith(SSO)


async def test_roundtrip_yields_federated_identity(certs, idp_metadata_file, make_idp):
    settings = _settings(certs, idp_metadata_file)
    engine = SamlEngine(settings)
    reqid, _ = await engine.create_authn_request(relay_state="/app")

    idp = make_idp(engine.sp_metadata())
    saml_response = mint_response(
        idp, reqid,
        ava={
            "eduPersonPrincipalName": ["u123@test.de"],
            "mail": ["u@test.de"],
            "eduPersonScopedAffiliation": ["staff@test.de"],
        },
    )

    identity = await engine.parse_response(saml_response, outstanding={reqid: "/app"})
    assert identity.eppn == "u123@test.de"
    assert identity.mail == ["u@test.de"]
    assert identity.scoped_affiliation == ["staff@test.de"]
    assert identity.idp_entity_id == IDP_EID
    assert identity.name_id == "u123-persistent"
```

- [ ] **Step 3: Test rot laufen lassen**

Run: `uv run pytest tests/engine/test_client_roundtrip.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.saml.engine.client`).

- [ ] **Step 4: `engine/client.py` implementieren**

`src/fastapi_auth/saml/engine/client.py`:

```python
"""Async wrapper around a pysaml2 Saml2Client for one service provider.

pysaml2 is synchronous; every blocking call runs in a worker thread.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Any

import anyio.to_thread
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string

from fastapi_auth.saml.engine.config import build_sp_config
from fastapi_auth.saml.identity.mapper import map_attributes
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings


def to_identity(resp: Any) -> FederatedIdentity:
    """Map a validated pysaml2 AuthnResponse onto a FederatedIdentity."""
    info = resp.session_info()
    name_id = info.get("name_id")
    authn_info = info.get("authn_info") or []
    authn_class = authn_info[0][0] if authn_info else None
    return map_attributes(
        info.get("ava", {}),
        name_id=name_id.text if name_id is not None else None,
        name_id_format=name_id.format if name_id is not None else None,
        idp_entity_id=resp.issuer(),
        authn_context_class=authn_class,
        assertion_id=resp.assertion.id if resp.assertion is not None else None,
    )


class SamlEngine:
    """Owns the pysaml2 client and exposes async SSO operations."""

    def __init__(self, settings: SamlSettings) -> None:
        self._settings = settings
        self._config = SPConfig().load(build_sp_config(settings))
        self._client = Saml2Client(config=self._config)

    async def create_authn_request(self, relay_state: str) -> tuple[str, str]:
        """Build a signed AuthnRequest; return (request_id, redirect URL)."""
        return await anyio.to_thread.run_sync(self._prepare, relay_state)

    def _prepare(self, relay_state: str) -> tuple[str, str]:
        reqid, info = self._client.prepare_for_authenticate(
            entityid=self._settings.fixed_idp_entity_id,
            relay_state=relay_state,
            binding=BINDING_HTTP_REDIRECT,
            sign=self._settings.authn_requests_signed,
        )
        location = dict(info["headers"])["Location"]
        return reqid, location

    async def parse_response(self, saml_response: str, outstanding: dict[str, str]) -> FederatedIdentity:
        """Validate a base64 SAML response and map it onto a FederatedIdentity."""
        return await anyio.to_thread.run_sync(self._parse, saml_response, outstanding)

    def _parse(self, saml_response: str, outstanding: dict[str, str]) -> FederatedIdentity:
        resp = self._client.parse_authn_request_response(
            saml_response, BINDING_HTTP_POST, outstanding=outstanding
        )
        if resp is None:
            msg = "SAML response could not be parsed"
            raise ValueError(msg)
        return to_identity(resp)

    def sp_metadata(self) -> str:
        """Return this SP's metadata XML."""
        return create_metadata_string(None, config=self._config, sign=False).decode()
```

- [ ] **Step 5: Test grün + lint**

Run: `uv run pytest tests/engine/ -v && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: roundtrip + config tests passed; ruff clean; ty 0 (falls pysaml2s dynamische Typen an `resp.*` ty stören, gezielt `# ty: ignore[...]` mit Begründung auf der betroffenen Zeile — pysaml2 ist untypisiert).

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/saml/engine/client.py tests/conftest.py tests/engine/test_client_roundtrip.py
git commit -m "feat(engine): async SamlEngine (AuthnRequest, Response-Validierung, Identity)"
```

---

## Task 4: Memory-Store + SessionBackend-Protocol (`session/store.py`, `session/base.py`)

**Files:**
- Create: `src/fastapi_auth/saml/session/__init__.py`, `src/fastapi_auth/saml/session/store.py`, `src/fastapi_auth/saml/session/base.py`
- Test: `tests/session/test_store.py`

**Interfaces:**
- Consumes: `FederatedIdentity` (Plan 1).
- Produces:
  - `class MemoryStore`:
    - `async def save_session(self, sid: str, identity: FederatedIdentity) -> None`
    - `async def load_session(self, sid: str) -> FederatedIdentity | None`
    - `async def delete_session(self, sid: str) -> None`
    - `async def add_outstanding(self, request_id: str, return_url: str) -> None`
    - `async def outstanding(self) -> dict[str, str]` — Kopie aller offenen `{request_id: return_url}`
    - `async def pop_outstanding(self, request_id: str) -> str | None` — entfernt & liefert `return_url`
  - `class SessionBackend(Protocol)`:
    - `async def establish(self, identity: FederatedIdentity, response: Response) -> None`
    - `async def load(self, request: Request) -> FederatedIdentity | None`
    - `async def revoke(self, request: Request, response: Response) -> None`

- [ ] **Step 1: Failing test schreiben**

`tests/session/test_store.py`:

```python
"""Tests for the in-memory session + outstanding-request store."""

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.store import MemoryStore


async def test_save_and_load_session():
    store = MemoryStore()
    ident = FederatedIdentity(eppn="u@lmu.de")
    await store.save_session("sid-1", ident)
    loaded = await store.load_session("sid-1")
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_load_missing_session_returns_none():
    store = MemoryStore()
    assert await store.load_session("nope") is None


async def test_delete_session():
    store = MemoryStore()
    await store.save_session("sid-1", FederatedIdentity())
    await store.delete_session("sid-1")
    assert await store.load_session("sid-1") is None


async def test_outstanding_roundtrip():
    store = MemoryStore()
    await store.add_outstanding("req-1", "/app")
    await store.add_outstanding("req-2", "/other")
    assert await store.outstanding() == {"req-1": "/app", "req-2": "/other"}
    assert await store.pop_outstanding("req-1") == "/app"
    assert await store.outstanding() == {"req-2": "/other"}
    assert await store.pop_outstanding("gone") is None
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/session/test_store.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/saml/session/__init__.py`:

```python
"""Session layer: pluggable backend, in-memory store, cookie backend.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""
```

`src/fastapi_auth/saml/session/store.py`:

```python
"""In-memory session and outstanding-request store (single process).

Milestone 2 default. Redis/Postgres backends arrive in Plan 3.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.saml.identity.model import FederatedIdentity


class MemoryStore:
    """Non-persistent store for sessions and outstanding AuthnRequests."""

    def __init__(self) -> None:
        self._sessions: dict[str, FederatedIdentity] = {}
        self._outstanding: dict[str, str] = {}

    async def save_session(self, sid: str, identity: FederatedIdentity) -> None:
        self._sessions[sid] = identity

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        return self._sessions.get(sid)

    async def delete_session(self, sid: str) -> None:
        self._sessions.pop(sid, None)

    async def add_outstanding(self, request_id: str, return_url: str) -> None:
        self._outstanding[request_id] = return_url

    async def outstanding(self) -> dict[str, str]:
        return dict(self._outstanding)

    async def pop_outstanding(self, request_id: str) -> str | None:
        return self._outstanding.pop(request_id, None)
```

`src/fastapi_auth/saml/session/base.py`:

```python
"""SessionBackend protocol.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Protocol

from fastapi import Request, Response

from fastapi_auth.saml.identity.model import FederatedIdentity


class SessionBackend(Protocol):
    """Establishes, loads and revokes a login session on a response/request."""

    async def establish(self, identity: FederatedIdentity, response: Response) -> None: ...

    async def load(self, request: Request) -> FederatedIdentity | None: ...

    async def revoke(self, request: Request, response: Response) -> None: ...
```

- [ ] **Step 4: Test grün + lint**

Run: `uv run pytest tests/session/test_store.py -v && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: passed; clean; 0 ty diagnostics.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/session/__init__.py src/fastapi_auth/saml/session/store.py src/fastapi_auth/saml/session/base.py tests/session/test_store.py
git commit -m "feat(session): Memory-Store + SessionBackend-Protocol"
```

---

## Task 5: Cookie-Backend (`session/cookie.py`)

**Files:**
- Create: `src/fastapi_auth/saml/session/cookie.py`
- Test: `tests/session/test_cookie.py`

**Interfaces:**
- Consumes: `SamlSettings` (Task 1), `MemoryStore` (Task 4), `SessionBackend` (Task 4), `FederatedIdentity`.
- Produces:
  - `class CookieBackend` (erfüllt `SessionBackend`):
    - `__init__(self, settings: SamlSettings, store: MemoryStore)` — hält `URLSafeTimedSerializer(settings.session_secret)`.
    - `establish`: erzeugt `sid = token_urlsafe(...)`, `store.save_session(sid, identity)`, setzt signiertes Cookie (`response.set_cookie(name, serializer.dumps(sid), max_age=ttl, httponly=True, secure=settings.cookie_secure, samesite="lax")`).
    - `load`: liest Cookie, entsigniert (`serializer.loads(..., max_age=ttl)`; bei `BadSignature`/`SignatureExpired` → `None`), `store.load_session(sid)`.
    - `revoke`: entsigniert Cookie → `store.delete_session(sid)`, `response.delete_cookie(name)`.

- [ ] **Step 1: Failing test schreiben**

`tests/session/test_cookie.py`:

```python
"""Tests for the signed-cookie session backend."""

from fastapi import Request, Response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.cookie import CookieBackend
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings


def _settings() -> SamlSettings:
    return SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file="/tmp/k",
        cert_file="/tmp/c",
        fixed_idp_entity_id="urn:test:idp",
        session_secret="s3cr3t",
        cookie_secure=False,
    )


def _request_with_cookies(cookie_header: str) -> Request:
    scope = {"type": "http", "headers": [(b"cookie", cookie_header.encode())]}
    return Request(scope)


async def test_establish_sets_signed_cookie_and_load_roundtrips():
    settings = _settings()
    store = MemoryStore()
    backend = CookieBackend(settings, store)

    response = Response()
    await backend.establish(FederatedIdentity(eppn="u@lmu.de"), response)
    set_cookie = response.headers["set-cookie"]
    assert settings.session_cookie_name in set_cookie
    assert "httponly" in set_cookie.lower()

    cookie_value = set_cookie.split(";")[0].split("=", 1)[1]
    request = _request_with_cookies(f"{settings.session_cookie_name}={cookie_value}")
    loaded = await backend.load(request)
    assert loaded is not None
    assert loaded.eppn == "u@lmu.de"


async def test_load_without_cookie_returns_none():
    backend = CookieBackend(_settings(), MemoryStore())
    assert await backend.load(_request_with_cookies("")) is None


async def test_load_with_tampered_cookie_returns_none():
    settings = _settings()
    backend = CookieBackend(settings, MemoryStore())
    request = _request_with_cookies(f"{settings.session_cookie_name}=not-a-valid-signed-value")
    assert await backend.load(request) is None
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/session/test_cookie.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/saml/session/cookie.py`:

```python
"""Signed-cookie session backend (server-side session in a store).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings

_SALT = "fastapi-auth-saml-session"


class CookieBackend:
    """Server-side session addressed by a signed session id in a cookie."""

    def __init__(self, settings: SamlSettings, store: MemoryStore) -> None:
        self._settings = settings
        self._store = store
        self._serializer = URLSafeTimedSerializer(settings.session_secret, salt=_SALT)

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        sid = secrets.token_urlsafe(32)
        await self._store.save_session(sid, identity)
        response.set_cookie(
            self._settings.session_cookie_name,
            self._serializer.dumps(sid),
            max_age=self._settings.session_ttl,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    async def load(self, request: Request) -> FederatedIdentity | None:
        sid = self._read_sid(request)
        if sid is None:
            return None
        return await self._store.load_session(sid)

    async def revoke(self, request: Request, response: Response) -> None:
        sid = self._read_sid(request)
        if sid is not None:
            await self._store.delete_session(sid)
        response.delete_cookie(self._settings.session_cookie_name)

    def _read_sid(self, request: Request) -> str | None:
        raw = request.cookies.get(self._settings.session_cookie_name)
        if not raw:
            return None
        try:
            return self._serializer.loads(raw, max_age=self._settings.session_ttl)
        except (BadSignature, SignatureExpired):
            return None
```

- [ ] **Step 4: Test grün + lint**

Run: `uv run pytest tests/session/ -v && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: passed; clean; 0 ty diagnostics.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/session/cookie.py tests/session/test_cookie.py
git commit -m "feat(session): signiertes Cookie-Backend"
```

---

## Task 6: `SamlSP`-Fassade + Router + Dependencies (`sp.py`, `router.py`)

**Files:**
- Create: `src/fastapi_auth/saml/sp.py`, `src/fastapi_auth/saml/router.py`
- Modify: `src/fastapi_auth/saml/__init__.py` (Re-Exports: `SamlSP`, `SamlSettings`)
- Test: `tests/test_router_login_flow.py`

**Interfaces:**
- Consumes: `SamlSettings`, `SamlEngine`, `MemoryStore`, `CookieBackend`, `FederatedIdentity`.
- Produces:
  - `class SamlSP`:
    - `__init__(self, settings: SamlSettings)` — baut `SamlEngine`, `MemoryStore`, `CookieBackend`, `APIRouter` (via `build_router(self)`).
    - Attribute: `.settings`, `.engine`, `.store`, `.backend`, `.router`.
    - `def current_user(self) -> Callable` — FastAPI-Dependency, die `FederatedIdentity` liefert oder `HTTPException(401)` wirft.
    - `def optional_user(self) -> Callable` — Dependency, die `FederatedIdentity | None` liefert.
  - `build_router(sp: SamlSP) -> APIRouter` mit:
    - `GET /login?next=<path>` → `reqid, location = await engine.create_authn_request(relay_state=next)`; `await store.add_outstanding(reqid, next)`; `RedirectResponse(location, status_code=303)`.
    - `POST /acs` (Form `SAMLResponse`, optional `RelayState`) → `outstanding = await store.outstanding()`; `identity = await engine.parse_response(SAMLResponse, outstanding)`; `next_url = RelayState or "/"`; leere `outstanding` aufräumen (`pop` je matched reqid ist nicht direkt bekannt → nach Erfolg `outstanding` leeren, das den bekannten reqids entspricht: hier alle poppen, deren Wert == next_url; einfacher: `store` behält offene, TTL folgt in Plan 3 — für Milestone: nach Erfolg alle `outstanding` leeren); `response = RedirectResponse(next_url, status_code=303)`; `await backend.establish(identity, response)`; return response.
    - `GET /metadata` → `Response(engine.sp_metadata(), media_type="application/samlmetadata+xml")`.
  - Re-Exports in `fastapi_auth.saml`: zusätzlich `SamlSP`, `SamlSettings` (bestehende identity-Re-Exports bleiben).

> Outstanding-Cleanup im Milestone bewusst simpel (nach erfolgreichem ACS: `store` per
> `pop_outstanding` für die konsumierte reqid leeren — die reqid steckt in der Response
> als `InResponseTo`; da pysaml2 sie intern prüft, genügt fürs Milestone das Leeren der
> gesamten `outstanding`-Map nach Erfolg). Sauberes per-reqid-Handling + TTL: Plan 3.

- [ ] **Step 1: Failing end-to-end test schreiben**

`tests/test_router_login_flow.py`:

```python
"""End-to-end login flow through the FastAPI router with an in-memory IdP."""

from urllib.parse import parse_qs, urlparse

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from tests.conftest import IDP_EID, mint_response

from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _build_app(certs, idp_metadata_file):
    settings = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file,
        fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t",
        cookie_secure=False,
    )
    sp = SamlSP(settings)
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")

    @app.get("/me")
    async def me(user: FederatedIdentity = Depends(sp.current_user())):
        return {"eppn": user.eppn, "affiliation": user.scoped_affiliation}

    return app, sp


def test_metadata_endpoint(certs, idp_metadata_file):
    app, _ = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    resp = client.get("/saml/metadata")
    assert resp.status_code == 200
    assert "urn:test:sp" in resp.text


def test_protected_route_401_without_session(certs, idp_metadata_file):
    app, _ = _build_app(certs, idp_metadata_file)
    client = TestClient(app)
    assert client.get("/me").status_code == 401


def test_full_login_flow(certs, idp_metadata_file, make_idp):
    app, sp = _build_app(certs, idp_metadata_file)
    client = TestClient(app)

    # 1. /login -> redirect to IdP SSO with SAMLRequest
    login = client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    assert login.status_code == 303
    location = login.headers["location"]
    assert "SAMLRequest" in urlparse(location).query
    # the outstanding request id is what pysaml2 generated
    outstanding = __import__("anyio").from_thread  # placeholder to show sync bridge not needed
    reqids = list((sp.store._outstanding).keys())  # noqa: SLF001 - test introspection
    assert len(reqids) == 1
    reqid = reqids[0]

    # 2. IdP mints a signed response for that request
    idp = make_idp(sp.engine.sp_metadata())
    saml_response = mint_response(
        idp, reqid,
        ava={"eduPersonPrincipalName": ["u123@test.de"], "eduPersonScopedAffiliation": ["staff@test.de"]},
    )

    # 3. POST to ACS -> session cookie set, redirect to next
    acs = client.post(
        "/saml/acs",
        data={"SAMLResponse": saml_response, "RelayState": "/app"},
        follow_redirects=False,
    )
    assert acs.status_code == 303
    assert acs.headers["location"] == "/app"
    assert sp.settings.session_cookie_name in acs.headers.get("set-cookie", "")

    # 4. protected route now returns the identity (cookie carried by client)
    me = client.get("/me")
    assert me.status_code == 200
    assert me.json()["eppn"] == "u123@test.de"
    assert me.json()["affiliation"] == ["staff@test.de"]
```

> Der `outstanding = __import__(...)`-Platzhalter oben ist nur illustrativ; entferne ihn
> beim Implementieren und lies die reqid direkt via `list(sp.store._outstanding)`.

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_router_login_flow.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.saml.sp`).

- [ ] **Step 3: `sp.py` und `router.py` implementieren**

`src/fastapi_auth/saml/router.py`:

```python
"""FastAPI router factory for the SAML SP endpoints.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Form, Response
from fastapi.responses import RedirectResponse

if TYPE_CHECKING:
    from fastapi_auth.saml.sp import SamlSP

_METADATA_MEDIA_TYPE = "application/samlmetadata+xml"


def build_router(sp: SamlSP) -> APIRouter:
    """Build the /login, /acs and /metadata routes bound to this SamlSP."""
    router = APIRouter()

    @router.get("/login")
    async def login(next: str = "/") -> RedirectResponse:  # noqa: A002 - matches query param name
        request_id, location = await sp.engine.create_authn_request(relay_state=next)
        await sp.store.add_outstanding(request_id, next)
        return RedirectResponse(location, status_code=303)

    @router.post("/acs")
    async def acs(
        SAMLResponse: Annotated[str, Form()],  # noqa: N803 - SAML wire name
        RelayState: Annotated[str, Form()] = "/",  # noqa: N803 - SAML wire name
    ) -> RedirectResponse:
        outstanding = await sp.store.outstanding()
        identity = await sp.engine.parse_response(SAMLResponse, outstanding)
        for request_id in outstanding:
            await sp.store.pop_outstanding(request_id)
        response = RedirectResponse(RelayState or "/", status_code=303)
        await sp.backend.establish(identity, response)
        return response

    @router.get("/metadata")
    async def metadata() -> Response:
        return Response(sp.engine.sp_metadata(), media_type=_METADATA_MEDIA_TYPE)

    return router
```

`src/fastapi_auth/saml/sp.py`:

```python
"""SamlSP facade: wires settings, engine, store, session backend and router.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.identity.model import FederatedIdentity
from fastapi_auth.saml.router import build_router
from fastapi_auth.saml.session.cookie import CookieBackend
from fastapi_auth.saml.session.store import MemoryStore
from fastapi_auth.saml.settings import SamlSettings


class SamlSP:
    """Composition root: one configured SAML service provider."""

    def __init__(self, settings: SamlSettings) -> None:
        self.settings = settings
        self.engine = SamlEngine(settings)
        self.store = MemoryStore()
        self.backend = CookieBackend(settings, self.store)
        self.router = build_router(self)

    def optional_user(self) -> Callable[[Request], object]:
        """Dependency returning the FederatedIdentity or None."""

        async def _dep(request: Request) -> FederatedIdentity | None:
            return await self.backend.load(request)

        return _dep

    def current_user(self) -> Callable[[Request], object]:
        """Dependency returning the FederatedIdentity or raising 401."""

        async def _dep(request: Request) -> FederatedIdentity:
            identity = await self.backend.load(request)
            if identity is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
            return identity

        return _dep


__all__ = ["SamlSP"]

# Re-exported for convenience; Depends is imported so callers can build deps.
_ = Depends
```

> Hinweis: Der `_ = Depends`-Trick vermeidet einen ungenutzten Import; falls ruff das
> als unnötig flaggt, stattdessen `Depends` entfernen und nur importieren, was genutzt wird.
> Prüfe mit ruff und bereinige, statt Warnungen zu ignorieren.

- [ ] **Step 4: Public API re-exportieren**

Ergänze in `src/fastapi_auth/saml/__init__.py` die Re-Exports (bestehende identity-Re-Exports bleiben, `__all__` erweitern):

```python
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP
```

und ergänze `"SamlSP"`, `"SamlSettings"` in `__all__` (sortiert).

- [ ] **Step 5: Test grün + volle Suite + lint**

Run: `uv run pytest -v && uv run ruff format . && uv run ruff check . && uv run ty check src tests && make lint`
Expected: alle Tests passed (inkl. Plan-1-Suite unverändert grün); ruff clean; ty 0; `make lint` exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/saml/sp.py src/fastapi_auth/saml/router.py src/fastapi_auth/saml/__init__.py tests/test_router_login_flow.py
git commit -m "feat(saml): SamlSP-Fassade + Router (/login /acs /metadata) + current_user"
```

---

## Self-Review

**Spec-Abdeckung (Plan 2 vs. Spec §2/§3/§4/§6 + Milestone-Scope):**
- Async pysaml2-Wrapper (`anyio.to_thread`) → Task 3 ✅
- `source='direct'` (Datei/URL) → Task 2 ✅
- `discovery='passthrough'` (feste entityID) → Task 1 (Settings) + Task 3 (`prepare_for_authenticate(entityid=fixed_idp_entity_id)`) ✅
- AuthnRequest (signiert, Redirect-Binding) → Task 3 ✅
- ACS: Signatur/Conditions/InResponseTo (via pysaml2 `parse_authn_request_response` + `outstanding`) → Task 3 + Task 6 ✅
- AttributeStatement → `FederatedIdentity` (Reuse Plan-1-Mapper) → Task 3 `to_identity` ✅
- Cookie-Session (Default) + Memory-Store → Task 4 + Task 5 ✅
- SP-Metadaten-Endpoint → Task 6 `/metadata` ✅
- `current_user`/`optional_user`-Dependencies → Task 6 ✅
- Public API `from fastapi_auth import saml` (`SamlSP`, `SamlSettings`) → Task 6 ✅

**Bewusst NICHT in Plan 2 (Plan 3/4):** MDQ/Aggregat, externer DS/embedded WAYF, JWT,
Redis/Postgres, SLO, RequestedAttributes/Enforcement, per-reqid-Outstanding-TTL,
Open-Redirect-Allowlist (RelayState wird hier ungeprüft als lokaler Pfad genutzt — in
Plan 3 gegen `allowed_redirect_hosts` absichern), Assertion-Decryption-Konfiguration
(encryption_keypairs) — Milestone nutzt unverschlüsselte Test-Assertions.

**Platzhalter-Scan:** kein TBD/TODO; jeder Code-Schritt vollständig. (Der eine
illustrative `__import__`-Platzhalter im Test ist explizit als zu entfernen markiert.)

**Typ-Konsistenz:** `SamlEngine.create_authn_request -> (str, str)`, `parse_response -> FederatedIdentity`,
`MemoryStore`-Signaturen, `CookieBackend` erfüllt `SessionBackend`, `SamlSP`-Attribute
(`settings/engine/store/backend/router`) — durchgängig konsistent zwischen Tasks 3–6.

**Bekannte Risiken:**
- pysaml2 ist untypisiert → an `resp.*` evtl. gezielte `# ty: ignore` nötig (dokumentiert in Task 3 Step 5).
- `xmlsec1`-Pfad in `tests/conftest.py` ist auf `/opt/homebrew/bin/xmlsec1` gesetzt; für andere Umgebungen `shutil.which("xmlsec1")`.
- Der Login-Flow-Test greift auf `sp.store._outstanding` zu (Test-Introspektion, `# noqa: SLF001`) — akzeptabel im Test, da die reqid sonst nur im IdP-Redirect steckt.

---

## Nächste Meilensteine (eigene Pläne)

- **Plan 3 — SP-Profil & Sessions:** RequestedAttributes/`isRequired` + ACS-Enforcement,
  Entity Categories/mdui/Privacy in SP-Metadaten, JWT-Backend, Redis/Postgres-Store,
  Open-Redirect-Schutz für RelayState, per-reqid-Outstanding-TTL, Assertion-Decryption.
- **Plan 4 — Föderation & Discovery:** MDQ + Aggregat, externer DS + embedded WAYF, best-effort SLO.
- **Plan 5 — Docker/CI/Doku:** SimpleSAMLphp-Compose (`make test-integration`), GitHub Actions
  + tox, Sphinx-Doku, How-tos für `lmuidp-container` und DFN-AAI-Testföderation.
