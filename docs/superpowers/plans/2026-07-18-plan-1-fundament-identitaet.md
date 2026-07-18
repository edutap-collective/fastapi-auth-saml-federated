# Plan 1 — Fundament & Identität (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Das Package-Fundament (`fastapi_auth`-Namespace, Tooling) und das
eduPerson/SCHAC-Identitäts-Herzstück (Attribut-Registry, `FederatedIdentity`,
Mapper, Identifier-Auswahl) als reine, unit-getestete Bibliotheksschicht ohne
Netzwerk aufbauen.

**Architecture:** PEP-420-Namespace-Package `fastapi_auth` (src-Layout, kein
`__init__.py` in `fastapi_auth/`) mit dem Submodul `saml`. Die `identity/`-Schicht
ist völlig eigenständig: Eine deklarative Registry mappt Attribut-OIDs/-Namen auf
Felder eines Pydantic-v2-Modells; ein reiner Mapper übersetzt ein bereits
extrahiertes Attribut-Dict in `FederatedIdentity`. Keine SAML-/XML-/HTTP-Abhängigkeit
in diesem Meilenstein.

**Tech Stack:** Python 3.12+, setuptools (PEP 420 namespaces), Pydantic v2,
pydantic-settings, pytest + pytest-asyncio, ruff, ty, uv.

## Global Constraints

- Distribution (PyPI): `fastapi-auth-saml-federated`; Import: `from fastapi_auth import saml`.
- Namespace `fastapi_auth` ist PEP-420-implizit — **niemals** `src/fastapi_auth/__init__.py` anlegen.
- Lizenz: `Apache-2.0 OR EUPL-1.2` (SPDX-Ausdruck); Dual-License-Header in Quellcodedateien.
- Python-Floor: `>=3.12`. async-first (spätere Meilensteine); hier reiner sync-freier Code.
- Sprache: Code/Kommentare/Docstrings **Englisch**; Commit-Messages **Deutsch** (LMU-Kontext), Conventional Commits.
- Typisierung: Type Hints für alle öffentlichen Funktionen; kein `Any` ohne Begründung.
- ruff-Regelgruppen: `E,F,W,B,UP,I,D,S`. Tests dürfen `S101`/`D` ignorieren.
- Niemals `git push`; niemals direkt auf `main` — Arbeit läuft auf `docs/saml-federated-design` bzw. einem `feature/…`-Branch.
- Alle Attribut-OIDs exakt wie in Task 2 gelistet (aus dem Spec, eduPerson/SCHAC/SAML-Subject-Identifier).

---

## File Structure

```text
pyproject.toml                         # Distribution, Deps, ruff/pytest/ty-Konfig
Makefile                               # lint / reformat / test-local (test-integration: Platzhalter)
README.md                              # bereits vorhanden — Lizenz-/Install-Notiz ergänzen
LICENSE-APACHE                         # Apache-2.0 Volltext
LICENSE-EUPL                           # EUPL-1.2 Volltext
.python-version                        # 3.12
src/fastapi_auth/saml/__init__.py      # Public API (Re-Exports der identity-Schicht)
src/fastapi_auth/saml/py.typed         # PEP 561 Marker (leer)
src/fastapi_auth/saml/identity/__init__.py
src/fastapi_auth/saml/identity/registry.py   # AttributeDef + REGISTRY + Resolver
src/fastapi_auth/saml/identity/model.py      # FederatedIdentity (Pydantic v2)
src/fastapi_auth/saml/identity/mapper.py     # map_attributes(): dict -> FederatedIdentity
src/fastapi_auth/saml/identity/identifier.py # select_identifier()
tests/test_scaffold.py
tests/identity/test_registry.py
tests/identity/test_model.py
tests/identity/test_mapper.py
tests/identity/test_identifier.py
```

---

## Task 1: Projekt-Gerüst & Tooling

**Files:**
- Create: `pyproject.toml`, `Makefile`, `.python-version`, `LICENSE-APACHE`, `LICENSE-EUPL`
- Create: `src/fastapi_auth/saml/__init__.py`, `src/fastapi_auth/saml/py.typed`
- Modify: `README.md`
- Test: `tests/test_scaffold.py`

**Interfaces:**
- Consumes: nichts.
- Produces: importierbares Package `fastapi_auth.saml` (`saml.__version__: str`); lauffähiges `uv run pytest`, `uv run ruff check`.

- [ ] **Step 1: `.python-version` anlegen**

```text
3.12
```

- [ ] **Step 2: `pyproject.toml` anlegen**

```toml
[build-system]
requires = ["setuptools>=77.0.0"]
build-backend = "setuptools.build_meta"

[project]
name = "fastapi-auth-saml-federated"
version = "0.1.0.dev0"
description = "Federated SAML2 Service Provider for FastAPI (Shibboleth/eduGAIN/NREN AAIs)"
readme = "README.md"
requires-python = ">=3.12"
license = "Apache-2.0 OR EUPL-1.2"
license-files = ["LICENSE-APACHE", "LICENSE-EUPL"]
authors = [{ name = "Alexander Loechel", email = "Alexander.Loechel@lmu.de" }]
keywords = ["saml", "saml2", "shibboleth", "edugain", "fastapi", "sso", "federation", "eduperson", "schac"]
classifiers = [
    "Framework :: FastAPI",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: System :: Systems Administration :: Authentication/Directory",
]
dependencies = [
    "fastapi>=0.115",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
]

[project.optional-dependencies]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.23",
    "anyio>=4",
    "respx>=0.21",
    "httpx>=0.27",
    "ruff>=0.6",
    "ty",
    "pdbp>=1.5",
]

[project.urls]
Repository = "https://github.com/loechel/fastapi-auth-saml-federated"

[tool.setuptools.packages.find]
where = ["src"]
include = ["fastapi_auth*"]
namespaces = true

[tool.ruff]
line-length = 100
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "W", "B", "UP", "I", "D", "S"]
ignore = ["D203", "D213"]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101", "D"]

[tool.ruff.lint.pydocstyle]
convention = "pep257"

[tool.pytest.ini_options]
addopts = "-ra"
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 3: Lizenz-Volltexte anlegen**

Run:

```bash
curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE-APACHE
curl -fsSL https://interoperable-europe.ec.europa.eu/sites/default/files/custom-page/attachment/eupl_v1.2_en.txt -o LICENSE-EUPL
test -s LICENSE-APACHE && test -s LICENSE-EUPL && echo "licenses ok"
```

Expected: `licenses ok` (falls die EUPL-URL nicht erreichbar ist, EUPL-1.2-Volltext manuell von <https://interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12> speichern).

- [ ] **Step 4: `Makefile` anlegen**

```make
.PHONY: install lint reformat test-local test-integration

install:
	uv pip install -U -e ".[dev]"

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run ty check src tests

reformat:
	uv run ruff format .
	uv run ruff check --fix .

test-local:
	uv run pytest

test-integration:
	@echo "Integrationstests kommen in Meilenstein 5 (SimpleSAMLphp-Compose)."
```

- [ ] **Step 5: Namespace-Package anlegen (KEIN `__init__.py` in `fastapi_auth/`)**

Run:

```bash
mkdir -p src/fastapi_auth/saml
touch src/fastapi_auth/saml/py.typed
test ! -e src/fastapi_auth/__init__.py && echo "namespace ok"
```

Expected: `namespace ok`

`src/fastapi_auth/saml/__init__.py`:

```python
"""Federated SAML2 Service Provider for FastAPI.

Public entry point of the ``fastapi_auth.saml`` package.
Import via ``from fastapi_auth import saml``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0.dev0"
```

- [ ] **Step 6: `README.md` um Install-/Lizenz-Notiz ergänzen**

Ersetze den gesamten Inhalt von `README.md` durch:

````markdown
# fastapi-auth-saml-federated

Federated SAML2 Service Provider for FastAPI — Shibboleth / eduGAIN / NREN AAIs
(DFN-AAI, SWITCHaai, SURFconext, SWAMID). Part of the `fastapi_auth` package family.

```python
from fastapi_auth import saml
```

## Install (development)

```bash
uv venv && source .venv/bin/activate
make install          # uv pip install -U -e ".[dev]"
make test-local
```

## License

Dual-licensed: **Apache-2.0 OR EUPL-1.2** — the recipient may choose either.
See `LICENSE-APACHE` and `LICENSE-EUPL`.
````

- [ ] **Step 7: Scaffold-Test schreiben (failing)**

`tests/test_scaffold.py`:

```python
"""Smoke tests for the package scaffold and namespace layout."""

import fastapi_auth.saml as saml


def test_package_imports_via_namespace():
    assert saml.__version__ == "0.1.0.dev0"


def test_namespace_has_no_init_module(tmp_path):
    import fastapi_auth

    # PEP 420 namespace packages expose no single __file__.
    assert getattr(fastapi_auth, "__file__", None) is None
```

- [ ] **Step 8: Env erstellen & Test laufen lassen (rot → grün)**

Run:

```bash
uv venv
uv pip install -U -e ".[dev]"
uv run pytest tests/test_scaffold.py -v
```

Expected: 2 passed. (Falls `fastapi_auth.__file__` doch gesetzt ist, wurde versehentlich ein `__init__.py` erzeugt — löschen.)

- [ ] **Step 9: Lint & Format prüfen**

Run:

```bash
uv run ruff format .
uv run ruff check .
```

Expected: „All checks passed!" und keine Format-Änderungen mehr offen.

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml Makefile .python-version LICENSE-APACHE LICENSE-EUPL README.md src tests/test_scaffold.py
git commit -m "chore: Projekt-Gerüst mit fastapi_auth-Namespace und Tooling"
```

---

## Task 2: Attribut-Registry (eduPerson / SCHAC / SAML Subject Identifier)

**Files:**
- Create: `src/fastapi_auth/saml/identity/__init__.py`, `src/fastapi_auth/saml/identity/registry.py`
- Test: `tests/identity/test_registry.py`

**Interfaces:**
- Consumes: nichts.
- Produces:
  - `AttributeDef` (frozen dataclass): Felder `field: str`, `friendly: str`, `oid: str`, `multivalued: bool`.
  - `REGISTRY: tuple[AttributeDef, ...]`.
  - `resolve(name: str) -> AttributeDef | None` — akzeptiert OID (`urn:oid:…` bzw. `urn:oasis:…`), friendly-Kurzname (`eduPersonPrincipalName`) und MACE-URN (`urn:mace:dir:attribute-def:…`).

- [ ] **Step 1: Failing test schreiben**

`tests/identity/test_registry.py`:

```python
"""Tests for the eduPerson/SCHAC attribute registry."""

import pytest

from fastapi_auth.saml.identity import registry


def test_resolve_by_oid():
    d = registry.resolve("urn:oid:1.3.6.1.4.1.5923.1.1.1.6")
    assert d is not None
    assert d.field == "eppn"
    assert d.multivalued is False


def test_resolve_by_friendly_name():
    assert registry.resolve("eduPersonPrincipalName").field == "eppn"


def test_resolve_by_mace_urn():
    d = registry.resolve("urn:mace:dir:attribute-def:eduPersonPrincipalName")
    assert d.field == "eppn"


def test_resolve_subject_id_and_pairwise_id():
    assert registry.resolve("urn:oasis:names:tc:SAML:attribute:subject-id").field == "subject_id"
    assert registry.resolve("urn:oasis:names:tc:SAML:attribute:pairwise-id").field == "pairwise_id"


def test_scoped_affiliation_is_multivalued():
    assert registry.resolve("urn:oid:1.3.6.1.4.1.5923.1.1.1.9").multivalued is True


def test_unknown_returns_none():
    assert registry.resolve("urn:oid:9.9.9") is None


@pytest.mark.parametrize("field", ["eppn", "subject_id", "mail", "scoped_affiliation", "home_organization"])
def test_every_expected_field_present(field):
    assert any(d.field == field for d in registry.REGISTRY)
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/identity/test_registry.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.saml.identity`).

- [ ] **Step 3: `identity`-Package + Registry implementieren**

`src/fastapi_auth/saml/identity/__init__.py`:

```python
"""Identity layer: attribute registry, model, mapper, identifier selection.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""
```

`src/fastapi_auth/saml/identity/registry.py`:

```python
"""Registry mapping SAML attribute names/OIDs to FederatedIdentity fields.

Covers modern SAML Subject Identifiers (subject-id, pairwise-id), eduPerson,
SCHAC and core LDAP attributes. Each attribute is resolvable by its OID
(``urn:oid:…`` / ``urn:oasis:…``), its friendly short name and its MACE URN.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from dataclasses import dataclass

_MACE_PREFIX = "urn:mace:dir:attribute-def:"


@dataclass(frozen=True)
class AttributeDef:
    """A single known attribute and how it maps onto FederatedIdentity."""

    field: str
    friendly: str
    oid: str
    multivalued: bool


REGISTRY: tuple[AttributeDef, ...] = (
    # --- Modern SAML V2.0 Subject Identifiers (preferred) ---
    AttributeDef("subject_id", "subject-id", "urn:oasis:names:tc:SAML:attribute:subject-id", False),
    AttributeDef("pairwise_id", "pairwise-id", "urn:oasis:names:tc:SAML:attribute:pairwise-id", False),
    # --- eduPerson ---
    AttributeDef("eppn", "eduPersonPrincipalName", "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", False),
    AttributeDef("unique_id", "eduPersonUniqueId", "urn:oid:1.3.6.1.4.1.5923.1.1.1.13", False),
    AttributeDef("affiliation", "eduPersonAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.1", True),
    AttributeDef("scoped_affiliation", "eduPersonScopedAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.9", True),
    AttributeDef("entitlement", "eduPersonEntitlement", "urn:oid:1.3.6.1.4.1.5923.1.1.1.7", True),
    AttributeDef("assurance", "eduPersonAssurance", "urn:oid:1.3.6.1.4.1.5923.1.1.1.11", True),
    AttributeDef("orcid", "eduPersonOrcid", "urn:oid:1.3.6.1.4.1.5923.1.1.1.16", True),
    # --- SCHAC ---
    AttributeDef("home_organization", "schacHomeOrganization", "urn:oid:1.3.6.1.4.1.25178.1.2.9", False),
    AttributeDef("home_organization_type", "schacHomeOrganizationType", "urn:oid:1.3.6.1.4.1.25178.1.2.10", True),
    AttributeDef("personal_unique_code", "schacPersonalUniqueCode", "urn:oid:1.3.6.1.4.1.25178.1.2.14", True),
    # --- Core / LDAP ---
    AttributeDef("mail", "mail", "urn:oid:0.9.2342.19200300.100.1.3", True),
    AttributeDef("display_name", "displayName", "urn:oid:2.16.840.1.113730.3.1.241", False),
    AttributeDef("given_name", "givenName", "urn:oid:2.5.4.42", False),
    AttributeDef("surname", "sn", "urn:oid:2.5.4.4", False),
    AttributeDef("common_name", "cn", "urn:oid:2.5.4.3", False),
    AttributeDef("preferred_language", "preferredLanguage", "urn:oid:2.16.840.1.113730.3.1.39", False),
)

_BY_KEY: dict[str, AttributeDef] = {}
for _d in REGISTRY:
    _BY_KEY[_d.oid] = _d
    _BY_KEY[_d.friendly] = _d
    _BY_KEY[f"{_MACE_PREFIX}{_d.friendly}"] = _d


def resolve(name: str) -> AttributeDef | None:
    """Resolve an attribute by OID, friendly short name or MACE URN."""
    return _BY_KEY.get(name)
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/identity/test_registry.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/identity/__init__.py src/fastapi_auth/saml/identity/registry.py tests/identity/test_registry.py
git commit -m "feat(identity): Attribut-Registry für eduPerson/SCHAC/Subject-Identifier"
```

---

## Task 3: `FederatedIdentity`-Modell

**Files:**
- Create: `src/fastapi_auth/saml/identity/model.py`
- Test: `tests/identity/test_model.py`

**Interfaces:**
- Consumes: nichts (rein deklarativ).
- Produces: `FederatedIdentity` (Pydantic `BaseModel`) mit den Feldern:
  - Single: `subject_id, pairwise_id, eppn, unique_id, display_name, given_name, surname, common_name, home_organization, preferred_language: str | None`
  - Multi (`list[str]`, default `[]`): `affiliation, scoped_affiliation, entitlement, assurance, orcid, mail, home_organization_type, personal_unique_code`
  - SAML-Meta: `name_id, name_id_format, idp_entity_id, authn_context_class, assertion_id: str | None`; `authn_instant: datetime | None`
  - Escape-Hatch: `attributes: dict[str, list[str]]` (default `{}`)
  - Alle Defaults gesetzt, sodass `FederatedIdentity()` konstruiert werden kann.

- [ ] **Step 1: Failing test schreiben**

`tests/identity/test_model.py`:

```python
"""Tests for the FederatedIdentity model."""

from fastapi_auth.saml.identity.model import FederatedIdentity


def test_empty_identity_has_sane_defaults():
    ident = FederatedIdentity()
    assert ident.eppn is None
    assert ident.mail == []
    assert ident.scoped_affiliation == []
    assert ident.attributes == {}


def test_identity_holds_values():
    ident = FederatedIdentity(
        eppn="u123@lmu.de",
        scoped_affiliation=["staff@lmu.de", "member@lmu.de"],
        mail=["a@lmu.de"],
        attributes={"eduPersonPrincipalName": ["u123@lmu.de"]},
    )
    assert ident.eppn == "u123@lmu.de"
    assert ident.scoped_affiliation == ["staff@lmu.de", "member@lmu.de"]
    assert ident.attributes["eduPersonPrincipalName"] == ["u123@lmu.de"]


def test_multivalue_lists_are_independent_between_instances():
    a = FederatedIdentity()
    a.mail.append("x@lmu.de")
    b = FederatedIdentity()
    assert b.mail == []
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/identity/test_model.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Modell implementieren**

`src/fastapi_auth/saml/identity/model.py`:

```python
"""Typed identity assembled from a SAML assertion.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FederatedIdentity(BaseModel):
    """Curated view of the attributes released by an IdP.

    Well-known attributes are typed fields; the full set of released
    attributes (friendly-name keyed) is always available under ``attributes``.
    """

    # --- stable identifiers ---
    subject_id: str | None = None
    pairwise_id: str | None = None
    eppn: str | None = None
    unique_id: str | None = None

    # --- affiliation / authorization ---
    affiliation: list[str] = Field(default_factory=list)
    scoped_affiliation: list[str] = Field(default_factory=list)
    entitlement: list[str] = Field(default_factory=list)
    assurance: list[str] = Field(default_factory=list)

    # --- personal / core ---
    mail: list[str] = Field(default_factory=list)
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    common_name: str | None = None
    orcid: list[str] = Field(default_factory=list)
    preferred_language: str | None = None

    # --- SCHAC / organization ---
    home_organization: str | None = None
    home_organization_type: list[str] = Field(default_factory=list)
    personal_unique_code: list[str] = Field(default_factory=list)

    # --- SAML metadata ---
    name_id: str | None = None
    name_id_format: str | None = None
    idp_entity_id: str | None = None
    authn_instant: datetime | None = None
    authn_context_class: str | None = None
    assertion_id: str | None = None

    # --- escape hatch: all released attributes (friendly-name -> values) ---
    attributes: dict[str, list[str]] = Field(default_factory=dict)
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/identity/test_model.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/identity/model.py tests/identity/test_model.py
git commit -m "feat(identity): FederatedIdentity-Modell mit Escape-Hatch"
```

---

## Task 4: Attribut-Mapper

**Files:**
- Create: `src/fastapi_auth/saml/identity/mapper.py`
- Test: `tests/identity/test_mapper.py`

**Interfaces:**
- Consumes: `registry.resolve` (Task 2), `FederatedIdentity` (Task 3).
- Produces:
  - `map_attributes(raw: dict[str, list[str]], *, name_id: str | None = None, name_id_format: str | None = None, idp_entity_id: str | None = None, authn_instant: datetime | None = None, authn_context_class: str | None = None, assertion_id: str | None = None) -> FederatedIdentity`
  - Verhalten: bekannte Attribute → Feld (single = erster Wert, multi = ganze Liste). `attributes` enthält **alle** Attribute unter friendly-Namen (unbekannte unter ihrem Rohschlüssel). Leere Wertlisten werden übersprungen.

- [ ] **Step 1: Failing test schreiben**

`tests/identity/test_mapper.py`:

```python
"""Tests for mapping a raw attribute dict onto FederatedIdentity."""

from datetime import datetime, timezone

from fastapi_auth.saml.identity.mapper import map_attributes

_EPPN = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
_SCOPED = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
_SUBJECT_ID = "urn:oasis:names:tc:SAML:attribute:subject-id"
_MAIL = "urn:oid:0.9.2342.19200300.100.1.3"


def test_single_valued_takes_first_value():
    ident = map_attributes({_EPPN: ["u123@lmu.de"]})
    assert ident.eppn == "u123@lmu.de"


def test_multi_valued_keeps_full_list():
    ident = map_attributes({_SCOPED: ["staff@lmu.de", "member@lmu.de"]})
    assert ident.scoped_affiliation == ["staff@lmu.de", "member@lmu.de"]


def test_subject_id_maps():
    ident = map_attributes({_SUBJECT_ID: ["abc@lmu.de"]})
    assert ident.subject_id == "abc@lmu.de"


def test_attributes_escape_hatch_uses_friendly_names():
    ident = map_attributes({_EPPN: ["u@lmu.de"], _MAIL: ["a@lmu.de", "b@lmu.de"]})
    assert ident.attributes["eduPersonPrincipalName"] == ["u@lmu.de"]
    assert ident.attributes["mail"] == ["a@lmu.de", "b@lmu.de"]


def test_unknown_attribute_kept_under_raw_key():
    ident = map_attributes({"urn:oid:9.9.9": ["x"]})
    assert ident.attributes["urn:oid:9.9.9"] == ["x"]


def test_empty_value_list_is_skipped():
    ident = map_attributes({_EPPN: []})
    assert ident.eppn is None
    assert "eduPersonPrincipalName" not in ident.attributes


def test_saml_metadata_is_carried_through():
    ts = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
    ident = map_attributes(
        {_EPPN: ["u@lmu.de"]},
        name_id="nameid-123",
        name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        idp_entity_id="urn:lmu.de:testidp",
        authn_instant=ts,
        authn_context_class="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        assertion_id="_abc",
    )
    assert ident.idp_entity_id == "urn:lmu.de:testidp"
    assert ident.authn_instant == ts
    assert ident.assertion_id == "_abc"
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/identity/test_mapper.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Mapper implementieren**

`src/fastapi_auth/saml/identity/mapper.py`:

```python
"""Map a raw (already extracted) SAML attribute dict onto FederatedIdentity.

Pure function — no XML, no network. The caller (engine layer, later milestone)
passes attributes keyed by OID or friendly name, plus assertion metadata.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from datetime import datetime

from fastapi_auth.saml.identity import registry
from fastapi_auth.saml.identity.model import FederatedIdentity


def map_attributes(
    raw: dict[str, list[str]],
    *,
    name_id: str | None = None,
    name_id_format: str | None = None,
    idp_entity_id: str | None = None,
    authn_instant: datetime | None = None,
    authn_context_class: str | None = None,
    assertion_id: str | None = None,
) -> FederatedIdentity:
    """Build a FederatedIdentity from released attributes and assertion metadata."""
    fields: dict[str, object] = {}
    attributes: dict[str, list[str]] = {}

    for key, values in raw.items():
        if not values:
            continue
        definition = registry.resolve(key)
        if definition is None:
            attributes[key] = list(values)
            continue
        attributes[definition.friendly] = list(values)
        fields[definition.field] = list(values) if definition.multivalued else values[0]

    return FederatedIdentity(
        name_id=name_id,
        name_id_format=name_id_format,
        idp_entity_id=idp_entity_id,
        authn_instant=authn_instant,
        authn_context_class=authn_context_class,
        assertion_id=assertion_id,
        attributes=attributes,
        **fields,
    )
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/identity/test_mapper.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/identity/mapper.py tests/identity/test_mapper.py
git commit -m "feat(identity): Attribut-Mapper (dict -> FederatedIdentity)"
```

---

## Task 5: Identifier-Auswahl

**Files:**
- Create: `src/fastapi_auth/saml/identity/identifier.py`
- Modify: `src/fastapi_auth/saml/__init__.py` (Public-API-Re-Exports)
- Test: `tests/identity/test_identifier.py`

**Interfaces:**
- Consumes: `FederatedIdentity` (Task 3).
- Produces:
  - `select_identifier(identity: FederatedIdentity, primary: str, fallback: Sequence[str] = ()) -> str | None`
  - Wählt den ersten nicht-leeren Wert aus `[primary, *fallback]`; jeder Name ist ein `FederatedIdentity`-Feldname (z. B. `"subject_id"`, `"pairwise_id"`, `"eppn"`, `"name_id"`). Bei Listenfeldern zählt der erste Wert.
- Re-Exports in `fastapi_auth.saml`: `FederatedIdentity`, `map_attributes`, `select_identifier`.

- [ ] **Step 1: Failing test schreiben**

`tests/identity/test_identifier.py`:

```python
"""Tests for stable identifier selection."""

from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.model import FederatedIdentity


def test_primary_wins_when_present():
    ident = FederatedIdentity(subject_id="sub@lmu.de", eppn="u@lmu.de")
    assert select_identifier(ident, "subject_id", ["pairwise_id", "eppn"]) == "sub@lmu.de"


def test_falls_back_when_primary_missing():
    ident = FederatedIdentity(eppn="u@lmu.de")
    assert select_identifier(ident, "subject_id", ["pairwise_id", "eppn"]) == "u@lmu.de"


def test_returns_none_when_nothing_matches():
    ident = FederatedIdentity()
    assert select_identifier(ident, "subject_id", ["eppn"]) is None


def test_list_field_uses_first_value():
    ident = FederatedIdentity(mail=["first@lmu.de", "second@lmu.de"])
    assert select_identifier(ident, "mail") == "first@lmu.de"


def test_public_api_reexports():
    from fastapi_auth import saml

    assert hasattr(saml, "FederatedIdentity")
    assert hasattr(saml, "map_attributes")
    assert hasattr(saml, "select_identifier")
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/identity/test_identifier.py -v`
Expected: FAIL (`ModuleNotFoundError` bzw. fehlende Re-Exports).

- [ ] **Step 3: `select_identifier` implementieren**

`src/fastapi_auth/saml/identity/identifier.py`:

```python
"""Select the stable identifier for a service provider.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi_auth.saml.identity.model import FederatedIdentity


def select_identifier(
    identity: FederatedIdentity,
    primary: str,
    fallback: Sequence[str] = (),
) -> str | None:
    """Return the first non-empty identifier field value in preference order.

    Each name is a FederatedIdentity field (e.g. ``"subject_id"``, ``"eppn"``,
    ``"name_id"``). For list-valued fields the first element is used.
    """
    for name in (primary, *fallback):
        value = getattr(identity, name, None)
        if isinstance(value, list):
            value = value[0] if value else None
        if value:
            return str(value)
    return None
```

- [ ] **Step 4: Public API re-exportieren**

Ersetze den Inhalt von `src/fastapi_auth/saml/__init__.py` durch:

```python
"""Federated SAML2 Service Provider for FastAPI.

Public entry point of the ``fastapi_auth.saml`` package.
Import via ``from fastapi_auth import saml``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.saml.identity.identifier import select_identifier
from fastapi_auth.saml.identity.mapper import map_attributes
from fastapi_auth.saml.identity.model import FederatedIdentity

__all__ = [
    "FederatedIdentity",
    "__version__",
    "map_attributes",
    "select_identifier",
]

__version__ = "0.1.0.dev0"
```

- [ ] **Step 5: Test grün laufen lassen**

Run: `uv run pytest tests/identity/test_identifier.py -v`
Expected: alle passed.

- [ ] **Step 6: Ganze Suite + Lint grün**

Run:

```bash
uv run pytest
uv run ruff format .
uv run ruff check .
uv run ty check src tests
```

Expected: pytest alle passed; ruff „All checks passed!"; `ty` ohne Fehler (bei ty-pre-release-Rauschen: dokumentieren, nicht überpatchen).

- [ ] **Step 7: Commit**

```bash
git add src/fastapi_auth/saml/identity/identifier.py src/fastapi_auth/saml/__init__.py tests/identity/test_identifier.py
git commit -m "feat(identity): Identifier-Auswahl + Public-API-Re-Exports"
```

---

## Self-Review

**Spec-Abdeckung (Plan 1 vs. Spec §5 / §5.1 / §1 Familie):**
- Namespace-Packaging (`fastapi_auth`, PEP 420, kein `__init__.py`) → Task 1 ✅
- Dual-Lizenz `Apache-2.0 OR EUPL-1.2` → Task 1 (pyproject + LICENSE-Dateien) ✅
- Attribut-Registry eduPerson/SCHAC/Subject-Identifier mit OID+friendly+MACE → Task 2 ✅
- `FederatedIdentity` typisiert + Escape-Hatch → Task 3 ✅
- Mapper AttributeStatement→Identity (single/multi, friendly-Keys) → Task 4 ✅
- Expliziter Identifier mit Fallback (Spec §5.1) → Task 5 ✅ (die *Konfigurations*-Anbindung `identifier`/`identifier_fallback` folgt in Plan 2/3 an den Settings)
- Tooling ruff/ty/pytest/Make → Task 1 ✅

**Bewusst NICHT in Plan 1 (Folgepläne):** pysaml2-Engine, Metadaten/Trust, Discovery, Session/Store, SP-Metadaten-Endpoint, RequestedAttributes/Enforcement, Docker/CI/Doku. Diese hängen an Netzwerk/XML und gehören in Meilenstein 2–5.

**Platzhalter-Scan:** keine TBD/TODO; jeder Code-Schritt enthält vollständigen Code und exakte Kommandos mit erwarteter Ausgabe.

**Typ-Konsistenz:** `AttributeDef.field`-Werte (Task 2) = `FederatedIdentity`-Feldnamen (Task 3) = Mapper-Zuweisungen (Task 4) = Identifier-Feldnamen (Task 5). Geprüft: `eppn`, `subject_id`, `pairwise_id`, `scoped_affiliation`, `mail`, `home_organization` etc. stimmen überein.

---

## Nächste Meilensteine (eigene Pläne)

- **Plan 2 — SSO-Kern:** `settings.py` (SP-Keys, `source='direct'`, `passthrough`), `engine/` (pysaml2-Wrapper, `anyio.to_thread`), `router.py` (`/login`, `/acs`), `session/cookie.py` + `store.py` (memory) → durchgängiger Login gegen einen einzelnen IdP; Integration folgt in Plan 5.
- **Plan 3 — SP-Profil & Sessions:** RequestedAttributes/`isRequired` + ACS-Enforcement, `/saml/metadata`, JWT-Backend, Redis/Postgres-Store.
- **Plan 4 — Föderation & Discovery:** MDQ + Aggregat, externer DS + embedded WAYF, best-effort SLO.
- **Plan 5 — Docker/CI/Doku:** SimpleSAMLphp-Compose (`make test-integration`), GitHub Actions + tox-Matrix, Sphinx/MyST-Doku, How-tos für `lmuidp-container` und DFN-AAI-Testföderation.
