# Plan 3 — SP-Profil & Security-Härtung (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Den SP GDPR-konform und produktionssicher machen: explizites SP-Profil
(angeforderte Attribute mandatory/optional in den SP-Metadaten, Entity Categories,
mdui/Privacy), Attribut-Release-Enforcement am ACS, expliziter Identifier, plus die
in Plan 2 bewusst verschobenen Security-Härtungen (Host-Allowlist für Redirects,
per-reqid Outstanding + TTL, pysaml2-Fehler → 400/401) und **verschlüsselte
Assertions** (Decryption).

**Architecture:** Erweitert `SamlSettings` um das SP-Profil und die Security-Felder;
`engine/config.py` emittiert `required_attributes`/`optional_attributes` (→
`RequestedAttribute isRequired`), `entity_category`, `ui_info` (mdui) und
`encryption_keypairs`. Ein neuer `engine/enforcement`-Baustein prüft am ACS die
Pflicht-Attribute. Der Router bekommt Fehler-Mapping und eine echte
Redirect-Allowlist. Alles baut additiv auf Plan 1 (identity) + Plan 2 (engine,
session, sp, router) auf.

**Tech Stack:** wie Plan 2 (pysaml2 7.5.4 + xmlsec1, FastAPI, Pydantic v2, anyio,
pytest). Alle pysaml2-Config-Keys sind im Spike verifiziert.

## Global Constraints

- Baut additiv auf Plan 1 + Plan 2; deren öffentliche API/Verhalten NICHT brechen.
- Namespace `fastapi_auth` bleibt PEP-420-implizit (kein `src/fastapi_auth/__init__.py`).
- Krypto ausschließlich pysaml2/xmlsec1. **Decryption** via `encryption_keypairs` (im Spike bestätigt).
- Milestone-Scope: SP-Profil, Enforcement, Security-Härtung, Decryption. **NICHT** hier:
  JWT-Backend, Redis/Postgres-Store (Plan 4), MDQ/Aggregat/DS/WAYF/SLO (Plan 5), Docker/CI (Plan 6).
- pysaml2-Config-Platzierung (verifiziert): `required_attributes`/`optional_attributes`/`ui_info`
  unter `service.sp`; `entity_category` top-level; `encryption_keypairs` top-level.
- async-first (blockierende pysaml2-Calls in `anyio.to_thread.run_sync`).
- English code/docstrings; SPDX header `SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2` in neuen Quelldateien.
- ruff `E,F,W,B,UP,I,D,S` (Tests ignorieren `S101`/`D`); `ty` 0 Diagnosen; `make lint` exit 0; `# ty: ignore[<code>]` nur gezielt mit Begründung.
- Commit auf `main` (user-autorisiert), Conventional Commits **Deutsch**, kein `git push`.
- TDD: erst Test (rot), dann Implementierung (grün), dann Commit. `make lint` grün + volle Suite grün vor jedem Commit.
- Attribut-friendly-Namen exakt wie in der Plan-1-Registry (`eduPersonPrincipalName`, `mail`, `displayName`, `eduPersonScopedAffiliation`, `schacHomeOrganization`, …).

## File Structure

```text
src/fastapi_auth/saml/
  settings.py                 # + SP-Profil- & Security-Felder (erweitern)
  engine/
    config.py                 # + required/optional attrs, entity_category, ui_info, encryption_keypairs (erweitern)
    entity_categories.py      # NEU: shorthand -> pysaml2-Kategorie-Konstante
    enforcement.py            # NEU: check_required_attributes(identity, required) -> None | raises AttributeReleaseError
    errors.py                 # NEU: AttributeReleaseError, SamlResponseError
    client.py                 # parse_response: pysaml2-Fehler -> SamlResponseError; identifier-Auswahl (erweitern)
  router.py                   # ACS: enforcement + Fehler->400/403; Redirect-Allowlist (erweitern)
  redirect.py                 # NEU: is_safe_redirect(value, allowed_hosts) -> str
  sp.py                       # + sp.identifier(identity); Enforcement verdrahten (erweitern)
tests/
  test_settings.py            # + Profil-/Security-Felder (erweitern)
  engine/test_config_profile.py     # NEU: SP-Metadaten (RequestedAttribute isRequired, EntityAttributes, UIInfo, KeyDescriptor use=encryption)
  engine/test_decryption.py         # NEU: verschlüsselte Assertion -> FederatedIdentity
  engine/test_enforcement.py        # NEU: mandatory fehlt -> AttributeReleaseError
  engine/test_entity_categories.py  # NEU: shorthand-Mapping
  test_redirect.py                  # NEU: is_safe_redirect (local + allowlist)
  test_router_enforcement_flow.py   # NEU: ACS end-to-end: fehlendes Pflichtattribut -> 403; Erfolg -> 303
  test_router_error_handling.py     # NEU: kaputte/unsignierte Response am ACS -> 400
```

---

## Task 1: SP-Profil- & Security-Settings

**Files:**
- Modify: `src/fastapi_auth/saml/settings.py`
- Test: `tests/test_settings.py`

**Interfaces:**
- Consumes: bestehende `SamlSettings` (Plan 2).
- Produces: zusätzliche Felder auf `SamlSettings`:
  - Identifier: `identifier: str = "subject_id"`, `identifier_fallback: list[str] = ["pairwise_id", "eppn"]`
  - Attribute: `required_attributes: list[str] = []`, `optional_attributes: list[str] = []`
  - Metadaten-UI/GDPR: `entity_categories: list[str] = []`, `sp_display_name: str | None = None`, `sp_description: str | None = None`, `privacy_statement_url: str | None = None`
  - Security: `allowed_redirect_hosts: list[str] = []`
  - Decryption: `encryption_key_file: str | None = None`, `encryption_cert_file: str | None = None`
  - Properties: `enc_key_file -> str` (= `encryption_key_file or key_file`), `enc_cert_file -> str` (= `encryption_cert_file or cert_file`)

- [ ] **Step 1: Failing test schreiben**

Ergänze in `tests/test_settings.py`:

```python
def test_profile_defaults():
    s = SamlSettings(**_BASE)
    assert s.identifier == "subject_id"
    assert s.identifier_fallback == ["pairwise_id", "eppn"]
    assert s.required_attributes == []
    assert s.entity_categories == []
    assert s.allowed_redirect_hosts == []


def test_encryption_files_default_to_signing_pair():
    s = SamlSettings(**_BASE)
    assert s.enc_key_file == s.key_file
    assert s.enc_cert_file == s.cert_file


def test_encryption_files_override():
    s = SamlSettings(**{**_BASE, "encryption_key_file": "/tmp/enc.key", "encryption_cert_file": "/tmp/enc.crt"})
    assert s.enc_key_file == "/tmp/enc.key"
    assert s.enc_cert_file == "/tmp/enc.crt"


def test_profile_lists_from_values():
    s = SamlSettings(**{**_BASE, "required_attributes": ["eduPersonPrincipalName", "mail"], "entity_categories": ["code-of-conduct"]})
    assert s.required_attributes == ["eduPersonPrincipalName", "mail"]
    assert s.entity_categories == ["code-of-conduct"]
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_settings.py -v -k "profile or encryption"`
Expected: FAIL (`AttributeError`/`ValidationError` — neue Felder fehlen).

- [ ] **Step 3: Settings erweitern**

Füge in `src/fastapi_auth/saml/settings.py` die Felder in der Klasse `SamlSettings` hinzu (nach den bestehenden Gruppen, vor `acs_url`):

```python
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

    # --- decryption (defaults to the signing key/cert pair) ---
    encryption_key_file: str | None = None
    encryption_cert_file: str | None = None
```

und ergänze zwei Properties (neben `acs_url`):

```python
    @property
    def enc_key_file(self) -> str:
        """Private key used to decrypt EncryptedAssertions (defaults to signing key)."""
        return self.encryption_key_file or self.key_file

    @property
    def enc_cert_file(self) -> str:
        """Certificate advertised for assertion encryption (defaults to signing cert)."""
        return self.encryption_cert_file or self.cert_file
```

- [ ] **Step 4: Test grün + lint**

Run: `uv run pytest tests/test_settings.py -v && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: passed; clean; ty 0.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/settings.py tests/test_settings.py
git commit -m "feat(settings): SP-Profil (Identifier, Requested Attributes, Entity Categories, Privacy) + Security-Felder"
```

---

## Task 2: Entity-Category-Mapping

**Files:**
- Create: `src/fastapi_auth/saml/engine/entity_categories.py`
- Test: `tests/engine/test_entity_categories.py`

**Interfaces:**
- Produces: `resolve_entity_categories(shorthands: list[str]) -> list[str]` — mappt Kurznamen auf pysaml2-Kategorie-URIs; unbekannte Werte werden unverändert durchgereicht (erlaubt direkte URIs). Bekannte Kurznamen:
  - `"code-of-conduct"` → `saml2.entity_category.edugain.COC`
  - `"research-and-scholarship"` / `"refeds-rs"` → `saml2.entity_category.refeds.RESEARCH_AND_SCHOLARSHIP`

> Hinweis: `COC` und `RESEARCH_AND_SCHOLARSHIP` sind Listen/Strings von URIs; `resolve_entity_categories`
> gibt eine flache Liste von Kategorie-URIs zurück, wie sie pysaml2 unter `entity_category` erwartet.
> Prüfe im Zweifel den Typ (`from saml2.entity_category.edugain import COC; print(COC)`) und flache
> Listen entsprechend ab.

- [ ] **Step 1: Failing test schreiben**

`tests/engine/test_entity_categories.py`:

```python
"""Tests for entity-category shorthand resolution."""

from fastapi_auth.saml.engine.entity_categories import resolve_entity_categories


def test_known_shorthands_resolve_to_uris():
    result = resolve_entity_categories(["code-of-conduct", "research-and-scholarship"])
    assert all(isinstance(x, str) and x.startswith("http") for x in result)
    assert len(result) >= 2


def test_unknown_value_passed_through():
    assert "https://custom/category" in resolve_entity_categories(["https://custom/category"])


def test_empty():
    assert resolve_entity_categories([]) == []
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/engine/test_entity_categories.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/saml/engine/entity_categories.py`:

```python
"""Resolve entity-category shorthands to their canonical URIs.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from saml2.entity_category.edugain import COC
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP


def _flatten(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_flatten(item))
        return out
    return [str(value)]


_SHORTHANDS: dict[str, list[str]] = {
    "code-of-conduct": _flatten(COC),
    "research-and-scholarship": _flatten(RESEARCH_AND_SCHOLARSHIP),
    "refeds-rs": _flatten(RESEARCH_AND_SCHOLARSHIP),
}


def resolve_entity_categories(shorthands: list[str]) -> list[str]:
    """Map known shorthands to category URIs; pass unknown values through."""
    result: list[str] = []
    for name in shorthands:
        result.extend(_SHORTHANDS.get(name, [name]))
    return result
```

- [ ] **Step 4: Test grün + lint**

Run: `uv run pytest tests/engine/test_entity_categories.py -v && uv run ruff check . && uv run ty check src tests`
Expected: passed; clean; ty 0 (falls die pysaml2-Kategorie-Imports ty stören: gezielt `# ty: ignore` mit Begründung).

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/engine/entity_categories.py tests/engine/test_entity_categories.py
git commit -m "feat(engine): Entity-Category-Kurznamen-Mapping"
```

---

## Task 3: SP-Metadaten mit Profil + Decryption-Keypair

**Files:**
- Modify: `src/fastapi_auth/saml/engine/config.py`
- Test: `tests/engine/test_config_profile.py`, `tests/engine/test_decryption.py`

**Interfaces:**
- Consumes: `SamlSettings` (Task 1), `resolve_entity_categories` (Task 2).
- Produces: `build_sp_config` erweitert das `service.sp`-Dict um `required_attributes`, `optional_attributes`, `ui_info` (nur gesetzte Keys) und das Top-Level um `entity_category` und `encryption_keypairs` (immer die enc-Paar-Property). Verhalten unverändert, wenn die Profil-Felder leer sind.

- [ ] **Step 1: Failing tests schreiben**

`tests/engine/test_config_profile.py`:

```python
"""SP metadata reflects the requested-attributes / entity-category / mdui profile."""

from saml2.config import SPConfig
from saml2.metadata import create_metadata_string

from tests.conftest import IDP_EID
from fastapi_auth.saml.engine.config import build_sp_config
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
        required_attributes=["eduPersonPrincipalName", "mail"],
        optional_attributes=["displayName"],
        entity_categories=["code-of-conduct", "research-and-scholarship"],
        sp_display_name="Test SP",
        privacy_statement_url="https://sp.example/privacy",
    )


def _sp_metadata(certs, idp_metadata_file) -> str:
    cfg = SPConfig().load(build_sp_config(_settings(certs, idp_metadata_file)))
    return create_metadata_string(None, config=cfg, sign=False).decode()


def test_metadata_has_required_attribute_is_required_true(certs, idp_metadata_file):
    md = _sp_metadata(certs, idp_metadata_file)
    assert 'isRequired="true"' in md
    assert "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" in md  # eduPersonPrincipalName


def test_metadata_has_optional_attribute_is_required_false(certs, idp_metadata_file):
    md = _sp_metadata(certs, idp_metadata_file)
    assert 'isRequired="false"' in md


def test_metadata_has_entity_attributes(certs, idp_metadata_file):
    assert "EntityAttributes" in _sp_metadata(certs, idp_metadata_file)


def test_metadata_has_uiinfo_privacy(certs, idp_metadata_file):
    assert "privacy" in _sp_metadata(certs, idp_metadata_file).lower()


def test_metadata_has_encryption_key_descriptor(certs, idp_metadata_file):
    assert 'use="encryption"' in _sp_metadata(certs, idp_metadata_file)
```

`tests/engine/test_decryption.py`:

```python
"""An encrypted assertion is decrypted and mapped to FederatedIdentity."""

from tests.conftest import IDP_EID, mint_response

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


async def test_encrypted_assertion_is_decrypted(certs, idp_metadata_file, make_idp):
    settings = _settings(certs, idp_metadata_file)
    engine = SamlEngine(settings)
    reqid, _ = await engine.create_authn_request(relay_state="/app")
    idp = make_idp(engine.sp_metadata())
    saml_response = mint_response(
        idp, reqid,
        ava={"eduPersonPrincipalName": ["u@test.de"], "mail": ["u@test.de"]},
        encrypt_cert=open(certs["sp_crt"]).read(),
    )
    identity = await engine.parse_response(saml_response, outstanding={reqid: "/app"})
    assert identity.eppn == "u@test.de"
```

> `mint_response` bekommt in Step 2 einen optionalen `encrypt_cert`-Parameter (siehe unten).

- [ ] **Step 2: `mint_response` um Encryption erweitern**

In `tests/conftest.py`, erweitere `mint_response` um einen optionalen `encrypt_cert: str | None = None` Parameter; wenn gesetzt, `create_authn_response(..., encrypt_assertion=True, encrypt_cert_assertion=encrypt_cert)`. Bestehende Aufrufe bleiben unverändert (Default `None` = unverschlüsselt). Signatur-Flags (`sign_response`/`sign_assertion` aus Plan-2-Fix) bleiben erhalten.

- [ ] **Step 3: Tests rot laufen lassen**

Run: `uv run pytest tests/engine/test_config_profile.py tests/engine/test_decryption.py -v`
Expected: FAIL (Metadaten enthalten noch keine RequestedAttribute/EntityAttributes/UIInfo/encryption; Decryption schlägt fehl, weil `encryption_keypairs` fehlt).

- [ ] **Step 4: `build_sp_config` erweitern**

In `src/fastapi_auth/saml/engine/config.py`: importiere `resolve_entity_categories`, und erweitere das zurückgegebene Dict. Der `service.sp`-Block bekommt bedingt Profil-Keys, das Top-Level bekommt `entity_category` und `encryption_keypairs`:

```python
def build_sp_config(settings: SamlSettings) -> dict[str, Any]:
    """Assemble the pysaml2 SPConfig dict for this service provider."""
    idp_metadata = load_idp_metadata(settings)

    sp: dict[str, Any] = {
        "endpoints": {
            "assertion_consumer_service": [(settings.acs_url, BINDING_HTTP_POST)],
        },
        "allow_unsolicited": False,
        "authn_requests_signed": settings.authn_requests_signed,
        "want_assertions_signed": settings.want_assertions_signed,
        "want_response_signed": False,
    }
    if settings.required_attributes:
        sp["required_attributes"] = settings.required_attributes
    if settings.optional_attributes:
        sp["optional_attributes"] = settings.optional_attributes

    ui_info: dict[str, str] = {}
    if settings.sp_display_name:
        ui_info["display_name"] = settings.sp_display_name
    if settings.sp_description:
        ui_info["description"] = settings.sp_description
    if settings.privacy_statement_url:
        ui_info["privacy_statement_url"] = settings.privacy_statement_url
    if ui_info:
        sp["ui_info"] = ui_info

    config: dict[str, Any] = {
        "entityid": settings.entity_id,
        "xmlsec_binary": settings.xmlsec_binary,
        "allow_unknown_attributes": True,
        "service": {"sp": sp},
        "key_file": settings.key_file,
        "cert_file": settings.cert_file,
        "encryption_keypairs": [{"key_file": settings.enc_key_file, "cert_file": settings.enc_cert_file}],
        "metadata": {"inline": [idp_metadata]},
    }
    if settings.entity_categories:
        config["entity_category"] = resolve_entity_categories(settings.entity_categories)
    return config
```

- [ ] **Step 5: Tests grün + volle Suite + lint**

Run: `uv run pytest tests/engine/ -v && uv run pytest && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: neue + bestehende Tests grün; ruff clean; ty 0. (Der Plan-2-`test_build_sp_config_loads_in_pysaml2` und der Roundtrip müssen weiterhin grün sein — `encryption_keypairs` zeigt aufs SP-Paar.)

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/saml/engine/config.py tests/engine/test_config_profile.py tests/engine/test_decryption.py tests/conftest.py
git commit -m "feat(engine): SP-Metadaten-Profil (RequestedAttributes/EntityCategories/mdui) + Assertion-Decryption"
```

---

## Task 4: Attribut-Release-Enforcement

**Files:**
- Create: `src/fastapi_auth/saml/engine/errors.py`, `src/fastapi_auth/saml/engine/enforcement.py`
- Test: `tests/engine/test_enforcement.py`

**Interfaces:**
- Produces:
  - `errors.py`: `class AttributeReleaseError(Exception)` mit `missing: list[str]`; `class SamlResponseError(Exception)`.
  - `enforcement.py`: `check_required_attributes(identity: FederatedIdentity, required: list[str]) -> None` — mappt jeden geforderten friendly-Namen über die Registry auf sein Feld und prüft, ob es in `identity` gesetzt/nicht-leer ist; fehlt eines, `raise AttributeReleaseError(missing=[...])`. Unbekannte friendly-Namen (nicht in Registry) werden gegen `identity.attributes` geprüft.

- [ ] **Step 1: Failing test schreiben**

`tests/engine/test_enforcement.py`:

```python
"""Tests for mandatory-attribute enforcement."""

import pytest

from fastapi_auth.saml.engine.enforcement import check_required_attributes
from fastapi_auth.saml.engine.errors import AttributeReleaseError
from fastapi_auth.saml.identity.model import FederatedIdentity


def test_passes_when_all_required_present():
    ident = FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"])
    check_required_attributes(ident, ["eduPersonPrincipalName", "mail"])  # no raise


def test_raises_with_missing_list():
    ident = FederatedIdentity(eppn="u@lmu.de")  # no mail
    with pytest.raises(AttributeReleaseError) as exc:
        check_required_attributes(ident, ["eduPersonPrincipalName", "mail"])
    assert "mail" in exc.value.missing


def test_empty_required_always_passes():
    check_required_attributes(FederatedIdentity(), [])  # no raise


def test_empty_list_value_counts_as_missing():
    ident = FederatedIdentity(eppn="u@lmu.de", mail=[])
    with pytest.raises(AttributeReleaseError):
        check_required_attributes(ident, ["mail"])
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/engine/test_enforcement.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/saml/engine/errors.py`:

```python
"""SAML engine error types.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations


class SamlResponseError(Exception):
    """A SAML response could not be parsed or failed validation."""


class AttributeReleaseError(Exception):
    """The IdP did not release all attributes this SP marks as mandatory."""

    def __init__(self, missing: list[str]) -> None:
        self.missing = missing
        super().__init__(f"Missing required attributes: {', '.join(missing)}")
```

`src/fastapi_auth/saml/engine/enforcement.py`:

```python
"""Enforce that mandatory attributes were released (GDPR data-minimisation).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.saml.engine.errors import AttributeReleaseError
from fastapi_auth.saml.identity import registry
from fastapi_auth.saml.identity.model import FederatedIdentity


def _is_present(identity: FederatedIdentity, friendly: str) -> bool:
    definition = registry.resolve(friendly)
    if definition is not None:
        value = getattr(identity, definition.field, None)
        return bool(value)
    return bool(identity.attributes.get(friendly))


def check_required_attributes(identity: FederatedIdentity, required: list[str]) -> None:
    """Raise AttributeReleaseError if any required friendly-named attribute is absent."""
    missing = [name for name in required if not _is_present(identity, name)]
    if missing:
        raise AttributeReleaseError(missing=missing)
```

- [ ] **Step 4: Test grün + lint**

Run: `uv run pytest tests/engine/test_enforcement.py -v && uv run ruff check . && uv run ty check src tests`
Expected: passed; clean; ty 0.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/engine/errors.py src/fastapi_auth/saml/engine/enforcement.py tests/engine/test_enforcement.py
git commit -m "feat(engine): Attribut-Release-Enforcement (mandatory fehlt -> AttributeReleaseError)"
```

---

## Task 5: Redirect-Allowlist

**Files:**
- Create: `src/fastapi_auth/saml/redirect.py`
- Modify: `src/fastapi_auth/saml/router.py` (nutzt `is_safe_redirect` statt `_safe_local_path`)
- Test: `tests/test_redirect.py`

**Interfaces:**
- Produces: `is_safe_redirect(value: str, allowed_hosts: list[str]) -> str` — gibt `value` zurück, wenn es (a) ein sicherer lokaler Pfad ist (`startswith("/")` und nicht `//` und nicht `/\`) ODER (b) eine absolute URL, deren Host in `allowed_hosts` steht; sonst `"/"`.
- `router.py`: `/login` und `/acs` nutzen `is_safe_redirect(value, sp.settings.allowed_redirect_hosts)`; das bisherige `_safe_local_path` wird durch diese Funktion ersetzt (Verhalten für lokale Pfade bleibt identisch).

- [ ] **Step 1: Failing test schreiben**

`tests/test_redirect.py`:

```python
"""Tests for safe-redirect resolution (local paths + host allowlist)."""

import pytest

from fastapi_auth.saml.redirect import is_safe_redirect


@pytest.mark.parametrize("value", ["/", "/app", "/a/b?x=1"])
def test_local_paths_allowed(value):
    assert is_safe_redirect(value, []) == value


@pytest.mark.parametrize("value", ["//evil.com", "/\\evil.com", "https://evil.com", "\\\\evil.com", "http://x"])
def test_unsafe_normalized_to_root(value):
    assert is_safe_redirect(value, []) == "/"


def test_absolute_url_allowed_when_host_in_allowlist():
    assert is_safe_redirect("https://app.lmu.de/dashboard", ["app.lmu.de"]) == "https://app.lmu.de/dashboard"


def test_absolute_url_rejected_when_host_not_in_allowlist():
    assert is_safe_redirect("https://evil.com/x", ["app.lmu.de"]) == "/"
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_redirect.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/saml/redirect.py`:

```python
"""Resolve a post-login redirect target safely (open-redirect protection).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from urllib.parse import urlparse


def is_safe_redirect(value: str, allowed_hosts: list[str]) -> str:
    """Return value if it is a safe local path or an allow-listed absolute URL, else '/'.

    Local paths must be single-slash-prefixed and must not start with '//' or '/\\'
    (both resolve to a cross-origin URL in browsers).
    """
    if value.startswith("/") and not value.startswith(("//", "/\\")):
        return value
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.hostname in allowed_hosts:
        return value
    return "/"
```

`router.py`: entferne `_safe_local_path` und ersetze beide Aufrufe durch
`is_safe_redirect(next, sp.settings.allowed_redirect_hosts)` bzw.
`is_safe_redirect(RelayState or "/", sp.settings.allowed_redirect_hosts)` (Import ergänzen).

- [ ] **Step 4: Tests grün + volle Suite + lint**

Run: `uv run pytest tests/test_redirect.py tests/test_router_login_flow.py -v && uv run pytest && uv run ruff format . && uv run ruff check . && uv run ty check src tests`
Expected: neue + bestehende Redirect-/Flow-Tests grün (die Plan-2-Open-Redirect-Tests müssen weiterhin grün sein); ty 0.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/saml/redirect.py src/fastapi_auth/saml/router.py tests/test_redirect.py
git commit -m "feat(saml): Redirect-Allowlist (lokale Pfade + erlaubte Hosts) ersetzt lokalen Guard"
```

---

## Task 6: ACS-Enforcement, Fehler-Mapping, per-reqid Outstanding + TTL

**Files:**
- Modify: `src/fastapi_auth/saml/engine/client.py` (pysaml2-Fehler → `SamlResponseError`; `parse_response` gibt zusätzlich `in_response_to` zurück)
- Modify: `src/fastapi_auth/saml/session/store.py` (Outstanding mit Zeitstempel + TTL-Bereinigung)
- Modify: `src/fastapi_auth/saml/sp.py` (Enforcement verdrahten; `sp.identifier(identity)`)
- Modify: `src/fastapi_auth/saml/router.py` (ACS: per-reqid pop, Enforcement, Fehler→400/403)
- Test: `tests/test_router_enforcement_flow.py`, `tests/test_router_error_handling.py`

**Interfaces:**
- `client.py`: `parse_response(...)` fängt pysaml2-Exceptions und wirft `SamlResponseError`; gibt `tuple[FederatedIdentity, str]` zurück (Identity + `in_response_to` der Assertion, für per-reqid-Cleanup). `to_identity` unverändert.
- `store.py`: `add_outstanding(request_id, return_url)` speichert `(return_url, created_at)`; neue Methode `purge_expired(ttl_seconds: int, now: float) -> None`. `outstanding()` gibt weiterhin `{request_id: return_url}` (ohne Zeitstempel).
- `sp.py`: `def identifier(self, identity) -> str | None` = `select_identifier(identity, settings.identifier, settings.identifier_fallback)`; ACS-Enforcement über `check_required_attributes(identity, settings.required_attributes)`.
- `router.py`: `/acs`: `try: identity, in_response_to = await engine.parse_response(...)` → `except SamlResponseError: HTTPException(400)`; dann `check_required_attributes(...)` → `except AttributeReleaseError as e: HTTPException(403, detail=...)`; `store.pop_outstanding(in_response_to)`; Redirect.

> Zeit: `store.purge_expired` bekommt `now` als Parameter (kein `time.time()` im Store, damit testbar). Der Router ruft `purge_expired(ttl, time.monotonic())` vor `outstanding()`.

- [ ] **Step 1: Failing tests schreiben**

`tests/test_router_enforcement_flow.py`:

```python
"""ACS enforces mandatory attributes end-to-end."""

from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import IDP_EID, mint_response
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _app(certs, idp_metadata_file, required):
    settings = SamlSettings(
        entity_id="urn:test:sp", base_url="https://sp.example",
        key_file=certs["sp_key"], cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file, fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t", cookie_secure=False, required_attributes=required,
    )
    sp = SamlSP(settings)
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")
    return app, sp


def _login_and_get_reqid(client, sp):
    client.get("/saml/login", params={"next": "/app"}, follow_redirects=False)
    return next(iter(sp.store._outstanding))  # noqa: SLF001


def test_acs_403_when_mandatory_missing(certs, idp_metadata_file, make_idp):
    app, sp = _app(certs, idp_metadata_file, ["eduPersonPrincipalName", "mail"])
    client = TestClient(app)
    reqid = _login_and_get_reqid(client, sp)
    idp = make_idp(sp.engine.sp_metadata())
    resp = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"]})  # no mail
    r = client.post("/saml/acs", data={"SAMLResponse": resp, "RelayState": "/app"}, follow_redirects=False)
    assert r.status_code == 403
    assert "mail" in r.text


def test_acs_success_when_all_present(certs, idp_metadata_file, make_idp):
    app, sp = _app(certs, idp_metadata_file, ["eduPersonPrincipalName", "mail"])
    client = TestClient(app)
    reqid = _login_and_get_reqid(client, sp)
    idp = make_idp(sp.engine.sp_metadata())
    resp = mint_response(idp, reqid, ava={"eduPersonPrincipalName": ["u@test.de"], "mail": ["u@test.de"]})
    r = client.post("/saml/acs", data={"SAMLResponse": resp, "RelayState": "/app"}, follow_redirects=False)
    assert r.status_code == 303
```

`tests/test_router_error_handling.py`:

```python
"""A malformed/invalid SAML response yields HTTP 400, not 500."""

import base64

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import IDP_EID
from fastapi_auth.saml.settings import SamlSettings
from fastapi_auth.saml.sp import SamlSP


def _app(certs, idp_metadata_file):
    settings = SamlSettings(
        entity_id="urn:test:sp", base_url="https://sp.example",
        key_file=certs["sp_key"], cert_file=certs["sp_crt"],
        idp_metadata_file=idp_metadata_file, fixed_idp_entity_id=IDP_EID,
        session_secret="s3cr3t", cookie_secure=False,
    )
    sp = SamlSP(settings)
    app = FastAPI()
    app.include_router(sp.router, prefix="/saml")
    return app


def test_acs_garbage_response_is_400(certs, idp_metadata_file):
    app = _app(certs, idp_metadata_file)
    client = TestClient(app)
    garbage = base64.b64encode(b"<not-a-saml-response/>").decode()
    r = client.post("/saml/acs", data={"SAMLResponse": garbage, "RelayState": "/app"}, follow_redirects=False)
    assert r.status_code == 400
```

- [ ] **Step 2: Tests rot laufen lassen**

Run: `uv run pytest tests/test_router_enforcement_flow.py tests/test_router_error_handling.py -v`
Expected: FAIL (Enforcement/Fehler-Mapping/parse_response-Signatur noch nicht vorhanden).

- [ ] **Step 3: `client.py` — Fehler-Mapping + in_response_to**

In `src/fastapi_auth/saml/engine/client.py`:
- Importiere `from fastapi_auth.saml.engine.errors import SamlResponseError`.
- Ändere `parse_response` Rückgabetyp auf `tuple[FederatedIdentity, str]` und `_parse` entsprechend:

```python
    async def parse_response(self, saml_response: str, outstanding: dict[str, str]) -> tuple[FederatedIdentity, str]:
        """Validate a base64 SAML response; return (identity, in_response_to)."""
        return await anyio.to_thread.run_sync(self._parse, saml_response, outstanding)

    def _parse(self, saml_response: str, outstanding: dict[str, str]) -> tuple[FederatedIdentity, str]:
        try:
            resp = self._client.parse_authn_request_response(
                saml_response, BINDING_HTTP_POST, outstanding=outstanding
            )
        except Exception as err:  # pysaml2 raises many types on bad/forged input
            raise SamlResponseError(str(err)) from err
        if resp is None:
            raise SamlResponseError("SAML response could not be parsed")
        in_response_to = resp.in_response_to or ""  # ty: ignore[unresolved-attribute]  # pysaml2 untyped
        return to_identity(resp), in_response_to
```

> Prüfe das genaue Attribut für `InResponseTo` an der pysaml2-AuthnResponse (`resp.in_response_to`); falls
> abweichend, korrekt anpassen und den Roundtrip-Test damit grün halten.

- [ ] **Step 4: `store.py` — TTL**

Erweitere `MemoryStore`:

```python
    async def add_outstanding(self, request_id: str, return_url: str) -> None:
        self._outstanding[request_id] = (return_url, _MISSING)  # replaced below

    async def purge_expired(self, ttl_seconds: int, now: float) -> None:
        expired = [rid for rid, (_, created) in self._outstanding.items() if now - created > ttl_seconds]
        for rid in expired:
            self._outstanding.pop(rid, None)
```

Speichere Outstanding als `dict[str, tuple[str, float]]`; `add_outstanding(request_id, return_url, now)` bekommt `now: float` als dritten Parameter (Router übergibt `time.monotonic()`); `outstanding()` gibt `{rid: url for rid,(url,_) in ...}`; `pop_outstanding(rid)` gibt `url` (aus dem Tuple) oder `None`. Passe die Signaturen konsistent an und aktualisiere `tests/session/test_store.py` (Zeit als Parameter). Kein `time`-Import im Store.

- [ ] **Step 5: `sp.py` + `router.py` — Enforcement, Identifier, per-reqid, Fehler-Mapping**

`sp.py`: ergänze
```python
    def identifier(self, identity: FederatedIdentity) -> str | None:
        """Return this SP's chosen stable identifier for the identity."""
        return select_identifier(identity, self.settings.identifier, self.settings.identifier_fallback)
```
(Import `select_identifier`).

`router.py` `/acs` (neu):
```python
    @router.post("/acs")
    async def acs(
        SAMLResponse: Annotated[str, Form()],
        RelayState: Annotated[str, Form()] = "/",
    ) -> RedirectResponse:
        await sp.store.purge_expired(sp.settings.session_ttl, time.monotonic())
        outstanding = await sp.store.outstanding()
        try:
            identity, in_response_to = await sp.engine.parse_response(SAMLResponse, outstanding)
        except SamlResponseError as err:
            raise HTTPException(status_code=400, detail="Invalid SAML response") from err
        try:
            check_required_attributes(identity, sp.settings.required_attributes)
        except AttributeReleaseError as err:
            raise HTTPException(status_code=403, detail=str(err)) from err
        await sp.store.pop_outstanding(in_response_to)
        target = is_safe_redirect(RelayState or "/", sp.settings.allowed_redirect_hosts)
        response = RedirectResponse(target, status_code=303)
        await sp.backend.establish(identity, response)
        return response
```
(Imports: `time`, `HTTPException`, `SamlResponseError`, `AttributeReleaseError`, `check_required_attributes`, `is_safe_redirect`. `/login` ruft `add_outstanding(request_id, next, time.monotonic())` und nutzt `is_safe_redirect` für `next`.)

- [ ] **Step 6: Tests grün + volle Suite + lint**

Run: `uv run pytest && uv run ruff format . && uv run ruff check . && uv run ty check src tests && make lint`
Expected: alle Tests grün (inkl. Plan-1/2-Suiten unverändert); ruff clean; ty 0; `make lint` exit 0. Der Plan-2-Login-Flow-Test nutzt `parse_response`s neuen Tuple-Return nur indirekt über den Router — falls ein Test `parse_response` direkt aufruft (Task-3-Roundtrip), passe dessen Entpacken auf das Tuple an.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(saml): ACS-Enforcement + Fehler->400/403 + per-reqid Outstanding-TTL + Identifier-Auswahl"
```

---

## Self-Review

**Spec-Abdeckung (Plan 3 vs. Spec §5.1 / §7):**
- Expliziter Identifier pro SP + Fallback → Task 1 (Settings) + Task 6 (`sp.identifier`) ✅
- RequestedAttributes mit `isRequired` in SP-Metadaten → Task 1 + Task 3 (verifiziert im Spike) ✅
- Entity Categories / mdui / Privacy-URL → Task 1 + Task 2 + Task 3 ✅
- Attribut-Release-Enforcement am ACS (mandatory fehlt → Ablehnung) → Task 4 + Task 6 (403) ✅
- EncryptedAssertion-Decryption → Task 3 (`encryption_keypairs`, Spike-verifiziert) ✅
- Open-Redirect-Schutz mit Host-Allowlist (Plan-2-Deferral) → Task 5 ✅
- per-reqid Outstanding + TTL (Plan-2-Deferral) → Task 6 ✅
- pysaml2-Fehler → 400/401 statt 500 (Plan-2-Deferral) → Task 6 ✅

**Bewusst NICHT in Plan 3 (spätere Pläne):** JWT-Backend, Redis/Postgres-Store (Plan 4);
MDQ/Aggregat, externer DS/embedded WAYF, SLO (Plan 5); Docker/CI/Doku (Plan 6);
`to_identity`-None-Branch-Unit-Tests + `outstanding()`-Copy-Test (Härtung, optional in Plan 4).

**Platzhalter-Scan:** kein TBD/TODO; jeder Code-Schritt vollständig. Zwei „prüfe das genaue
Attribut"-Hinweise (`resp.in_response_to`, Kategorie-Listen-Form) sind bewusste
Verifikations-Schritte, keine Lücken.

**Typ-Konsistenz:** `parse_response -> tuple[FederatedIdentity, str]` (Task 6) konsistent in
`sp.py`/`router.py`/Task-3-Roundtrip-Test angepasst; `check_required_attributes(identity, list[str])`,
`is_safe_redirect(str, list[str]) -> str`, `resolve_entity_categories(list[str]) -> list[str]`,
`AttributeReleaseError.missing: list[str]` — durchgängig.

**Bekannte Risiken:**
- `resp.in_response_to` Attribut-Name an pysaml2-AuthnResponse verifizieren (Task 6 Step 3 flaggt das).
- Änderung von `parse_response`-Signatur (Tuple) berührt den Plan-2-Roundtrip-Test → im selben Task grün halten.
- `entity_category`-Konstanten sind ggf. Listen von URIs → `resolve_entity_categories` flacht ab (Task 2).

---

## Nächste Meilensteine (eigene Pläne)

- **Plan 4 — Session-Backends & Scale-out:** JWT-Backend (opt-in), Redis- + Postgres-Store
  (SQLModel async), Session-Backend-Auswahl via Settings; `to_identity`-Härtungstests.
- **Plan 5 — Föderation & Discovery:** MDQ + Aggregat, externer DS + embedded WAYF, best-effort SLO.
- **Plan 6 — Docker/CI/Doku:** SimpleSAMLphp-Compose (`make test-integration`), GitHub Actions
  + tox, Sphinx-Doku, How-tos für `lmuidp-container` und DFN-AAI-Testföderation.
