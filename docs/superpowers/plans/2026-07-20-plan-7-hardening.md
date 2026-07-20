# Plan 7 — Härtungen (Hardening) (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Die in Plan 4–6 bewusst verschobenen Härtungen umsetzen: **öffentliches
`aclose()`** auf allen Stores (Cleanup/lifespan), **`sp.mount()`-Helfer** gegen
`mount_path`↔prefix-Divergenz, **atomares `pop_outstanding`** (Redis `GETDEL` / PG
`DELETE…RETURNING`), **asymmetrisches JWT (RS256/EdDSA)** + **JWT-Claims-Allowlist**
(PII/Größe), plus **Doku-/Infra-Hygiene**.

**Architecture:** Additiv auf Plan 1–6; keine öffentliche API brechen. Store-Protocol
bekommt `aclose()`; JWTBackend lernt asymmetrische Keys (Datei-basiert) neben dem
HS*-Secret; `pop_outstanding` wird pro Backend atomar. Defaults unverändert
(HS256, Cookie/Memory, keine Allowlist) → Plan-1–6-Suite bleibt grün.

**Tech Stack:** wie Plan 6; PyJWT RS256/EdDSA (mit `cryptography`, bereits Dep) + Redis
`GETDEL` + SQLAlchemy `RETURNING` — alle im Spike verifiziert (RS256+EdDSA-Roundtrip mit
Alg-Pinning; fakeredis `getdel`).

## Global Constraints

- Additiv/rückwärtskompatibel: Defaults (HS256, Cookie, Memory, keine Claims-Allowlist) reproduzieren Plan-1–6-Verhalten → 150+2 Tests bleiben grün.
- Namespace `fastapi_auth` bleibt PEP-420-implizit (kein `src/fastapi_auth/__init__.py`).
- async-first; keine blockierenden Calls im Event-Loop; `filterwarnings=["error"]` → keine offenen Verbindungen/ResourceWarnings.
- Krypto ausschließlich über etablierte Libs (PyJWT/`cryptography`, pysaml2/xmlsec1).
- **JWT-Alg-Pinning:** `jwt.decode(..., algorithms=[jwt_alg])` (nur der konfigurierte Alg) — verhindert Alg-Confusion (im Spike bestätigt: HS-gegen-RS wirft `InvalidAlgorithmError`).
- English code/docstrings; SPDX in neuen Quelldateien.
- ruff `E,F,W,B,UP,I,D,S`; `ty` 0; `make lint` exit 0; `# ty: ignore[<code>]` nur gezielt mit Begründung.
- Commit auf `main` (user-autorisiert), Conventional Commits **Deutsch**, kein `git push`, Autor **Loechel**.
- TDD: erst Test (rot), dann Implementierung (grün), dann Commit. Vor jedem Commit `make lint` + volle Suite grün, Lint-Ausgabe im Report belegen.

## File Structure

```text
src/fastapi_auth/saml/session/
  store.py            # Store-Protocol + MemoryStore: aclose() (Task 1); atomares pop (Task 3)
  redis_store.py      # aclose() + getdel-pop (Task 1/3)
  postgres_store.py   # aclose() + DELETE..RETURNING-pop (Task 1/3)
  jwt.py              # asymmetrische Keys + Claims-Allowlist (Task 4/5)
src/fastapi_auth/saml/
  sp.py               # aclose() + mount(app) (Task 1/2)
  settings.py         # jwt_private/public_key_file + jwt_attributes + Validatoren (Task 4/5)
Dockerfile            # uv-Tag pinnen (Task 6)
.github/workflows/ci.yml  # docs-Job (Task 6)
docs/howto/{lmuidp,stores}.md  # interne Markierung / MD060 (Task 6)
tests/…               # je Task
```

---

## Task 1: Öffentliches `aclose()` auf allen Stores + `SamlSP.aclose()`

**Files:** Modify `session/store.py`, `session/redis_store.py`, `session/postgres_store.py`, `sp.py`, `tests/integration/test_stores_integration.py`; Test `tests/session/test_store_close.py`.

**Interfaces:**
- `Store` Protocol: `async def aclose(self) -> None`.
- `MemoryStore.aclose()` → no-op. `RedisStore.aclose()` → `await self._r.aclose()`. `PostgresStore.aclose()` → `await self._engine.dispose()`.
- `SamlSP.aclose()` → `await self.store.aclose()` (für FastAPI-`lifespan`).
- Integrationstest: private `store._r.aclose()`/`store._engine.dispose()` durch das öffentliche `store.aclose()` ersetzen (SLF001-`noqa` entfernen).

- [ ] **Step 1: Failing test** `tests/session/test_store_close.py`: `MemoryStore().aclose()` läuft ohne Fehler; `RedisStore(fakeredis.aioredis.FakeRedis()).aclose()` schließt (danach kein ResourceWarning); PostgresStore gegen aiosqlite `aclose()` disposed die Engine. (Async-Tests.)
- [ ] **Step 2: Rot** → `uv run pytest tests/session/test_store_close.py -v` FAIL.
- [ ] **Step 3: Implementieren** — `aclose()` in Protocol + drei Stores + `SamlSP.aclose()`; Integrationstest auf `store.aclose()` umstellen.
- [ ] **Step 4: Grün + volle Suite + lint** (belegen; `make test-integration` optional — falls Ports frei).
- [ ] **Step 5: Commit** — `feat(session): oeffentliches aclose() auf Stores + SamlSP.aclose() (lifespan-Cleanup)`.

---

## Task 2: `SamlSP.mount(app)`-Helfer (mount_path-Konsistenz)

**Files:** Modify `sp.py`; Test `tests/test_sp_mount.py`.

**Interfaces:**
- `SamlSP.mount(self, app, **kwargs) -> None` → `app.include_router(self.router, prefix=self.settings.mount_path, **kwargs)`. Damit können `mount_path` und der tatsächliche Prefix nicht mehr divergieren.
- Doku/Docstring: `sp.mount(app)` ist der empfohlene Weg; `app.include_router(sp.router, prefix=...)` bleibt möglich, muss dann aber `mount_path` matchen.

- [ ] **Step 1: Failing test** `tests/test_sp_mount.py`: `SamlSP.mount(app)` mountet den Router unter `settings.mount_path` (z. B. `mount_path="/auth/saml"`) → `GET /auth/saml/metadata` liefert 200 (SP-Metadaten); und mit Default `/saml` bleibt `GET /saml/metadata` 200. (FastAPI TestClient.)
- [ ] **Step 2–5:** Rot → `mount()` implementieren → Grün + lint → Commit `feat(saml): SamlSP.mount(app) haelt mount_path und Router-Prefix konsistent`.

---

## Task 3: Atomares `pop_outstanding` (Redis GETDEL / PG DELETE..RETURNING)

**Files:** Modify `session/redis_store.py`, `session/postgres_store.py`; Test `tests/session/test_atomic_pop.py`.

**Interfaces:**
- `RedisStore.pop_outstanding` → `val = await self._r.getdel(key)` (atomar get+delete; Redis 6.2+; fakeredis-verifiziert); Rückgabe dekodiert oder `None`.
- `PostgresStore.pop_outstanding` → ein `DELETE FROM saml_outstanding WHERE request_id=:rid RETURNING return_url, expires_at` (via SQLAlchemy `delete(...).where(...).returning(...)`), in einer Transaktion; Rückgabe `return_url` wenn nicht abgelaufen, sonst `None`.

> **Verifikation (Task-lokal):** SQLite (aiosqlite) unterstützt `RETURNING` ab SQLite 3.35 — prüfen, dass der Test-SQLite es kann; falls nicht, atomar via `select ... with_for_update()`-freien Weg in EINER Session-Transaktion (select→delete→commit) umsetzen (bei SQLite reicht die Session-Transaktion für Atomizität im Test). Der Redis-`getdel`-Weg ist im Spike bestätigt.

- [ ] **Step 1: Failing test** `tests/session/test_atomic_pop.py`: Redis (fakeredis) + Postgres (aiosqlite): nach `add_outstanding("r","/x")` liefert `pop_outstanding("r")=="/x"` und der Key/Zeile ist danach weg (ein `pop` gibt Wert, ein zweites `None`). (Der Test dokumentiert die Atomizitäts-Absicht; echte Concurrency nicht nötig.)
- [ ] **Step 2–5:** Rot → Redis `getdel` + PG `RETURNING` (bzw. Transaktions-Fallback) → Grün + volle Suite (bestehende Store-Tests bleiben grün) + lint → Commit `feat(session): atomares pop_outstanding (Redis GETDEL / Postgres DELETE RETURNING)`.

---

## Task 4: Asymmetrisches JWT (RS256/EdDSA)

**Files:** Modify `settings.py`, `session/jwt.py`; Test `tests/session/test_jwt_asymmetric.py`.

**Interfaces:**
- `settings.py`: neue Felder `jwt_private_key_file: str | None = None`, `jwt_public_key_file: str | None = None`. Helfer:
  - `def jwt_is_symmetric(self) -> bool` → `self.jwt_alg.startswith("HS")`.
  - `jwt_signing_key` (Property) → symmetrisch: `jwt_signing_secret`; sonst `Path(jwt_private_key_file).read_text()`.
  - `jwt_verifying_key` (Property) → symmetrisch: `jwt_signing_secret`; sonst `Path(jwt_public_key_file).read_text()`.
  - Validator (`_check_jwt_secret_strength` erweitern/ergänzen): wenn `backend=="jwt"` und **asymmetrisch** → `jwt_private_key_file` und `jwt_public_key_file` erforderlich; wenn **symmetrisch** → der bestehende ≥32-Byte-Check.
- `session/jwt.py`: `establish` signiert mit `settings.jwt_signing_key`; `load` verifiziert mit `settings.jwt_verifying_key`, `algorithms=[settings.jwt_alg]` (Alg-Pinning). Bei HS* unverändert.

**Verifiziert (Spike):** `jwt.encode(claims, rsa_priv_pem, algorithm="RS256")` / `EdDSA` mit PEM-Keys; `jwt.decode(tok, pub_pem, algorithms=["RS256"])`; Alg-Confusion (`algorithms=["HS256"]` gegen RS-Token) wirft `jwt.InvalidAlgorithmError` → durch das Pinning ausgeschlossen.

- [ ] **Step 1: Failing test** `tests/session/test_jwt_asymmetric.py`: Test-Fixture erzeugt RSA- und Ed25519-Keypaare (openssl oder `cryptography`); für `jwt_alg="RS256"` bzw. `"EdDSA"` (mit `jwt_private_key_file`/`jwt_public_key_file`): `JWTBackend.establish`→Cookie, `load`→dieselbe `FederatedIdentity` (eppn/mail intakt); manipuliertes/falsch-signiertes Token → `None`. Settings-Validator: asymmetrisch ohne Key-Files → `ValidationError`.
- [ ] **Step 2–5:** Rot → Settings-Felder/Properties/Validator + JWTBackend-Key-Auswahl → Grün (HS256-Bestandstests bleiben grün) + lint → Commit `feat(session): asymmetrisches JWT (RS256/EdDSA) mit Datei-Keys + Alg-Pinning`.

---

## Task 5: JWT-Claims-Allowlist (PII/Größe)

**Files:** Modify `settings.py`, `session/jwt.py`; Test `tests/session/test_jwt_claims_allowlist.py`.

**Interfaces:**
- `settings.py`: `jwt_attributes: list[str] | None = None`. Wenn gesetzt, trägt das JWT nur diese `FederatedIdentity`-Felder in `attrs` (Data-Minimisation, kleinere Cookies); wenn `None`, das bisherige Verhalten (voller `model_dump`).
- `session/jwt.py` `establish`: `dump = identity.model_dump(mode="json")`; wenn `settings.jwt_attributes` gesetzt → `attrs = {k: dump[k] for k in settings.jwt_attributes if k in dump}`; sonst `attrs = dump`. `load` rekonstruiert weiterhin via `FederatedIdentity.model_validate(payload["attrs"])` (fehlende Felder = Defaults).

- [ ] **Step 1: Failing test** `tests/session/test_jwt_claims_allowlist.py`: mit `jwt_attributes=["eppn"]` enthält das dekodierte Token nur `eppn` (kein `mail`), `load` liefert `FederatedIdentity(eppn=...)` mit leerem `mail`; ohne Allowlist bleibt alles erhalten.
- [ ] **Step 2–5:** Rot → Feld + Filter in `establish` → Grün + lint → Commit `feat(session): JWT-Claims-Allowlist (jwt_attributes) fuer Data-Minimisation`.

---

## Task 6: Doku- & Infra-Hygiene

**Files:** Modify `Dockerfile`, `.github/workflows/ci.yml`, `docs/howto/lmuidp.md`, `docs/howto/stores.md`, `docs/index.md` (bzw. Migrationsnotiz).

**Interfaces (kleine, verifizierbare Änderungen):**
- `Dockerfile`: `ghcr.io/astral-sh/uv:latest` auf eine gepinnte Version (z. B. `ghcr.io/astral-sh/uv:0.9`) — reproduzierbarer Build. `docker build` muss weiterhin grün sein.
- `.github/workflows/ci.yml`: neuer Job `docs` (`uv pip install --system -e ".[docs]"` → `sphinx-build -W -b html docs docs/_build`), damit Doku-Regressionen (`-W`) in CI auffallen.
- `docs/howto/lmuidp.md`: klare **„LMU-internal only"**-Admonition oben (interner GitLab-Link + Test-Credentials sind nicht-öffentlich).
- `docs/index.md` (oder ein kurzer Migrations-Abschnitt): Notiz, dass `SAML_ACS_PATH` durch `SAML_MOUNT_PATH` ersetzt wurde (acs leitet sich jetzt aus `mount_path` ab; altes Env wird still ignoriert).
- `docs/howto/stores.md`: die MD060-Tabellen-Ausrichtung korrigieren (oder als bekannt markieren).

- [ ] **Step 1:** Änderungen umsetzen.
- [ ] **Step 2: Verifizieren** — `docker build -t fa-saml:test .` grün (uv-Pin); `uv run sphinx-build -W -b html docs docs/_build` grün; `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` valide; `make lint` + `uv run pytest -q` grün. Belegen.
- [ ] **Step 3: Commit** — `chore: Doku-/Infra-Haertung (uv-Tag pinnen, CI-docs-Job, lmuidp intern markiert, Migrationsnotiz)`.

---

## Self-Review

**Abdeckung (offene Deferrals aus Plan 4–6):**
- Store-`aclose()` (Plan-6-Review) → Task 1 ✅
- `mount_path`↔prefix-Guard (Plan-6-Review) → Task 2 ✅
- Atomares `pop_outstanding` (Plan-4-Review) → Task 3 (Redis GETDEL spike-verifiziert) ✅
- RS256/EdDSA-JWT (Plan-4/6) → Task 4 (Spike-verifiziert, Alg-Pinning) ✅
- JWT-Claims-Allowlist (Plan-4/6) → Task 5 ✅
- Doku-/Infra-Hygiene (Plan-6-Review) → Task 6 ✅

**Bekannte Risiken:**
- SQLite-`RETURNING`-Unterstützung im Test (Task 3) — Fallback-Weg im Task genannt.
- JWT-Validator berührt den bestehenden `_check_jwt_secret_strength` (Plan 4) → im selben Task grün halten; HS256-Default-Pfad unverändert.
- `jwt_verifying_key`/`jwt_signing_key` lesen Dateien beim Zugriff — nur konstruktions-/lifespan-nah nutzen (nicht pro Request neu lesen: JWTBackend kann die Keys im `__init__` cachen).

**Danach:** Roadmap-Kern + Härtungen vollständig; verbleibend nur optionale Erweiterungen
(IdP-initiated Flow, generisches Consumer-Identity-Modell, Metadaten-Auto-Refresh-Scheduler,
mehrere SP-EntityIDs) — kein Muss für ein v0.1.0-Release.
```
