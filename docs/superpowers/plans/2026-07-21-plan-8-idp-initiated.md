# Plan 8 — IdP-initiated Flow (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Optional **IdP-initiated (unsolicited) Login** unterstützen: der IdP/ein Portal POSTet
eine unaufgeforderte, signierte AuthnResponse an den ACS (kein vorheriger AuthnRequest, **kein
InResponseTo**). Standardmäßig **aus** (sicherer Default); wenn an, ersetzt ein
**Assertion-Replay-Cache** die fehlende Outstanding-/InResponseTo-Absicherung.

**Architecture:** Additiv auf Plan 1–7. Ein Setting `allow_idp_initiated` schaltet
`allow_unsolicited` in der pysaml2-SP-Config. Der `Store` bekommt einen atomaren
**Replay-Cache** (`seen_assertion(id, ttl)`), umgesetzt pro Backend (Memory/Redis/Postgres).
Der ACS-Router unterscheidet solicited (InResponseTo vorhanden → bisheriger Pfad, Outstanding-Pop)
von unsolicited (kein InResponseTo → nur wenn erlaubt, Replay-Check, konfigurierbares Ziel).
Default (`allow_idp_initiated=False`) reproduziert Plan-1–7-Verhalten (unsolicited wird von
pysaml2 abgelehnt → 400).

**Tech Stack:** wie Plan 7. Kernannahme im Spike verifiziert: `allow_unsolicited=False` lehnt
unsolicited ab (`UnsolicitedResponse`), `allow_unsolicited=True` akzeptiert; eine echte
unsolicited Response **lässt InResponseTo weg** (`create_authn_response(in_response_to=None)`);
`resp.in_response_to is None` und `resp.assertion.id` sind verfügbar.

## Global Constraints

- Additiv/rückwärtskompatibel: Default `allow_idp_initiated=False` reproduziert Plan-1–7-Verhalten (168+2 Tests bleiben grün); unsolicited wird ohne das Flag von pysaml2 abgelehnt.
- **Sicherheit:** IdP-initiated ist ohne InResponseTo/Outstanding anfällig für Replay → bei `allow_idp_initiated=True` MUSS jede unsolicited Assertion gegen den Replay-Cache geprüft werden (verbrauchte Assertion-ID → Ablehnung). RelayState kommt vom IdP → immer durch `is_safe_redirect` (kein Open-Redirect).
- Namespace `fastapi_auth` bleibt PEP-420-implizit; async-first; `filterwarnings=["error"]` → keine offenen Verbindungen.
- Krypto/Signaturprüfung unverändert über pysaml2/xmlsec1 (unsolicited-Assertions werden identisch signaturgeprüft).
- English code/docstrings; SPDX in neuen Quelldateien; ruff `E,F,W,B,UP,I,D,S`; `ty` 0; `make lint` exit 0; `# ty: ignore[<code>]` nur gezielt mit Begründung.
- Commit auf `main` (user-autorisiert), Conventional Commits **Deutsch**, kein `git push`, Autor **Loechel**.
- TDD: erst Test (rot), dann Implementierung (grün), dann Commit. Vor jedem Commit `make lint` + volle Suite grün, Lint-Ausgabe im Report belegen. Volle Suite nach jedem Task selbst prüfen.

## File Structure

```text
src/fastapi_auth/saml/settings.py       # + allow_idp_initiated / idp_initiated_default_relay_state / assertion_replay_ttl (Task 1)
src/fastapi_auth/saml/engine/config.py  # allow_unsolicited = settings.allow_idp_initiated (Task 2)
src/fastapi_auth/saml/session/store.py       # Store-Protocol + MemoryStore: seen_assertion (Task 3)
src/fastapi_auth/saml/session/redis_store.py # seen_assertion (SET NX EX) (Task 3)
src/fastapi_auth/saml/session/postgres_store.py # seen_assertion (INSERT + IntegrityError) (Task 3)
src/fastapi_auth/saml/router.py         # ACS: solicited vs unsolicited + Replay-Check (Task 4)
tests/conftest.py                       # mint_response: in_response_to-Param (Task 2)
docs/howto/idp-initiated.md             # How-to + Security-Hinweise (Task 5)
tests/…                                 # je Task
```

---

## Task 1: Settings (allow_idp_initiated + Ziel + Replay-TTL)

**Files:** Modify `settings.py`; Test `tests/test_settings.py`.

**Interfaces:** neue Felder:
- `allow_idp_initiated: bool = False`
- `idp_initiated_default_relay_state: str = "/"` (Landing-Ziel, wenn der IdP kein RelayState schickt)
- `assertion_replay_ttl: int = 300` (Sekunden; Replay-Cache-Fenster ~ Assertion-Gültigkeit)

- [ ] **Step 1: Failing test** (in `tests/test_settings.py`): Defaults (`allow_idp_initiated is False`, `idp_initiated_default_relay_state == "/"`, `assertion_replay_ttl == 300`) + Setzen der Werte.
- [ ] **Step 2–5:** Rot → Felder ergänzen (nach dem Security-Block) → Grün + volle Suite + lint (belegen) → Commit `feat(settings): allow_idp_initiated + Replay-TTL + IdP-initiated-Default-RelayState`.

---

## Task 2: SP-Config `allow_unsolicited` + Test-Minting

**Files:** Modify `engine/config.py`, `tests/conftest.py`; Test `tests/engine/test_config.py` (ergänzen).

**Interfaces:**
- `engine/config.py` `build_sp_config`: das feste `"allow_unsolicited": False` durch `"allow_unsolicited": settings.allow_idp_initiated` ersetzen.
- `tests/conftest.py` `mint_response(...)`: optionalen Parameter `in_response_to: str | None = None`-Steuerung ergänzen — aktuell nutzt es `request_id` als `in_response_to`. Neue Signatur: behalte `request_id` als Default-`in_response_to`, aber erlaube `in_response_to=None` explizit für unsolicited (dann `create_authn_response(in_response_to=None, ...)` → InResponseTo wird weggelassen). **Wichtig (Spike):** NICHT `in_response_to=""` verwenden (bricht die XSD-Validierung); für unsolicited `None`.

- [ ] **Step 1: Failing test** (`tests/engine/test_config.py` ergänzen): mit `allow_idp_initiated=True` enthält `build_sp_config(...)["service"]["sp"]["allow_unsolicited"]` `True`; Default `False`.
- [ ] **Step 2–5:** Rot → `allow_unsolicited` ableiten + `mint_response`-Param → Grün + volle Suite (bestehende Roundtrip-/Config-Tests bleiben grün) + lint (belegen) → Commit `feat(engine): allow_unsolicited aus Settings + mint_response(in_response_to)`.

---

## Task 3: Assertion-Replay-Cache im Store

**Files:** Modify `session/store.py`, `session/redis_store.py`, `session/postgres_store.py`; Test `tests/session/test_replay_cache.py`.

**Interfaces:** `Store` Protocol: `async def seen_assertion(self, assertion_id: str, ttl: int) -> bool` — **atomarer check-and-set**: gibt `True` zurück, wenn die Assertion-ID INNERHALB des TTL-Fensters schon gesehen wurde (Replay), sonst `False` (neu — und markiert sie).
- `MemoryStore`: dict `{assertion_id: expires_at}` mit injizierter Clock; wenn vorhanden & nicht abgelaufen → `True`; sonst setzen (`clock()+ttl`) und `False`.
- `RedisStore`: `was_set = await self._r.set(f"{prefix}{id}", "1", nx=True, ex=ttl)`; `return not was_set` (SET NX gibt truthy bei neu-gesetzt → nicht Replay; None wenn Key existiert → Replay). Prefix z. B. `fa:seen:`.
- `PostgresStore`: Tabelle `SamlSeenAssertion(assertion_id PK, expires_at)`; zuerst abgelaufene Zeilen löschen (`delete where expires_at < now`), dann `INSERT`; bei `IntegrityError` (Duplicate PK) → `True` (Replay), sonst commit + `False`. (Der PK-Insert ist der atomare Check.) `create_all` legt die neue Tabelle mit an.

- [ ] **Step 1: Failing test** `tests/session/test_replay_cache.py` (Memory + fakeredis + aiosqlite): erster `seen_assertion("a1", 300)` → `False` (neu); zweiter `seen_assertion("a1", 300)` → `True` (Replay); eine andere ID → `False`. Memory zusätzlich: nach Ablauf (Clock vorstellen) ist dieselbe ID wieder `False`.
- [ ] **Step 2–5:** Rot → drei Implementierungen + Protocol → Grün + volle Suite (bestehende Store-Tests bleiben grün) + lint (belegen; SQLAlchemy-`ty:ignore`-Muster wie in Plan 7 nur wo nötig) → Commit `feat(session): Assertion-Replay-Cache (seen_assertion) fuer Memory/Redis/Postgres`.

---

## Task 4: ACS — solicited vs. unsolicited + Replay-Check

**Files:** Modify `router.py`; Test `tests/test_idp_initiated_flow.py`.

**Interfaces:** `POST /acs` (erweitern; `parse_response` gibt weiterhin `(identity, in_response_to)`):
- `try: identity, in_response_to = await sp.engine.parse_response(SAMLResponse, outstanding)` → `except SamlResponseError: 400` (fängt auch pysaml2s `UnsolicitedResponse`, wenn `allow_idp_initiated=False` → unsolicited wird 400).
- **solicited** (`in_response_to` truthy): bisheriger Pfad — `pop_outstanding(in_response_to)`, `target = is_safe_redirect(RelayState or "/", allowed_hosts)`.
- **unsolicited** (`in_response_to` leer/`""`): 
  - **Replay-Check:** `if not identity.assertion_id or await sp.store.seen_assertion(identity.assertion_id, sp.settings.assertion_replay_ttl): raise HTTPException(400, "Replay or missing assertion id")` (logge warnend; keine Secrets).
  - `target = is_safe_redirect(RelayState or sp.settings.idp_initiated_default_relay_state, allowed_hosts)`.
- Danach für BEIDE Pfade gleich: `check_required_attributes(...)` (Enforcement, 403), `RedirectResponse(target, 303)`, `backend.establish(...)`, Audit-Logging wie bisher.

> Hinweis: Die solicited-Ersetzung der Outstanding-Map bleibt der Replay-Schutz für solicited (ein
> verbrauchter reqid ist weg → pysaml2 lehnt einen Replay ab). `seen_assertion` gilt nur für unsolicited.

- [ ] **Step 1: Failing e2e test** `tests/test_idp_initiated_flow.py` (FastAPI TestClient + In-Memory-IdP):
  - `allow_idp_initiated=True`: POST einer unsolicited Response (via `mint_response(idp, ???, ava, in_response_to=None)` — kein reqid) an `/acs` → 303, Session gesetzt, Redirect zu `idp_initiated_default_relay_state` (bzw. zu einem mitgegebenen sicheren `RelayState`); `GET /me` liefert die Identity.
  - **Replay:** dieselbe unsolicited Response ein zweites Mal an `/acs` → 400 (Replay-Cache).
  - **Default off:** mit `allow_idp_initiated=False` → unsolicited Response an `/acs` → 400 (pysaml2 `UnsolicitedResponse` → SamlResponseError).
  - **solicited unverändert:** der bestehende SP-initiated Flow (mit reqid/Outstanding) bleibt grün.
- [ ] **Step 2–5:** Rot → Router-Zweig + Replay-Check → Grün + volle Suite (Plan-1–7-Flows bleiben grün) + `make lint` (belegen) → Commit `feat(saml): IdP-initiated ACS (unsolicited) mit Assertion-Replay-Schutz`.

---

## Task 5: Doku / How-to

**Files:** Create `docs/howto/idp-initiated.md`; Modify `docs/index.md` (Toctree) und ggf. `docs/howto/stores.md`.

**Interfaces:** eine MyST-How-to (Englisch) mit Backtick-Admonitions:
- Was IdP-initiated ist und wann man es braucht (Portal-/IdP-gestarteter Login).
- **Security-Warnung** (```` ```{warning} ````): default **off**; nur aktivieren, wenn nötig; RelayState vom IdP wird als Ziel behandelt → nur lokale Pfade / `allowed_redirect_hosts`; der Replay-Cache (`assertion_replay_ttl`) verhindert erneute Nutzung einer Assertion — bei Multi-Worker einen geteilten Store (Redis/Postgres) verwenden, sonst greift der Cache pro Prozess.
- Konfiguration: `allow_idp_initiated=True`, `idp_initiated_default_relay_state`, `assertion_replay_ttl`, geteilter Store.
- In den Toctree von `docs/index.md` aufnehmen.

- [ ] **Step 1:** Datei + Toctree.
- [ ] **Step 2: Verifizieren** — `uv run sphinx-build -W -b html docs docs/_build` grün (0 Warnungen; Backtick-Admonitions, kein colon-fence); `make lint` + volle Suite grün. Belegen.
- [ ] **Step 3: Commit** — `docs: How-to IdP-initiated Flow (+ Security-Hinweise)`.

---

## Self-Review

**Abdeckung:**
- Setting + sicherer Default (off) → Task 1 ✅
- `allow_unsolicited` aus Settings → Task 2 (Spike: default-off lehnt unsolicited ab) ✅
- Assertion-Replay-Cache (Memory/Redis/Postgres) → Task 3 ✅
- ACS solicited/unsolicited-Unterscheidung + Replay-Check + RelayState-Guard → Task 4 (Spike-verifiziert: `in_response_to is None`) ✅
- Doku + Security-Hinweise → Task 5 ✅

**Sicherheits-Fokus:** unsolicited nur bei explizitem Opt-in; jede unsolicited Assertion einmal-verwendbar
(Replay-Cache); RelayState immer durch `is_safe_redirect`; Signatur-/Conditions-/Audience-Prüfung
unverändert durch pysaml2. Multi-Worker braucht geteilten Store (dokumentiert).

**Bekannte Risiken:**
- `mint_response` muss `in_response_to=None` (nicht `""`) für unsolicited nutzen (Spike-Fund).
- Postgres `seen_assertion` via IntegrityError — auf aiosqlite verifizieren (Duplicate-PK → IntegrityError); `create_all` legt die neue Tabelle mit an.
- Der Replay-Cache-TTL sollte ≥ der Assertion-Gültigkeit (NotOnOrAfter) sein, sonst könnte eine noch gültige Assertion nach Cache-Ablauf erneut akzeptiert werden — Default 300s; dokumentieren.

**Danach:** verbleibende optionale Erweiterungen (Metadaten-Auto-Refresh, generisches Identity-Modell,
mehrere SP-EntityIDs) als weitere Pläne möglich.
```
