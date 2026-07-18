# Design-Spec: `fastapi-auth-saml-federated`

- **Datum:** 2026-07-18
- **Status:** Entwurf (zur Umsetzung freigegeben)
- **Distribution (PyPI):** `fastapi-auth-saml-federated`
- **Import:** `from fastapi_auth import saml`
- **Lizenz:** `Apache-2.0 OR EUPL-1.2` (Dual, Empfänger wählt)

## 1. Ziel & Kontext

Ein wiederverwendbares, öffentliches PyPI-Package, das FastAPI-Services das Login
via **Federated SAML2** ermöglicht — so wie es im Shibboleth-/eduGAIN-Ökosystem
und den NREN-AAIs (DFN-AAI, SWITCHaai, SURFconext, SUNET/SWAMID …) genutzt wird.

Das Package ist ein moderner, async-sauberer FastAPI-Layer über **`pysaml2`**
(IdentityPython). Es implementiert einen **SAML2 Service Provider (SP)** — keinen
IdP. Attribute werden als **eduPerson-/SCHAC-** und moderne **SAML-Subject-Identifier**
verstanden und auf ein typisiertes Pydantic-Modell abgebildet.

### Nicht-Ziele

- Kein IdP.
- Keine eigene SAML-Krypto (Signatur/Verschlüsselung bleibt bei `pysaml2`/`xmlsec1`).
- Kein Ersatz für die Attribut-Freigabe-Policy des IdP.

### Package-Familie (`fastapi_auth`-Namespace, PEP 420)

Bewusst als Familie angelegt (im Geist des Zope/Plone-Namespace-Packagings):

| Distribution (PyPI)              | Import                          | Rolle                     |
| -------------------------------- | ------------------------------- | ------------------------- |
| `fastapi-auth-saml-federated`    | `from fastapi_auth import saml` | Federated SAML2 (dieses)  |
| `fastapi-auth-openid-federated`  | `from fastapi_auth import openid` | OIDC Federation (später)  |
| `fastapi-auth-wallet-oid4vp`     | `from fastapi_auth import wallet` | Wallet / OID4VP (später)  |

Muster: `fastapi-auth-<protokoll>-<flavor>` als Distribution, kurzer Submodul-Name
im geteilten Namespace. **Wichtig:** `fastapi_auth/` erhält *kein* `__init__.py`
(impliziter Namespace-Package nach PEP 420), damit mehrere Distributionen denselben
Namespace teilen können.

> **Repo-Umbenennung:** Der Git-Ordner heißt aktuell `fastapi-auth-federated-saml`
> und wird im Implementierungs-Setup auf `fastapi-auth-saml-federated` umbenannt
> (Remote/Push bleibt beim Nutzer).

## 2. Grundarchitektur & Entscheidungen

| Achse             | Entscheidung                                                              |
| ----------------- | ------------------------------------------------------------------------ |
| SAML-Engine       | Wrapper um **`pysaml2`**, synchrone Calls via `anyio.to_thread.run_sync` |
| Session-Modell    | **Pluggable** `SessionBackend`: Cookie (Default) + JWT (Opt-in)          |
| Metadaten/Trust   | **Konfigurierbar**: MDQ (Default) *oder* Aggregat-Datei                   |
| Discovery         | **Extern (DS-Protocol, Default)** + Embedded-Picker + feste entityID     |
| Identitätsmodell  | **Typisiert** (`FederatedIdentity`) + `attributes`-Escape-Hatch          |
| Teststrategie     | **Gestuft**: Unit (respx) / Integration (compose) / E2E (DFN-AAI-Test)   |
| Zuschnitt         | Öffentliches PyPI-Package, semver, Sphinx-Doku, CI                       |

**Leitprinzipien:** klare Grenzen — der SAML-Kern kennt keinen Session-Typ, das
Session-Layer kein XML; Lesbarkeit vor Kompaktheit (PEP 20); async-first; keine
selbstgebaute Krypto.

### Package-Struktur

```text
fastapi_auth/                 # PEP 420 Namespace — KEIN __init__.py
  saml/
    __init__.py               # Public API: SamlSP, SamlSettings, FederatedIdentity, current_user
    settings.py               # pydantic-settings (Keys, Metadaten, Discovery, Session…)
    sp.py                     # SamlSP — Fassade/Orchestrator, hält AsyncClient & Engine
    router.py                 # APIRouter-Factory: /login /acs /metadata /slo /disco-return
    engine/                   # pysaml2-Integration (sync → threadpool)
      client.py               #   AuthnRequest bauen, Response validieren
      metadata.py             #   MDQ + Aggregat-Loader, Trust-Anchor-Signaturprüfung
      crypto.py               #   SP-Key/Cert, xmlsec-Konfig, Assertion-Decryption
    discovery/
      external.py             #   SAML DS-Protocol (Redirect + Return)
      embedded.py             #   Opt-in htmx/Jinja-Picker (mdui: Logos/DisplayNames)
    identity/
      model.py                #   FederatedIdentity (Pydantic v2)
      registry.py             #   OID ↔ friendly-URN ↔ Feld (eduPerson/SCHAC/subject-id)
      mapper.py               #   AttributeStatement → FederatedIdentity
    session/
      base.py                 #   SessionBackend (Protocol) + current_user-Dependency
      cookie.py               #   signiertes Cookie / server-side Session (Default)
      jwt.py                  #   JWT-Ausgabe (Opt-in)
      store.py                #   Session- + Replay-Cache-Store (memory | redis | postgres)
    templates/                #   embedded WAYF (nur wenn genutzt)
    py.typed
docs/                         # Sphinx + MyST (Diataxis)
tests/                        # unit + integration
compose.yml, Dockerfile
pyproject.toml
```

## 3. Request-Flows

```text
Login:  GET /saml/login?next=/app
          ├─(discovery=external)──► Redirect DS ──► GET /saml/disco-return?entityID=IdP
          ├─(discovery=embedded)──► eigener Picker (htmx) ──► entityID
          └─(discovery=passthrough)► feste entityID
        ► AuthnRequest (signiert, HTTP-Redirect-Binding) ► IdP SSO
        ► Outstanding-Request (InResponseTo/RelayState) im Store hinterlegt

ACS:    POST /saml/acs   (SAMLResponse, HTTP-POST-Binding)
        ► Signatur prüfen (IdP-Cert aus Metadaten)
        ► Conditions/AudienceRestriction · SubjectConfirmation Recipient=ACS
        ► InResponseTo gegen Outstanding-Request · Assertion-Replay-Cache
        ► EncryptedAssertion mit SP-Key entschlüsseln
        ► AttributeStatement ─mapper─► FederatedIdentity
        ► SessionBackend.establish() ► Set-Cookie / JWT ► Redirect next (Open-Redirect-Schutz)

Meta:   GET  /saml/metadata   → SP-Metadaten (EntityCategories, RequestedAttributes, Keys)
SLO:    GET/POST /saml/slo    → best-effort Single Logout + lokale Session-Invalidierung
```

## 4. Öffentliche API (Consumer-Oberfläche)

```python
from fastapi import Depends, FastAPI
from fastapi_auth import saml
from fastapi_auth.saml import SamlSettings, FederatedIdentity, current_user

app = FastAPI()
sp = saml.SamlSP(SamlSettings())          # Konfig aus ENV/.env (pydantic-settings)
app.include_router(sp.router, prefix="/saml")

@app.get("/me")
async def me(user: FederatedIdentity = Depends(current_user)):
    return {"eppn": user.eppn, "affiliation": user.scoped_affiliation}
```

Autorisierungs-Guard (scoped affiliation / entitlement):

```python
from fastapi_auth.saml import require

@app.get("/staff", dependencies=[Depends(require(affiliation="staff"))])
async def staff_only(): ...
```

## 5. Identität & Attribut-Mapping (`identity/`)

Eine kuratierte **Registry** kennt jedes Attribut unter beiden Schreibweisen
(OID `urn:oid:…` *und* friendly URN `urn:mace:…`) und mappt auf `FederatedIdentity`.

### Abgedeckte Attribute (v1)

- **Moderne Subject Identifiers (bevorzugt):** `subject-id`
  (`urn:oasis:names:tc:SAML:attribute:subject-id`), `pairwise-id`
  (`urn:oasis:names:tc:SAML:attribute:pairwise-id`) — ersetzen das deprecated
  `eduPersonTargetedID`.
- **eduPerson:** `eduPersonPrincipalName` (eppn, `urn:oid:1.3.6.1.4.1.5923.1.1.1.6`),
  `eduPersonScopedAffiliation` (`…1.1.1.9`), `eduPersonAffiliation` (`…1.1.1.1`),
  `eduPersonEntitlement` (`…1.1.1.7`), `eduPersonUniqueId` (`…1.1.1.13`),
  `eduPersonAssurance` (`…1.1.1.11`), `eduPersonOrcid` (`…1.1.1.16`),
  `eduPersonTargetedID` (deprecated, aus NameID).
- **SCHAC:** `schacHomeOrganization` (`urn:oid:1.3.6.1.4.1.25178.1.2.9`),
  `schacHomeOrganizationType` (`…1.2.10`), `schacPersonalUniqueCode` (`…1.2.14`),
  `schacPersonalUniqueID` (`…1.2.15`).
- **Core/LDAP:** `mail` (`urn:oid:0.9.2342.19200300.100.1.3`), `displayName`
  (`urn:oid:2.16.840.1.113730.3.1.241`), `givenName` (`urn:oid:2.5.4.42`),
  `sn` (`urn:oid:2.5.4.4`), `cn` (`urn:oid:2.5.4.3`), `o` (`urn:oid:2.5.4.10`),
  `preferredLanguage` (`urn:oid:2.16.840.1.113730.3.1.39`).

### `FederatedIdentity` (Pydantic v2)

- Typisierte Felder; mehrwertige SAML-Attribute als `list[str]`
  (`scoped_affiliation`, `mail`, `entitlement`, `assurance` …).
- Metadaten: `idp_entity_id`, `authn_instant`, `authn_context_class`,
  `name_id`, `name_id_format`, `assertion_id`.
- **Escape-Hatch:** `attributes: dict[str, list[str]]` mit allen rohen Attributen
  (friendly-name → Werte), plus optional roh-OID-Zugriff.
- **`identifier`-Property:** wählt nach konfigurierbarer Präferenz den stabilen
  Identifier: `subject-id → pairwise-id → eppn → persistent NameID`
  (wichtig für Privacy & Persistenz).

Für später (v1.1): generisches Consumer-Modell via Subclassing eines
`FederatedIdentityBase` — additiv, ohne den Standardfall zu belasten.

## 6. Session-Layer (`session/`)

`SessionBackend` (Protocol):

```python
class SessionBackend(Protocol):
    async def establish(self, identity: FederatedIdentity, response: Response) -> None: ...
    async def load(self, request: Request) -> FederatedIdentity | None: ...
    async def revoke(self, request: Request, response: Response) -> None: ...
```

Dependencies: `current_user` (401 wenn nicht eingeloggt), `optional_user`,
`require(affiliation=…, entitlement=…)`.

- **CookieBackend (Default):** server-side Session im Store, signierte Session-ID
  im Cookie (`HttpOnly`, `Secure`, `SameSite`). **Detail:** der
  Request-Korrelations-Cookie (`InResponseTo`/`RelayState`) muss den cross-site-POST
  des IdP an den ACS überleben → `SameSite=None; Secure`.
- **JWTBackend (Opt-in):** stateless JWT (EdDSA/RS256), Claims-Mapping aus
  `FederatedIdentity`, konfigurierbare Expiry.
- **Store:** `memory | redis | postgres` (PG async via SQLModel). Derselbe Store
  trägt auch **Outstanding-Request-Cache** und **Assertion-Replay-Cache**.

## 7. Sicherheit

`pysaml2`/`xmlsec1` übernehmen die kryptografische Schwerarbeit; wir konfigurieren
strikt und validieren die Rahmenbedingungen:

- Response-/Assertion-**Signatur** gegen IdP-Metadaten-Cert; unsignierte Assertions
  ablehnen (`WantAssertionsSigned`).
- **Conditions**: NotBefore/NotOnOrAfter, **AudienceRestriction = eigene entityID**;
  `SubjectConfirmation` Recipient = ACS-URL; konfigurierbarer Clock-Skew.
- **InResponseTo** gegen Outstanding-Request (CSRF/Replay) + Assertion-**Replay-Cache**
  (per Assertion-ID).
- **EncryptedAssertion**-Entschlüsselung mit SP-Key (DFN/eduGAIN verschlüsseln oft).
- **AuthnRequest signieren.**
- XML-Signature-Wrapping / XXE bewusst an `pysaml2`/`xmlsec` delegiert — kein
  Handrolling.
- **Open-Redirect-Schutz** für `next` (Same-Origin/Allowlist).
- **Metadaten-Trust**: Aggregat-/MDQ-Signatur gegen konfigurierten Trust-Anchor;
  `validUntil`/`cacheDuration` erzwingen (abgelaufene Metadaten ablehnen).
- **SP-Key-Rollover**: mehrere Certs in SP-Metadaten möglich.
- Keine Secrets loggen/committen; Keys aus Datei oder ENV.

## 8. Konfiguration (`settings.py`, pydantic-settings)

Skizze der Kernfelder (Details im Implementierungsplan):

```text
SP:        entity_id, base_url, acs_path, key_file, cert_file, extra_certs[]
Metadaten: source = 'mdq' | 'aggregate'
           mdq_url, aggregate_url, trust_anchor_cert, refresh_interval
Discovery: mode = 'external' | 'embedded' | 'passthrough'
           ds_url, fixed_idp_entity_id
Session:   backend = 'cookie' | 'jwt'
           store = 'memory' | 'redis' | 'postgres'
           cookie_name, cookie_secure, jwt_alg, jwt_ttl, session_ttl, redis_url, db_url
Attribute: requested_attributes[], entity_categories[] (R&S, CoCo, Personalized Access)
Security:  clock_skew, want_assertions_signed=True, allowed_redirect_hosts[]
```

## 9. Teststrategie & Docker

- **Unit** (`make test-local`): `respx` für MDQ-HTTP, signierte XML-Fixtures
  (Test-CA + IdP-Cert), `pytest` + `anyio`. Deckt Signaturprüfung, Conditions,
  Replay, Attribut-Mapping, `identifier`-Präferenz.
- **Integration** (`compose.yml`, `make test-integration`): `sp` (unser App) +
  `idp` (**SimpleSAMLphp** mit eduPerson/SCHAC-Attributen) + statischer
  **MDQ/Metadaten-Service** + optional **DS**. Flow headless über `httpx`
  (Redirects + Formular-Parsing); embedded WAYF ggf. Playwright.
- **E2E** (dokumentiert, nightly/manuell): How-to zur SP-Registrierung in der
  **DFN-AAI-Testföderation**, Test gegen deren Test-IdP + zentralen DS + MDQ.
  Nicht im PR-CI (nicht deterministisch, netzabhängig, Zertifikate nötig).

## 10. Packaging / CI / Doku

- `uv`-Stack, `pyproject.toml`, `ruff` (`E,F,W,B,UP,I,D,S`), `ty` (mypy-Fallback),
  `pytest` + `tox`-Matrix (Py 3.12/3.13).
- **System-Abhängigkeit `libxmlsec1`** (via `pysaml2`) → im Docker-Image & in der
  Doku behandeln.
- **GitHub Actions** spiegeln lokal: ruff + ty + pytest/tox + Docker-Image-Build.
- **Sphinx + MyST** (Diataxis, `plone-doc-style`): Tutorial (DFN-Quickstart),
  How-tos (DFN-Registrierung, Keys, Redis/PG-Store, embedded WAYF), Reference
  (Settings, `FederatedIdentity`, Attribut-Registry), Explanation (Trust-/Security-Modell).
- **Lizenz:** `Apache-2.0 OR EUPL-1.2` (Dual-Header in Dateien; SPDX-Ausdruck).

## 11. v1-Scope (YAGNI) & Roadmap

**v1 — drin:**

- SP-initiated SSO (AuthnRequest via Redirect-Binding, ACS via POST-Binding)
- Metadaten: MDQ + Aggregat (konfigurierbar), Trust-Anchor-Prüfung
- Discovery: externer DS + Passthrough + **embedded WAYF (opt-in)**
- Session: Cookie (Default) + JWT (opt-in); Store memory/redis/postgres
- Typisierte `FederatedIdentity` + Attribut-Registry (eduPerson/SCHAC/subject-id)
- SP-Metadaten-Endpoint, Assertion-Decryption, signierte Requests
- Best-effort SLO (lokale Session-Invalidierung immer; SAML-SLO wo IdP es kann)
- Security-Validierungen, Docker-Integration, DFN-Test-Doku

**Später (v1.1+):**

- IdP-initiated Flow
- Generisches Consumer-Identity-Modell (Subclassing)
- Metadaten-Auto-Refresh-Scheduler (Politur)
- Mehrere SP-EntityIDs

## 12. Offene Punkte / Risiken

- **`pysaml2` ist synchron & schwergewichtig** — akzeptierter Trade-off; via
  `anyio.to_thread.run_sync` gekapselt. Wartungsstand vor Release prüfen.
- `libxmlsec1`-Systemabhängigkeit erschwert reine `pip`-Installs — Docker + Doku
  entschärfen das.
- SLO in Föderationen ist notorisch unzuverlässig → bewusst nur best-effort.
- `SameSite`-Cookie-Verhalten am ACS (cross-site POST) sorgfältig testen.
- DFN-AAI-Testföderation braucht Registrierung/Zertifikate → nur E2E, nicht CI.
