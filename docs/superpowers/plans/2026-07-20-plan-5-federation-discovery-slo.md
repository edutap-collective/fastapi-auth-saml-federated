# Plan 5 — Föderation & Discovery & SLO (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Aus dem Einzel-IdP-SP einen echten **Föderations-SP** machen: Metadaten aus
**MDQ** oder **Aggregat** (Trust-Anchor-verifiziert) neben `direct`; **Discovery** über
externen **DS-Protocol** oder eingebautes **WAYF** neben `passthrough`; und
**best-effort Single Logout (SLO)**.

**Architecture:** Die Metadaten-Quelle und die Discovery werden generalisiert
(`engine/config` baut das pysaml2-`metadata`-Dict je Quelle; `engine.create_authn_request`
nimmt die IdP-EntityID *dynamisch* aus der Discovery statt fix). Zwei neue Discovery-Bausteine
(`discovery/external.py` DS-Protocol, `discovery/embedded.py` WAYF aus Metadaten +
Jinja/htmx). SLO (`engine/logout.py` + Router-Endpoints) baut LogoutRequests aus dem in der
Session gespeicherten `idp_entity_id`/`name_id` und invalidiert **immer** die lokale Session.
Additiv auf Plan 1–4; Default (`direct`+`passthrough`) unverändert.

**Tech Stack:** wie Plan 4 + **Jinja2** (WAYF-Templates) und **responses** (dev, MDQ-`requests`-Mock).
pysaml2-Config-Formate & Enumerations-/SLO-API im Quellcode verifiziert (7.5.4).

## Global Constraints

- Additiv auf Plan 1–4; Default `metadata_source="direct"` + `discovery_mode="passthrough"` reproduziert Plan-2/3-Verhalten (Suiten bleiben grün).
- Namespace `fastapi_auth` bleibt PEP-420-implizit (kein `src/fastapi_auth/__init__.py`).
- async-first: pysaml2-Calls (inkl. MDQ-Fetch, das intern `requests` nutzt) in `anyio.to_thread.run_sync`.
- Krypto/Signaturprüfung ausschließlich pysaml2/xmlsec1; Aggregat/MDQ gegen **Trust-Anchor-Cert** verifiziert.
- **Wichtig (verifiziert):** `MetaDataMDX` nutzt synchrones `requests` (nicht httpx) → MDQ-Tests mocken mit `responses` (dev-Extra), nicht respx; MDQ-Fetch stets im Thread.
- Milestone-Scope: Metadaten (mdq/aggregate/direct), Discovery (external/embedded/passthrough), best-effort SLO. **NICHT** hier: Docker-Compose/CI/Doku (Plan 6).
- pysaml2-Metadaten-Dict-Formate (verifiziert): direct→`{"inline":[xml]}`; Aggregat-Datei→`{"local":[path]}`; Aggregat-URL→`{"remote":[{"url","cert"}]}`; MDQ→`{"mdq":[{"url","cert"}]}`.
- English code/docstrings; SPDX header `SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2` in neuen Quelldateien.
- ruff `E,F,W,B,UP,I,D,S` (Tests ignorieren `S101`/`D`); `ty` 0; `make lint` exit 0; `# ty: ignore[<code>]` nur gezielt mit Begründung.
- Commit auf `main` (user-autorisiert), Conventional Commits **Deutsch**, kein `git push`. Autor-Schreibweise **Loechel** (oe).
- TDD: erst Test (rot), dann Implementierung (grün), dann Commit. Vor jedem Commit `make lint` grün + volle Suite grün, Lint-Ausgabe im Report belegen.

## File Structure

```text
src/fastapi_auth/saml/
  settings.py                 # + metadata_source/aggregate/mdq/trust_anchor + discovery_mode/ds_url + Validatoren (erweitern)
  engine/
    config.py                 # build_metadata_config(settings) je Quelle (erweitern)
    client.py                 # create_authn_request(idp_entity_id): dynamische IdP (anpassen); list_idps()
    logout.py                 # NEU: best-effort SLO (LogoutRequest bauen, Response verarbeiten)
  discovery/
    __init__.py               # NEU
    external.py               # NEU: DS-Protocol (redirect-URL bauen, return parsen)
    embedded.py               # NEU: IdP-Liste aus Metadaten (entityID + mdui display name/logo)
  wayf/
    templates/wayf.html       # NEU: WAYF-Picker (Jinja + htmx, minimal)
  router.py                   # /login je discovery_mode; /disco (return); /slo (+ return); WAYF (anpassen)
  sp.py                       # Jinja-Env für WAYF; slo/discovery verdrahten (anpassen)
tests/
  engine/test_metadata_sources.py    # NEU: config-Dict je Quelle + Aggregat-lokal end-to-end (signiert)
  engine/test_mdq.py                 # NEU: MDQ via responses-Mock (signierte Entity)
  discovery/test_external.py         # NEU: DS-URL + return
  discovery/test_embedded.py         # NEU: IdP-Enumeration aus Metadaten
  test_router_discovery_flow.py      # NEU: /login external + embedded end-to-end
  test_slo.py                        # NEU: best-effort SLO (LogoutRequest + lokale Invalidierung)
```

---

## Task 1: Föderations-Settings (Metadaten-Quellen + Discovery-Modi)

**Files:** Modify `settings.py`; Test `tests/test_settings.py`.

**Interfaces:** neue Felder + Validatoren:
- `metadata_source: Literal["direct", "aggregate", "mdq"] = "direct"`
- `aggregate_file: str | None = None`, `aggregate_url: str | None = None`, `mdq_url: str | None = None`, `trust_anchor_cert: str | None = None`
- `discovery_mode: Literal["passthrough", "external", "embedded"] = "passthrough"`, `ds_url: str | None = None`
- `metadata_langpref: str = "en"` (WAYF-Sprache)
- `model_validator(mode="after")`: `mdq` → `mdq_url` gesetzt; `aggregate` → genau eines von `aggregate_file`/`aggregate_url`; `external` → `ds_url` gesetzt.

- [ ] **Step 1: Failing tests** — in `tests/test_settings.py` ergänzen:

```python
def test_metadata_source_defaults_direct():
    assert SamlSettings(**_BASE).metadata_source == "direct"


def test_mdq_requires_url():
    with pytest.raises(ValidationError, match="mdq_url"):
        SamlSettings(**{**_BASE, "metadata_source": "mdq"})


def test_aggregate_requires_a_source():
    with pytest.raises(ValidationError, match="aggregate"):
        SamlSettings(**{**_BASE, "metadata_source": "aggregate"})


def test_external_discovery_requires_ds_url():
    with pytest.raises(ValidationError, match="ds_url"):
        SamlSettings(**{**_BASE, "discovery_mode": "external"})


def test_mdq_accepts_url():
    s = SamlSettings(**{**_BASE, "metadata_source": "mdq", "mdq_url": "https://mdq.dfn.de"})
    assert s.mdq_url == "https://mdq.dfn.de"
```

- [ ] **Step 2: Rot** — `uv run pytest tests/test_settings.py -v -k "metadata or mdq or aggregate or discovery"` → FAIL.

- [ ] **Step 3: Settings** — Felder ergänzen (nach dem bestehenden Metadaten-/Discovery-Block; die alten `idp_metadata_file`/`idp_metadata_url` für `direct` und `fixed_idp_entity_id` für `passthrough` bleiben) und Validator:

```python
    @model_validator(mode="after")
    def _check_federation_config(self) -> "SamlSettings":
        if self.metadata_source == "mdq" and not self.mdq_url:
            raise ValueError("metadata_source='mdq' requires mdq_url")
        if self.metadata_source == "aggregate" and not (self.aggregate_file or self.aggregate_url):
            raise ValueError("metadata_source='aggregate' requires aggregate_file or aggregate_url")
        if self.discovery_mode == "external" and not self.ds_url:
            raise ValueError("discovery_mode='external' requires ds_url")
        return self
```

> Das bestehende `metadata_source: Literal["direct"]` wird zu `Literal["direct","aggregate","mdq"]` erweitert;
> `discovery_mode: Literal["passthrough"]` zu `Literal["passthrough","external","embedded"]`. Der JWT-Validator
> aus Plan 4 bleibt (ggf. beide Checks in einem `model_validator` zusammenführen — dann beide Bedingungen behalten).

- [ ] **Step 4: Grün + lint** — belegen. **Step 5: Commit** — `feat(settings): Föderations-Metadaten-Quellen (mdq/aggregate) + Discovery-Modi (external/embedded)`.

---

## Task 2: Metadaten-Config je Quelle + Jinja2/responses-Deps

**Files:** Modify `pyproject.toml`, `engine/config.py`; Test `tests/engine/test_metadata_sources.py`.

**Interfaces:** `build_metadata_config(settings) -> dict` liefert das pysaml2-`metadata`-Dict:
- `direct` → `{"inline": [load_idp_metadata(settings)]}` (bisheriges Verhalten)
- `aggregate` + `aggregate_file` → `{"local": [settings.aggregate_file]}`
- `aggregate` + `aggregate_url` → `{"remote": [{"url": settings.aggregate_url, "cert": settings.trust_anchor_cert}]}`
- `mdq` → `{"mdq": [{"url": settings.mdq_url, "cert": settings.trust_anchor_cert}]}`

`build_sp_config` nutzt `build_metadata_config(settings)` statt des festen `{"inline": [...]}`.

- [ ] **Step 1: Deps** — `pyproject.toml`: core `dependencies` += `"jinja2>=3.1"`; dev-Extra += `"responses>=0.25"`. `uv pip install -U -e ".[dev]"`.

- [ ] **Step 2: Failing test** — `tests/engine/test_metadata_sources.py`:

```python
"""build_metadata_config emits the right pysaml2 metadata dict per source."""

from saml2.config import SPConfig

from fastapi_auth.saml.engine.config import build_metadata_config, build_sp_config
from fastapi_auth.saml.settings import SamlSettings

_SP = dict(entity_id="urn:test:sp", base_url="https://sp.example", key_file="/tmp/k", cert_file="/tmp/c")


def test_direct_source_is_inline(tmp_path):
    md = tmp_path / "idp.xml"
    md.write_text('<EntityDescriptor entityID="urn:test:idp"/>')
    s = SamlSettings(**_SP, fixed_idp_entity_id="urn:test:idp", idp_metadata_file=str(md), session_secret="x")
    assert "inline" in build_metadata_config(s)


def test_aggregate_file_is_local(tmp_path):
    agg = tmp_path / "agg.xml"
    agg.write_text("<x/>")
    s = SamlSettings(**_SP, fixed_idp_entity_id="urn:i", metadata_source="aggregate", aggregate_file=str(agg), session_secret="x")
    assert build_metadata_config(s) == {"local": [str(agg)]}


def test_aggregate_url_is_remote_with_cert():
    s = SamlSettings(**_SP, fixed_idp_entity_id="urn:i", metadata_source="aggregate",
                     aggregate_url="https://md.dfn.de/agg.xml", trust_anchor_cert="/tmp/ta.pem", session_secret="x")
    assert build_metadata_config(s) == {"remote": [{"url": "https://md.dfn.de/agg.xml", "cert": "/tmp/ta.pem"}]}


def test_mdq_is_mdq_with_cert():
    s = SamlSettings(**_SP, fixed_idp_entity_id="urn:i", metadata_source="mdq",
                     mdq_url="https://mdq.dfn.de", trust_anchor_cert="/tmp/ta.pem", session_secret="x")
    assert build_metadata_config(s) == {"mdq": [{"url": "https://mdq.dfn.de", "cert": "/tmp/ta.pem"}]}


def test_aggregate_local_loads_multi_idp_in_pysaml2(tmp_path, certs):
    # Build a real signed aggregate of two IdPs and confirm SPConfig loads it.
    from tests.conftest import build_signed_aggregate  # helper added in this task
    agg = build_signed_aggregate(tmp_path, certs, ["urn:idp:a", "urn:idp:b"])
    s = SamlSettings(**{**_SP, "key_file": certs["sp_key"], "cert_file": certs["sp_crt"]},
                     fixed_idp_entity_id="urn:idp:a", metadata_source="aggregate", aggregate_file=agg, session_secret="x")
    cfg = SPConfig().load(build_sp_config(s))
    idps = cfg.metadata.identity_providers()
    assert "urn:idp:a" in idps and "urn:idp:b" in idps
```

- [ ] **Step 3: `build_signed_aggregate` conftest-Helfer** — in `tests/conftest.py` ergänzen: erzeugt aus mehreren IdP-EntityIDs je ein `IdPConfig`-Metadatum, fasst sie zu einem `<EntitiesDescriptor>` zusammen und schreibt es als Datei; nutzt `saml2.metadata` (ggf. `entities_descriptor` + Signatur mit `certs["idp_key"]`/`certs["idp_crt"]`). Für `{"local"}` genügt unsigniert (MetaDataFile prüft lokal keine Signatur) — der Test prüft nur Enumeration.

- [ ] **Step 4: `build_metadata_config` + `build_sp_config`** — implementieren (Dispatch je `metadata_source`). **Step 5: Grün + lint** (belegen). **Step 6: Commit** — `feat(engine): Metadaten-Config je Quelle (direct/aggregate/mdq) + jinja2/responses-Deps`.

---

## Task 3: MDQ end-to-end (responses-Mock, signierte Entity)

**Files:** Test `tests/engine/test_mdq.py` (nutzt bestehende Engine + build_sp_config mit `mdq`-Quelle).

**Interfaces:** kein neuer Produktionscode — validiert, dass die Engine mit `metadata_source="mdq"` eine per MDQ abgerufene, signierte IdP-Metadate lädt. `responses` mockt `GET {mdq_url}/entities/{sha1}<hexdigest>` mit signiertem `<EntityDescriptor>`, `cert` = Trust-Anchor.

- [ ] **Step 1: Failing test** — `tests/engine/test_mdq.py`:

```python
"""MDQ metadata source: per-entity signed fetch, mocked with `responses`."""

import hashlib

import responses

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.settings import SamlSettings


def _sha1_transform(entity_id: str) -> str:
    return "{sha1}" + hashlib.sha1(entity_id.encode()).hexdigest()  # noqa: S324 - MDQ spec mandates sha1


@responses.activate
def test_mdq_fetches_and_validates_signed_idp(tmp_path, certs, signed_idp_metadata):
    idp_eid = "urn:test:idp"
    mdq_url = "https://mdq.example"
    responses.add(
        responses.GET,
        f"{mdq_url}/entities/{_sha1_transform(idp_eid)}",
        body=signed_idp_metadata,  # signed EntityDescriptor bytes/str, signer = trust anchor
        content_type="application/samlmetadata+xml",
        status=200,
    )
    s = SamlSettings(
        entity_id="urn:test:sp", base_url="https://sp.example",
        key_file=certs["sp_key"], cert_file=certs["sp_crt"],
        fixed_idp_entity_id=idp_eid, metadata_source="mdq",
        mdq_url=mdq_url, trust_anchor_cert=certs["idp_crt"], session_secret="x",
    )
    engine = SamlEngine(s)
    # A successful create_authn_request proves the IdP metadata was fetched+validated via MDQ.
    reqid, location = engine._prepare("/app")  # sync helper; MDQ fetch happens on demand
    assert location.startswith("https://idp")  # IdP SSO location from fetched metadata
```

- [ ] **Step 2: `signed_idp_metadata` fixture** — in `tests/conftest.py`: erzeugt IdP-Metadaten (`create_metadata_string(..., sign=True, ...)` mit `certs["idp_key"]`/`certs["idp_crt"]`) für `IDP_EID` mit SSO-Endpoint `https://idp.../sso`. Trust-Anchor = `certs["idp_crt"]` (self-signed = Signer). Rückgabe als str.

> Verifikation nötig: `create_metadata_string`-Signatur-Parameter (`sign=True`, `keyfile`/`cert`).
> Falls die Signatur-API abweicht, korrekt anpassen; das Ziel: eine gegen `certs["idp_crt"]` verifizierbare Metadate.
> Der MDQ-Fetch (`requests.get`) darf im Test synchron laufen (kein Event-Loop nötig für `_prepare`).

- [ ] **Step 3: Rot → Grün** (Engine lädt via MDQ). **Step 4: lint** (belegen). **Step 5: Commit** — `test(engine): MDQ-Quelle end-to-end via responses-Mock (signierte Entity)`.

---

## Task 4: Engine — dynamische IdP + IdP-Enumeration

**Files:** Modify `engine/client.py`; Test `tests/discovery/test_embedded.py` (Enumeration), Anpassung bestehender Roundtrip-Tests.

**Interfaces:**
- `SamlEngine.create_authn_request(relay_state, idp_entity_id: str | None = None)` — nutzt `idp_entity_id` wenn gesetzt, sonst `settings.fixed_idp_entity_id` (Rückwärtskompatibilität für `passthrough`). `_prepare(relay_state, idp_entity_id)`.
- `SamlEngine.list_idps(langpref: str | None = None) -> list[IdPChoice]` — aus `self._client.config.metadata`: `identity_providers()` → je entityID `mdui_uiinfo_display_name(eid, langpref)` (Fallback `mds.name(eid)` bzw. entityID). `IdPChoice` = Pydantic (`entity_id`, `display_name`).

- [ ] **Step 1: Failing tests** — `tests/discovery/test_embedded.py`:

```python
"""IdP enumeration from federation metadata."""

from tests.conftest import build_signed_aggregate

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.settings import SamlSettings


def test_list_idps_from_aggregate(tmp_path, certs):
    agg = build_signed_aggregate(tmp_path, certs, ["urn:idp:a", "urn:idp:b"])
    s = SamlSettings(entity_id="urn:test:sp", base_url="https://sp.example",
                     key_file=certs["sp_key"], cert_file=certs["sp_crt"],
                     fixed_idp_entity_id="urn:idp:a", metadata_source="aggregate",
                     aggregate_file=agg, session_secret="x")
    idps = SamlEngine(s).list_idps()
    ids = {c.entity_id for c in idps}
    assert {"urn:idp:a", "urn:idp:b"} <= ids
```

Und in `tests/engine/test_client_roundtrip.py`: `create_authn_request` weiterhin ohne `idp_entity_id` grün (Default = fixed).

- [ ] **Step 2–5:** `IdPChoice`-Modell + `list_idps` + `create_authn_request(idp_entity_id=None)` implementieren; bestehende Roundtrip-Tests bleiben grün (Default-IdP). Grün + lint (belegen). Commit — `feat(engine): dynamische IdP-EntityID + IdP-Enumeration (list_idps)`.

---

## Task 5: Discovery — externer DS + embedded WAYF

**Files:** Create `discovery/__init__.py`, `discovery/external.py`, `discovery/embedded.py`, `wayf/templates/wayf.html`; Test `tests/discovery/test_external.py`, (embedded aus Task 4).

**Interfaces:**
- `external.py`: `ds_redirect_url(ds_url, sp_entity_id, return_url) -> str` (baut `{ds_url}?entityID=<sp>&return=<return_url>` URL-encoded); `parse_ds_return(query_params) -> str | None` (liest `entityID` aus dem Return).
- `embedded.py`: `render_wayf(idps: list[IdPChoice], login_path: str, jinja_env) -> str` (rendert `wayf.html`: Liste von `<a href="{login_path}?idp=<entityID>&next=...">display_name</a>`, htmx-optional, minimal).

- [ ] **Step 1: Failing tests** — `tests/discovery/test_external.py`:

```python
"""External Discovery Service protocol URL building + return parsing."""

from urllib.parse import parse_qs, urlparse

from fastapi_auth.saml.discovery.external import ds_redirect_url, parse_ds_return


def test_ds_redirect_url_encodes_params():
    url = ds_redirect_url("https://ds.dfn.de/DS", "urn:test:sp", "https://sp.example/saml/disco")
    q = parse_qs(urlparse(url).query)
    assert q["entityID"] == ["urn:test:sp"]
    assert q["return"] == ["https://sp.example/saml/disco"]


def test_parse_ds_return_reads_entity_id():
    assert parse_ds_return({"entityID": "urn:chosen:idp"}) == "urn:chosen:idp"
    assert parse_ds_return({}) is None
```

- [ ] **Step 2–5:** `external.py` + `embedded.py` + `wayf.html` implementieren; Grün + lint (belegen). Commit — `feat(discovery): externer DS-Protocol + embedded WAYF-Renderer`.

---

## Task 6: Router-Verdrahtung (Discovery-Flows)

**Files:** Modify `router.py`, `sp.py`; Test `tests/test_router_discovery_flow.py`.

**Interfaces:** `/login?next=` dispatcht je `settings.discovery_mode`:
- `passthrough` → wie bisher (fixed IdP, direkt AuthnRequest).
- `external` → Redirect zu `ds_redirect_url(ds_url, sp_entity_id, base_url+"/saml/disco")` (mit `next` im Return-URL-State, z. B. als Query oder signiertes RelayState).
- `embedded` → HTML-Response `render_wayf(sp.engine.list_idps(langpref), login_path, jinja_env)`.
- `GET /saml/disco` (DS-Return) → `entityID = parse_ds_return(request.query_params)`; dann AuthnRequest an diese IdP (`create_authn_request(relay_state=next, idp_entity_id=entityID)`), Outstanding speichern, Redirect zum IdP.
- `/login?idp=<entityID>` (WAYF-Auswahl) → AuthnRequest an gewählte IdP.

`sp.py`: Jinja-`Environment` (FileSystemLoader auf `wayf/templates`) als `sp._jinja`.

- [ ] **Step 1: Failing e2e test** — `tests/test_router_discovery_flow.py`: (a) `discovery_mode="external"`: `/login?next=/app` → 303 zum `ds_url` mit `entityID`+`return`; `/saml/disco?entityID=urn:test:idp` → 303 zum IdP SSO mit `SAMLRequest`. (b) `discovery_mode="embedded"`: `/login` → 200 HTML mit den IdP-`entity_id`s; `/login?idp=urn:test:idp` → 303 zum IdP.

- [ ] **Step 2–5:** Router/`sp.py` implementieren; Default `passthrough`-Flow (Plan-2/3-Tests) bleibt grün. Grün + lint (belegen). Commit — `feat(saml): Discovery-Router-Flows (external DS + embedded WAYF)`.

---

## Task 7: Best-effort SLO

**Files:** Create `engine/logout.py`; Modify `router.py`, `sp.py`, `session/*` (Backend `revoke` bereits vorhanden); Test `tests/test_slo.py`.

**Interfaces:**
- `engine/logout.py`: `SamlEngine.create_logout_redirect(identity) -> str | None` — baut aus `identity.idp_entity_id` + `identity.name_id`/`name_id_format` einen **LogoutRequest** an den SLO-Endpoint des IdP (aus Metadaten; HTTP-Redirect-Binding), signiert; gibt Redirect-URL zurück oder `None`, wenn der IdP kein SLO anbietet oder `name_id` fehlt. `handle_logout_response(saml_response, binding) -> bool` (best-effort).
- Router: `GET /saml/slo` → lokale Session **immer** invalidieren (`backend.revoke`); wenn `create_logout_redirect` eine URL liefert → dorthin redirecten, sonst zu `next`/`/`. `GET/POST /saml/slo/return` → `handle_logout_response` (best-effort), Redirect zu `/`.

> **pysaml2-Verifikation (Task-lokal):** Der genaue Weg, einen LogoutRequest ohne den
> `client.users`-Cache zu bauen, an pysaml2 7.5.4 prüfen (`create_logout_request(destination,
> issuer_entity_id, name_id, ...)` bzw. `do_logout` mit explizitem `entity_ids`/`name_id`).
> Falls `global_logout` zwingend den users-Cache braucht: vor dem Logout `client.users.add_information_about_person(session_info)` mit den gespeicherten Daten füttern ODER `create_logout_request` direkt nutzen. Der Test muss den erzeugten LogoutRequest gegen einen In-Memory-IdP prüfen.

- [ ] **Step 1: Failing test** — `tests/test_slo.py`: (a) nach Login (In-Memory-IdP mit SLO-Endpoint in Metadaten) liefert `create_logout_redirect(identity)` eine Redirect-URL zum IdP-SLO mit `SAMLRequest`; (b) `GET /saml/slo` invalidiert die Session **immer** (auch wenn der IdP kein SLO anbietet → Redirect zu `/`, Session weg).

- [ ] **Step 2–5:** `logout.py` + Router/`sp.py`; In-Memory-IdP-Fixture um SLO-Endpoint erweitern. Grün + lint + `make lint` (belegen). Commit — `feat(saml): best-effort Single Logout (LogoutRequest + lokale Invalidierung)`.

---

## Self-Review

**Spec-Abdeckung (Spec §2/§3):**
- MDQ + Aggregat-Metadaten (Trust-Anchor) → Task 1/2/3 ✅
- Externer DS + embedded WAYF → Task 5/6 ✅
- Dynamische IdP-Auswahl (Discovery → AuthnRequest) → Task 4/6 ✅
- Best-effort SLO (lokale Invalidierung immer) → Task 7 ✅
- Default direct+passthrough unverändert → alle Tasks additiv ✅

**Bewusst NICHT in Plan 5:** Docker-Compose/CI/Sphinx-Doku + Live-Tests gegen echtes DFN-MDQ/DS/lmuidp (Plan 6);
atomares Outstanding-Pop & RS256/EdDSA (aus Plan 4, weiterhin offen).

**Bekannte Risiken (mit Verifikations-Hinweisen im jeweiligen Task):**
- **MDQ nutzt `requests`** → `responses`-Mock statt respx (Task 3); Fetch im Thread.
- **Signierte Test-Metadaten** (`create_metadata_string(sign=True)`) — Signatur-API im Task verifizieren (Task 2/3).
- **SLO ohne users-Cache** — genauen pysaml2-Pfad (`create_logout_request` vs. `global_logout`) im Task verifizieren; ggf. Spike vor Task 7 (wie Plan-2-Spike).
- **`{"local"}` prüft keine Aggregat-Signatur** — Aggregat-Datei gilt als vertrauenswürdig bezogen; signaturgeprüft nur `remote`/`mdq`. In Doku (Plan 6) klarstellen.

**Empfehlung:** Vor Task 3 (MDQ) und Task 7 (SLO) je einen kurzen Spike (wie beim Plan-2-Signatur-Roundtrip),
um die signierte-Metadaten- bzw. LogoutRequest-API real zu bestätigen, bevor die Tasks laufen.

---

## Nächster Meilenstein

- **Plan 6 — Docker/CI/Doku:** `compose.yml` (SimpleSAMLphp-IdP + statischer MDQ/DS + Redis + Postgres),
  `make test-integration`, GitHub Actions + tox, Sphinx/MyST-Doku (Diataxis), How-tos für
  `lmuidp-container` (echter Shibboleth) und DFN-AAI-Testföderation; plus die aus Plan 4/5 offenen
  Härtungen (atomares Pop, RS256/EdDSA, `{"local"}`-Trust-Hinweis).
```
