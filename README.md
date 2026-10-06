# fastapi-auth-saml-federated

Federated SAML2 Service Provider for FastAPI — Shibboleth / eduGAIN / NREN AAIs
(DFN-AAI, SWITCHaai, SURFconext, SWAMID). Part of the `fastapi_auth` package family.

## Install

The SP shells out to the `xmlsec1` command-line tool for XML signing/verification
(via `pysaml2`) — install it via your system package manager first:

```bash
sudo apt-get install --no-install-recommends xmlsec1   # Debian/Ubuntu
```

Then the package:

```bash
uv pip install fastapi-auth-saml-federated
```

The session store is pluggable; the default in-memory store needs nothing extra,
Redis- or Postgres-backed stores need their extra (see [Backends](#backends)):

```bash
uv pip install "fastapi-auth-saml-federated[redis]"
uv pip install "fastapi-auth-saml-federated[postgres]"
```

## Quickstart

```python
from fastapi import Depends, FastAPI

from fastapi_auth import saml

app = FastAPI()

sp = saml.SamlSP(
    saml.SamlSettings(
        entity_id="https://sp.example.org/saml/metadata",
        base_url="https://sp.example.org",
        key_file="sp-key.pem",
        cert_file="sp-cert.pem",
        idp_metadata_file="idp-metadata.xml",
        fixed_idp_entity_id="https://idp.example.org/idp/shibboleth",
        session_secret="change-me-to-a-long-random-value",
    )
)
sp.mount(app)
# equivalent to: app.include_router(sp.router, prefix=sp.settings.mount_path)
# -- only use include_router() directly if prefix matches settings.mount_path exactly.

current_user = sp.current_user()


@app.get("/whoami")
async def whoami(identity: saml.FederatedIdentity = Depends(current_user)):
    return {"subject": sp.identifier(identity)}
```

`sp.current_user()` is a dependency raising `401` without an active session;
`sp.optional_user()` returns the identity or `None` instead.

## Development

```bash
uv venv && source .venv/bin/activate
make install          # uv pip install -U -e ".[dev]"
make test-local
```

## Docker

A multi-stage `Dockerfile` (slim runtime image, `xmlsec1` baked in) and a
`compose.yml` (Redis + Postgres, for exercising the store backends against the real
thing) are provided:

```bash
docker build -t fastapi-auth-saml-federated .
make test-integration   # docker compose up -d --wait, run integration tests, teardown
```

See `docs/howto/docker.md` for details, including local port overrides via
`compose.override.yml`.

## Backends

Session **backend** (`cookie` default, or `jwt`) and session **store**
(`memory` default, or `redis`/`postgres`) are chosen independently via
`SamlSettings(backend=..., store=..., redis_url=..., db_url=...)`. The `jwt` backend
requires a signing secret of at least 32 bytes. See `docs/howto/stores.md` for the
full trade-offs and extras.

## Federation

Metadata can come from a single bilateral IdP (`metadata_source="direct"`) or from a
federation (`"aggregate"` / `"mdq"`); the latter two require a `trust_anchor_cert` to
verify signatures on metadata fetched over the network. Discovery of the right IdP
is `"passthrough"` (single fixed IdP), `"external"` (redirect to a federation
Discovery Service via `ds_url`), or `"embedded"` (a WAYF page rendered by the SP
itself). See the how-tos for testing against a local SimpleSAMLphp IdP, the
LMU `lmuidp-container` (Shibboleth), and the DFN-AAI test federation.

## Authentication context and logout

A login can request an authentication context such as REFEDS MFA and have the
asserted one checked -- per login via `SamlEngine`, or for the whole router via
`SamlSP(settings, requested_authn_context=...)`; see `docs/howto/authn-context.md`.
Logging out is a `POST` to `{mount_path}/slo` with a CSRF token;
`GET {mount_path}/slo` only renders a confirmation form (`docs/howto/logout.md`).

## Extensions and raw attributes

`SamlEngine.create_authn_request(extensions=[...])` adds namespaced XML to
`<samlp:Extensions>` for one login; `SamlEngine.parse_response_details()`
also returns every `<saml:Attribute>` with its XML attributes. The
`fastapi_auth.saml.akdb` module builds BundID's `akdb:AuthenticationRequest`
and reads `akdb:TrustLevel`; see `docs/howto/extensions.md`.

## Signatures and the IdP sign-in endpoint

By default the SP requires a signed assertion. `want_response_signed=True`
(with `want_assertions_signed=False`, or `True` for both) requires a signed
response instead; see `docs/howto/signatures.md`.
`SamlEngine.idp_sso_url()` returns the IdP's `SingleSignOnService` location,
for example for a CSP `form-action`; see `docs/howto/sso-endpoint.md`.

## Docs

Full documentation (Sphinx + MyST) lives in `docs/`:

```bash
uv pip install -U -e ".[docs]"
uv run sphinx-build -b html docs docs/_build
```

Open `docs/_build/index.html`, or read the sources directly under `docs/index.md`
and `docs/howto/`.

## License

Dual-licensed: **Apache-2.0 OR EUPL-1.2** — the recipient may choose either.
See `LICENSE-APACHE` and `LICENSE-EUPL`.
