# fastapi-auth-saml-federated

A federated SAML2 Service Provider (SP) for [FastAPI](https://fastapi.tiangolo.com/),
built for Shibboleth-style academic identity federations (Germany's DFN-AAI, eduGAIN,
and other NREN AAIs such as SWITCHaai, SURFconext or SWAMID). It mounts a small router
that implements SP-initiated SSO (`/login`, `/acs`), SAML metadata (`/metadata`),
best-effort single logout (`/slo`), and, on top of that, discovery of the right
Identity Provider (IdP) — either a fixed bilateral IdP, an external federation
Discovery Service, or an embedded "Where Are You From" (WAYF) page.

## Install

The package needs the `xmlsec1` command-line tool at runtime (`pysaml2` shells out
to it for XML signing/verification). Install it via your system package manager
first, for example on Debian/Ubuntu:

```bash
sudo apt-get install --no-install-recommends xmlsec1
```

Then install the package itself:

```bash
uv pip install fastapi-auth-saml-federated
```

The session store backend is pluggable (see {doc}`howto/stores`). The default
in-memory store needs nothing extra; Redis- or Postgres-backed stores need their
respective extra:

```bash
uv pip install "fastapi-auth-saml-federated[redis]"
uv pip install "fastapi-auth-saml-federated[postgres]"
```

## Minimal usage

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
app.include_router(sp.router, prefix="/saml")

current_user = sp.current_user()


@app.get("/whoami")
async def whoami(identity: saml.FederatedIdentity = Depends(current_user)):
    return {"subject": sp.identifier(identity)}
```

`sp.current_user()` returns a dependency that raises `401 Unauthorized` when there is
no active session; `sp.optional_user()` returns the same identity or `None` instead of
raising. Both depend on the endpoint prefix matching `settings.mount_path` (default
`/saml`) — see {doc}`howto/stores` for how the session itself is carried and stored.

## How-to guides

```{toctree}
:maxdepth: 1
:caption: How-to guides

howto/docker
howto/stores
howto/simplesamlphp
howto/lmuidp
howto/dfn-aai
```
