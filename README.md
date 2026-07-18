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
