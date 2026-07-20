# Registering in the DFN-AAI test federation

Testing against a real, multi-IdP federation instead of a single bilateral IdP (see
{doc}`simplesamlphp` and {doc}`lmuidp`) means fetching IdP metadata from the
federation's own trust infrastructure and letting users pick their institution via
the federation's Discovery Service (DS), rather than hardcoding one fixed IdP.

[DFN-AAI](https://www.aai.dfn.de/) runs a separate test federation for exactly this
purpose: registering a test SP there does not require production-grade vetting, and
the test federation is isolated from the production one.

## 1. Register the SP

Follow the DFN-AAI test federation's own registration process (via the DFN-AAI
Wiki/registration form) to register your SP's metadata (`GET /saml/metadata`) and
receive back the federation's operational details: the MDQ (Metadata Query Protocol)
endpoint URL, the Discovery Service URL, and — critically — the trust anchor
certificate used to verify federation metadata signatures. These are specific to the
test federation instance and are handed to you as part of registration; they are not
guessed or hardcoded here.

## 2. Configure `metadata_source="mdq"`

MDQ (federation metadata fetched per-entity, on demand, rather than as one large
aggregate) is DFN-AAI's preferred metadata source. It **requires** a trust anchor
certificate — the SP refuses to start without one, because federation metadata must
be cryptographically verified before it is trusted:

```python
from fastapi_auth import saml

saml.SamlSettings(
    ...,
    metadata_source="mdq",
    mdq_url="https://<mdq-endpoint-from-registration>",
    trust_anchor_cert="/path/to/dfn-aai-test-signer.pem",
)
```

Omitting `trust_anchor_cert` with `metadata_source="mdq"` raises at settings
construction time:

```text
ValueError: metadata_source='mdq' requires trust_anchor_cert (metadata must be verified)
```

(The same requirement applies to `metadata_source="aggregate"` whenever
`aggregate_url` is a remote URL rather than a local `aggregate_file` — any metadata
fetched over the network must be signature-verified against a trust anchor before
use.)

## 3. Configure `discovery_mode="external"`

With many possible IdPs in a real federation, users need to pick their home
institution. `discovery_mode="external"` redirects to the federation's central
Discovery Service, which redirects back to `/saml/login` with the chosen IdP's
`entityID`:

```python
saml.SamlSettings(
    ...,
    discovery_mode="external",
    ds_url="https://<discovery-service-from-registration>",
)
```

`ds_url` is required whenever `discovery_mode="external"` — omitting it raises the
same way as the `trust_anchor_cert` check above.

## 4. Log in

Visit `/saml/login?next=/` on your SP. You are redirected to the DFN-AAI test
federation's Discovery Service, pick a test IdP there, authenticate, and return to
`next` with an active session — its attributes sourced from whichever IdP you chose,
subject to that IdP's attribute release policy for your SP.

## Notes

- This is deliberately **not** part of automated CI: it depends on external network
  services, federation registration state, and certificates that aren't available in
  a CI runner. Treat it as a manual, occasional end-to-end check.
- See {doc}`stores` for session handling once attributes come back from a federated
  IdP, and {doc}`lmuidp` for the LMU-internal bilateral alternative.
