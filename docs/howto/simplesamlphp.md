# Testing against a local SimpleSAMLphp IdP

For day-to-day development you don't need a real federation — a local
[SimpleSAMLphp](https://simplesamlphp.org/) instance running as an IdP is enough to
exercise the whole SP-initiated SSO flow (AuthnRequest → login form → assertion →
ACS) with real, self-signed SAML XML.

This how-to assumes you already have a SimpleSAMLphp IdP running somewhere reachable
from your SP (locally via Docker, e.g. `kristophjunge/test-saml-idp`, or an existing
instance) with `eduPerson`/`SCHAC` attributes configured for its test users. Setting
up the SimpleSAMLphp container itself is outside this package's scope; this how-to
covers the SP-side configuration once it's there.

## 1. Point the SP at the IdP's metadata

Two options, both supported via `metadata_source="direct"` (single bilateral IdP, no
federation trust chain needed):

```python
from fastapi_auth import saml

settings = saml.SamlSettings(
    entity_id="https://sp.example.org/saml/metadata",
    base_url="https://sp.example.org",
    key_file="sp-key.pem",
    cert_file="sp-cert.pem",
    metadata_source="direct",
    idp_metadata_url="http://localhost:8080/simplesaml/saml2/idp/metadata.php",
    fixed_idp_entity_id="http://localhost:8080/simplesaml/saml2/idp/metadata.php",
    discovery_mode="passthrough",
    session_secret="change-me-to-a-long-random-value",
)
```

- `idp_metadata_url` fetches the IdP's metadata over HTTP at startup (use
  `idp_metadata_file` instead to point at a locally saved copy — useful in offline
  or airgapped test setups).
- `fixed_idp_entity_id` must match the `entityID` in that metadata exactly.
- `discovery_mode="passthrough"` skips any discovery UI: `/login` goes straight to
  the fixed IdP, which is exactly what you want for a single test IdP.

## 2. Exchange the SP's metadata

SimpleSAMLphp (like any SAML IdP) needs to trust your SP's metadata before it will
accept AuthnRequests from it. Fetch the SP's metadata from the running application:

```bash
curl http://localhost:8000/saml/metadata > sp-metadata.xml
```

Register `sp-metadata.xml` as a trusted service provider in the SimpleSAMLphp IdP's
configuration (its `saml20-sp-remote.php` metadata store, or the admin UI if you're
using a container image that provides one). The exact steps depend on how you're
running SimpleSAMLphp; consult its documentation for "adding a remote SP".

## 3. Log in

Visit `http://localhost:8000/saml/login?next=/` in a browser. You should be
redirected to the SimpleSAMLphp login form, and back to `/` (or wherever `next`
points) with an active session after a successful login.

See {doc}`stores` for how that session is carried and persisted, and {doc}`lmuidp`
or {doc}`dfn-aai` for testing against a real academic IdP instead of a local one.
