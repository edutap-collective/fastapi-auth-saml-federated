# Testing against the real LMU Shibboleth IdP (`lmuidp-container`)

For a high-fidelity check beyond a local SimpleSAMLphp IdP (see {doc}`simplesamlphp`),
LMU maintains a containerized copy of its production Shibboleth IdP, pre-loaded with
the real LMU directory schema (`subject-id`/`pairwise-id`/`eppn`) and test users. This
how-to is LMU-internal — it only applies if you have access to the referenced
GitLab repository.

```{note}
This setup is heavy: a Java build producing a full Shibboleth IdP image, needing
**16 GB+** of free disk/RAM. Deliberately **not** part of automated CI — run it
manually, locally, when you need this level of fidelity.
```

## 1. Get and start the IdP container

Repository: `gitlab.lrz.de:LMU-Dez-VI/Ref.-VI.4/lmuidp-container`.

```bash
git clone git@gitlab.lrz.de:LMU-Dez-VI/Ref.-VI.4/lmuidp-container.git
cd lmuidp-container
./gradlew composeUp
```

This builds and starts the IdP, exposing it on host port **10444** (the container's
internal `8443`). Its entityID is fixed:

```text
urn:lmu.de:testidp
```

## 2. Point the SP at it

Same `metadata_source="direct"` + `discovery_mode="passthrough"` shape as the
SimpleSAMLphp how-to, but with the LMU test IdP's real metadata:

```python
from fastapi_auth import saml

settings = saml.SamlSettings(
    entity_id="https://sp.example.org/saml/metadata",
    base_url="https://sp.example.org",
    key_file="sp-key.pem",
    cert_file="sp-cert.pem",
    metadata_source="direct",
    idp_metadata_url="https://localhost:10444/idp/shibboleth",
    fixed_idp_entity_id="urn:lmu.de:testidp",
    discovery_mode="passthrough",
    session_secret="change-me-to-a-long-random-value",
)
```

Adjust the `idp_metadata_url` host/path to match however you reach the container
(e.g. via `idp_metadata_file` with a locally saved copy, if you prefer not to fetch
it live over TLS with a self-signed/test certificate).

## 3. Register the SP with the IdP (bilateral trust)

Unlike a federation-wide metadata source, this is a **bilateral** trust
relationship: the IdP only accepts AuthnRequests from SPs it explicitly knows about.
Fetch your SP's metadata and add it to the container's metadata file:

```bash
curl https://sp.example.org/saml/metadata
```

Copy the returned `<EntityDescriptor>` element into
`test/idp-test/metadata/metadata.xml` inside the `lmuidp-container` checkout,
alongside the container's existing test SPs, then restart the IdP (or reload its
metadata, depending on the container's own instructions) so it picks up the change.

## 4. Log in

Visit `/saml/login?next=/` on your SP. You'll be redirected to the real LMU IdP login
page. Test credentials (every test user shares the same password):

- Username: `i.reska`
- Password: `shampoo1`

A successful login returns you to `next` with an active session, carrying real
LMU-schema attributes (`subject-id`, `pairwise-id`, `eppn`, and others depending on
attribute release configured for your SP entry).

See {doc}`stores` for session handling and {doc}`dfn-aai` for testing against the
DFN-AAI test federation instead of a bilateral single-IdP setup.
