# Choose which IdP signature to require

An IdP can sign the SAML `<samlp:Response>`, the `<saml:Assertion>` inside it,
or both. The SP decides which signature it insists on; a response that lacks
it is rejected at the ACS like any other invalid response
(`SamlResponseError` from `SamlEngine.parse_response`, `400` from the router).

Two settings select the requirement:

| Requirement | `want_assertions_signed` | `want_response_signed` |
| ----------- | ------------------------ | ---------------------- |
| Signed assertion (default) | `True` | `False` |
| Signed response | `False` | `True` |
| Both signed | `True` | `True` |

Setting both to `False` is refused when `SamlSettings` is created. The SP
would otherwise accept a response in which nothing is signed, so anyone could
post a forged login to the ACS.

## When to change the default

Keep the default unless the IdP does not sign assertions for your SP. Check
what it sends: decode a `SAMLResponse` from a test login (base64) and look
for `<ds:Signature>` directly under `<samlp:Response>` and under
`<saml:Assertion>`. If the IdP signs only the response, switch to it:

```python
from fastapi_auth import saml

settings = saml.SamlSettings(
    ...,
    want_assertions_signed=False,
    want_response_signed=True,
)
```

or, from the environment, `SAML_WANT_ASSERTIONS_SIGNED=false` and
`SAML_WANT_RESPONSE_SIGNED=true`.

A signed response covers the assertion it contains, including an encrypted
one. Require both only if the IdP is known to sign both for your SP;
otherwise every login fails.

The SP metadata advertises `WantAssertionsSigned` from
`want_assertions_signed`. SAML metadata has no attribute for a response
signature, so `want_response_signed` is a local check only -- agree on it with
the IdP operator.
