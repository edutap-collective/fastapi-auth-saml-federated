# Request an authentication context (MFA, assurance level)

A login can ask the IdP for a particular authentication context -- for example
multi-factor authentication per the
[REFEDS MFA Profile](https://refeds.org/profile/mfa) -- with a
`<samlp:RequestedAuthnContext>` in the AuthnRequest. The IdP may ignore the
request, so the asserted `AuthnContextClassRef` is checked in the response.

## Describe the context

```python
from fastapi_auth import saml

mfa = saml.RequestedAuthnContext(class_refs=(saml.REFEDS_MFA,))
```

`comparison` is one of the four methods of SAML 2.0 Core, section 3.3.2.2.1
(`exact` is the default):

| `comparison` | Accepted `AuthnContextClassRef` |
| ------------ | ------------------------------- |
| `exact` | one of `class_refs` |
| `minimum` | one of `class_refs`, or ranked at least as strong as the weakest of them |
| `maximum` | one of `class_refs`, or ranked no stronger than the strongest of them |
| `better` | ranked stronger than every one of `class_refs` |

SAML leaves "stronger" to the parties, so the library only compares strength
where you pass a `ranking`, weakest first. It is never sent to the IdP:

```python
stork = tuple(f"STORK-QAA-Level-{n}" for n in range(1, 5))
substantial = saml.RequestedAuthnContext(
    class_refs=("STORK-QAA-Level-3",), comparison="minimum", ranking=stork
)
```

Without a ranking, `minimum` and `maximum` accept only the requested class
refs, and `better` is rejected when the object is created. Every
`AuthnStatement` in the assertion must satisfy the request; an assertion
without an `AuthnContextClassRef` never does.

## Per login, with `SamlEngine`

Applications that keep their own sessions use the protocol layer directly and
choose the context for each login. Pass the same object to both calls:

```python
engine = saml.SamlEngine(settings)

request_id, redirect_url = await engine.create_authn_request(
    relay_state="/admin", requested_authn_context=mfa
)
# ... remember request_id and that it asked for `mfa`, redirect the browser ...

try:
    identity, in_response_to = await engine.parse_response(
        saml_response, outstanding={request_id: "/admin"}, requested_authn_context=mfa
    )
except saml.AuthnContextError as err:
    ...  # err.requested, err.returned -- answer 403
```

`parse_response()` raises `SamlResponseError` for an invalid response and
`AuthnContextError` for a valid one with an insufficient context. Without
`requested_authn_context`, nothing is checked; the asserted class ref is
available as `identity.authn_context_class` either way.

## For the whole router, with `SamlSP`

```python
sp = saml.SamlSP(settings, requested_authn_context=mfa)
```

Every login the router starts requests the context, and every response at its
ACS -- including IdP-initiated ones -- must satisfy it, otherwise `403`. To offer
logins with different contexts, mount one `SamlSP` per context under its own
`mount_path`, or use `SamlEngine` as above.
