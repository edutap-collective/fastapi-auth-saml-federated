# Look up the IdP's sign-in endpoint

`SamlEngine.idp_sso_url()` returns the `Location` of the IdP's
`SingleSignOnService` from the metadata the engine has loaded -- the URL the
AuthnRequest redirects to. A typical use is the `form-action` directive of a
Content-Security-Policy: an application that starts the login with a form
`POST` and answers with a redirect to the IdP must allow the IdP's origin
there.

```python
from urllib.parse import urlsplit

from fastapi_auth import saml

engine = saml.SamlEngine(settings)

location = urlsplit(engine.idp_sso_url())
idp_origin = f"{location.scheme}://{location.netloc}"
csp = f"form-action 'self' {idp_origin}"
```

Without arguments it looks up `settings.fixed_idp_entity_id` and the
HTTP-Redirect binding, which `create_authn_request` uses. Pass an entity ID
to look up another IdP from a federation aggregate, and `binding=` for
another binding:

```python
from saml2 import BINDING_HTTP_POST

engine.idp_sso_url("https://idp.example.org/idp/shibboleth", binding=BINDING_HTTP_POST)
```

If the metadata does not contain the IdP, or the IdP publishes no
`SingleSignOnService` for that binding, it raises `LookupError`. If several
locations are published for the binding, it returns the first one, which is
the one the AuthnRequest goes to.

The method is synchronous. With `metadata_source="mdq"`, an IdP that is not
cached yet is fetched over the network, so call it at startup -- as the
`SamlEngine` constructor itself does with direct metadata -- or through
`anyio.to_thread.run_sync` on the request path.
