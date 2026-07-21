# Accepting IdP-initiated (unsolicited) login

In the normal, **SP-initiated** flow, a user starts at the SP, `GET /login`
redirects them to the IdP with a signed `AuthnRequest`, and the IdP's response
at `POST /acs` carries an `InResponseTo` that matches an outstanding request
the SP itself created. That `InResponseTo`/outstanding-request pair is what
makes the response trustworthy as a *reply* -- it can only be replayed once,
because popping the outstanding request consumes it.

**IdP-initiated (unsolicited) login** is the opposite shape: the user starts
at the IdP or at a portal (a "MyApps"-style tile, an IdP's post-login landing
page, a WAYF that also lists direct IdP-side links), and the IdP POSTs a
signed `AuthnResponse` straight to the SP's `/acs` -- there was no prior
`AuthnRequest`, so the response carries **no `InResponseTo`**. You need this
only if such a portal or IdP-side entry point is part of your deployment;
plain browser-initiated login through `/login` never needs it.

```{warning}
IdP-initiated login is **disabled by default** (`allow_idp_initiated=False`).
Only enable it if you actually have an IdP-initiated entry point -- it removes
the outstanding-request check that normally proves a response is a reply to
something the SP asked for, and replaces it with the safeguards below. Review
each one before turning the flag on:

- **RelayState is attacker-influenced.** The IdP (or a portal issuing the SSO
  request) supplies `RelayState`, and the SP treats it as the post-login
  redirect target. It is always passed through the open-redirect guard
  (`is_safe_redirect`), which only accepts local paths or hosts listed in
  `allowed_redirect_hosts` -- never trust `RelayState` as an absolute URL to
  an arbitrary host. If the IdP sends no `RelayState` at all, the SP falls
  back to `idp_initiated_default_relay_state`.
- **Every unsolicited assertion is single-use.** Because there is no
  outstanding-request to consume, the SP checks each unsolicited assertion's
  ID against a replay cache (`assertion_replay_ttl` seconds) before accepting
  it; a second POST of the same `AuthnResponse` is rejected with `400`.
- **The replay cache must be shared across workers.** With `store="memory"`
  (the default), the cache is an in-process dict -- it does **not** protect
  against replay across multiple worker processes or instances, since each
  process has its own cache. For any deployment with more than one
  worker/process, use `store="redis"` or `store="postgres"` (see
  {doc}`stores`) so all workers check the same cache.
- **Size the TTL to the assertion's validity window.** `assertion_replay_ttl`
  should be at least as long as the assertion's `NotOnOrAfter` validity
  period. If the cache entry expires before the assertion itself does, a
  still-valid assertion could be replayed successfully after the TTL lapses.
```

## Configuration

```python
from fastapi_auth import saml

settings = saml.SamlSettings(
    ...,
    backend="cookie",
    allow_idp_initiated=True,
    idp_initiated_default_relay_state="/dashboard",
    assertion_replay_ttl=300,
    store="redis",
    redis_url="redis://localhost:6379/0",
)
```

`allow_idp_initiated: bool = False`
: Opt-in switch. It maps directly onto pysaml2's `allow_unsolicited` SP
  setting -- with the default `False`, an unsolicited `AuthnResponse` (no
  `InResponseTo`) is rejected by pysaml2 itself and surfaces at `/acs` as
  `400 Bad Request`, exactly like the SP-initiated-only behaviour before this
  feature existed.

`idp_initiated_default_relay_state: str = "/"`
: The landing path used when the IdP sends no `RelayState` with an unsolicited
  response. Still passed through `is_safe_redirect`, so it must be a local
  path (or a path on an `allowed_redirect_hosts` entry).

`assertion_replay_ttl: int = 300`
: The replay-cache window, in seconds, for unsolicited assertions. See the
  sizing guidance in the warning above.

`store` / `redis_url` / `db_url`
: The replay cache lives in the same store used for sessions and outstanding
  requests (`memory`, `redis`, or `postgres`). See {doc}`stores` for how to
  choose and configure one -- the same "shared store for multi-worker
  deployments" rule that applies to sessions applies here too.

With `allow_idp_initiated=False` (the default), none of the above matters:
unsolicited responses are rejected before the replay cache or `RelayState`
handling are ever reached, and the SP behaves exactly as SP-initiated-only.
