# Log out safely

Logging out ends the local session and, if the IdP advertises a Single Logout
Service, starts SAML Single Logout towards it. Because that changes state, it
is a `POST` protected against cross-site request forgery (CSRF).

## The endpoints

`GET {mount_path}/slo`
: Changes nothing. With an active session it renders a small confirmation page
  whose form `POST`s back with a CSRF token; without a session it redirects to
  `next`. A plain link to `/saml/slo` therefore keeps working, with one extra
  click.

`POST {mount_path}/slo`
: Form fields `csrf_token` and `next`. If the request carries a session cookie,
  the token must match that cookie, otherwise the answer is `403`. On success
  the local session is always revoked, and the browser is sent to the IdP's
  logout endpoint or, if there is none, to `next`. The confirmation page refuses
  to be framed (`X-Frame-Options: DENY`, `frame-ancestors 'none'`).

`GET {mount_path}/slo/return`
: The SP's `SingleLogoutService` (HTTP-Redirect binding) as published in its
  metadata. The IdP sends the `LogoutResponse` here; it is unchanged.

## Your own logout button

Render a form that posts to the SLO endpoint and carries the token from
`sp.logout_csrf_token(request)`:

```python
from fastapi import Request
from fastapi.responses import HTMLResponse


@app.get("/account", response_class=HTMLResponse)
async def account(request: Request) -> str:
    token = sp.logout_csrf_token(request)
    if token is None:  # no session cookie: nothing to log out of
        return '<a href="/saml/login">Log in</a>'
    return f"""
      <form method="post" action="{sp.settings.slo_path}">
        <input type="hidden" name="csrf_token" value="{token}">
        <button>Log out</button>
      </form>
    """
```

The token is an HMAC of the session cookie under `session_secret`. It needs no
server-side storage, is useless for any other session, and changes with every
login. `logout_csrf_token()` returns `None` when there is no session cookie.

## Why

A `GET` that logs out can be triggered by any other site: a link, an image or a
redirect is enough, and the `SameSite=Lax` session cookie is sent along on
top-level navigations. See the
[OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
