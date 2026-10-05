# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - unreleased

First release on PyPI.

### Added

- `RequestedAuthnContext` (class refs, SAML comparison `exact`/`minimum`/
  `maximum`/`better`, optional weakest-first `ranking`) and the `REFEDS_MFA`
  constant.
- `SamlEngine.create_authn_request(..., requested_authn_context=)` sends a
  `<samlp:RequestedAuthnContext>` with that one request.
- `SamlEngine.parse_response(..., requested_authn_context=)` checks the
  asserted `AuthnContextClassRef` and raises the new `AuthnContextError`.
- `SamlSP(settings, requested_authn_context=)` requests the context on every
  router login and enforces it at the ACS, solicited or IdP-initiated
  (`403` on mismatch).
- `SamlSP.logout_csrf_token(request)` and `SamlSettings.slo_path` for
  application-rendered logout forms.
- `SamlEngine` is exported from `fastapi_auth.saml`.

### Changed

- **Breaking:** `GET {mount_path}/slo` no longer logs out. It renders a
  confirmation form; logout is `POST {mount_path}/slo` with a `csrf_token`
  bound to the session cookie (#15). `GET {mount_path}/slo/return` is
  unchanged.

### Fixed

- Logout CSRF: any cross-site link could end the session and start IdP
  Single Logout (#15).
- `[project.urls] Repository` pointed to a non-existent repository (#16).

## [0.1.0.dev0]

Development version, never published.

[0.2.0]: https://github.com/edutap-collective/fastapi-auth-saml-federated/compare/22f5ff9...v0.2.0
