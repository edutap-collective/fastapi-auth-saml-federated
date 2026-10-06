# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-10-06

### Added

- `SamlEngine.idp_sso_url(idp_entity_id=None, *, binding=HTTP-Redirect)`
  returns the IdP's `SingleSignOnService` location from the loaded metadata,
  for example for a Content-Security-Policy `form-action`. Raises
  `LookupError` for an unknown IdP or a binding it does not offer.
- `SamlSettings.want_response_signed` (`SAML_WANT_RESPONSE_SIGNED`, default
  `False`). Together with `want_assertions_signed` it selects the required
  IdP signature: on the assertion (default, unchanged), on the response, or
  on both.

### Changed

- `SamlSettings` refuses `want_assertions_signed=False` unless
  `want_response_signed=True`, and so does `SamlEngine` for settings changed
  after creation. Before, that combination accepted SAML responses in which
  nothing was signed.

## [0.3.0] - 2026-10-06

### Added

- `SamlEngine.create_authn_request(..., extensions=)` puts namespaced XML
  elements into `<samlp:Extensions>` of that one AuthnRequest, signed with
  it. Accepts pysaml2 `ExtensionElement` objects or any
  `AuthnRequestExtension` (an object with `to_extension_element()`);
  `extension_element_from_xml()` parses one from a string.
- `SamlEngine.parse_response_details()` validates like `parse_response()`
  and returns a `ParsedAuthnResponse` with the identity, `in_response_to` and
  every `<saml:Attribute>` as a `SamlAttribute`, XML attributes included.
- `fastapi_auth.saml.akdb` for BundID: `AuthenticationRequest` (requested
  attributes by OID, `DisplayInformation`, optional `AuthnMethods`),
  `trust_level()` and the ordered `TrustLevel` for `akdb:TrustLevel`,
  `STORK_QAA_LEVELS` as a `RequestedAuthnContext` ranking, and `BPK2`.

`parse_response()` and `FederatedIdentity` are unchanged.

## [0.2.0] - 2026-10-06

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

[0.3.1]: https://github.com/edutap-collective/fastapi-auth-saml-federated/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/edutap-collective/fastapi-auth-saml-federated/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/edutap-collective/fastapi-auth-saml-federated/compare/22f5ff9...v0.2.0
