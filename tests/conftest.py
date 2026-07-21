"""Shared test fixtures: test certs and an in-memory pysaml2 IdP."""

import base64
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import IdPConfig
from saml2.metadata import create_metadata_string, entities_descriptor, entity_descriptor
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NameID
from saml2.server import Server

# Sentinel distinguishing "caller omitted in_response_to" (-> use request_id, the
# existing behavior) from an explicit `in_response_to=None` (-> mint an unsolicited
# response, omitting InResponseTo). `Any` keeps ty happy as a default for `str | None`.
_UNSET: Any = object()

SP_EID = "urn:test:sp"
IDP_EID = "urn:test:idp"
ACS = "https://sp.example/saml/acs"
SSO = "https://idp.example/sso"
SLO = "https://idp.example/slo"

# Resolved once from PATH so tests don't depend on a hardcoded (e.g. Homebrew-only)
# install location; tests that need them are skipped if not found.
_OPENSSL_BIN = shutil.which("openssl")
_XMLSEC1_BIN = shutil.which("xmlsec1")


def _make_cert(path_key: Path, path_crt: Path, cn: str) -> None:
    assert _OPENSSL_BIN is not None  # narrows for ty; certs() fixture already skipped otherwise
    subprocess.run(  # noqa: S603
        [
            _OPENSSL_BIN,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(path_key),
            "-out",
            str(path_crt),
            "-days",
            "2",
            "-subj",
            f"/CN={cn}",
        ],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def certs(tmp_path):
    if _OPENSSL_BIN is None:
        pytest.skip("openssl binary not found on PATH; required to mint test certificates")
    d = tmp_path / "certs"
    d.mkdir()
    idp_key, idp_crt = d / "idp.key", d / "idp.crt"
    sp_key, sp_crt = d / "sp.key", d / "sp.crt"
    _make_cert(idp_key, idp_crt, "test-idp")
    _make_cert(sp_key, sp_crt, "test-sp")
    return {
        "idp_key": str(idp_key),
        "idp_crt": str(idp_crt),
        "sp_key": str(sp_key),
        "sp_crt": str(sp_crt),
    }


@pytest.fixture
def idp_metadata_file(tmp_path, certs):
    idp_cfg = IdPConfig().load(
        {
            "entityid": IDP_EID,
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)],
                        "single_logout_service": [(SLO, BINDING_HTTP_REDIRECT)],
                    }
                }
            },
            "key_file": certs["idp_key"],
            "cert_file": certs["idp_crt"],
        }
    )
    md = create_metadata_string(None, config=idp_cfg, sign=False).decode()
    path = tmp_path / "idp-metadata.xml"
    path.write_text(md)
    return str(path)


def build_signed_aggregate(tmp_path: Path, certs: dict[str, str], entity_ids: list[str]) -> str:
    """Build an ``<EntitiesDescriptor>`` aggregating one IdP per ``entity_ids``, written to a file.

    Used to exercise the ``aggregate``/``local`` metadata source against a
    realistic multi-IdP federation document. Each IdP gets a minimal
    single-sign-on-service endpoint and the shared test IdP key/cert. The
    aggregate is written unsigned: pysaml2's ``local`` metadata source does
    not verify signatures, and this helper only needs to support IdP
    enumeration via ``SPConfig().load(...).metadata.identity_providers()``.
    """
    entity_descriptors = []
    for entity_id in entity_ids:
        idp_cfg = IdPConfig().load(
            {
                "entityid": entity_id,
                "service": {
                    "idp": {"endpoints": {"single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)]}}
                },
                "key_file": certs["idp_key"],
                "cert_file": certs["idp_crt"],
            }
        )
        entity_descriptors.append(entity_descriptor(idp_cfg))

    entities, _xmldoc = entities_descriptor(
        entity_descriptors, valid_for=0, name=None, ident=None, sign=False, secc=None
    )
    xml = entities.to_string({"xs": "http://www.w3.org/2001/XMLSchema"}).decode()
    path = tmp_path / "aggregate.xml"
    path.write_text(xml)
    return str(path)


@pytest.fixture
def signed_idp_metadata(certs):
    """Return signed IdP metadata XML for ``IDP_EID``, signed with the IdP's own key.

    The self-signed ``certs["idp_crt"]`` is both the signer and, in MDQ tests,
    the configured trust anchor -- so a successful signature check here proves
    the fetched document really came from (and was validated against) that
    trust anchor.
    """
    if _XMLSEC1_BIN is None:
        pytest.skip("xmlsec1 binary not found on PATH; required for pysaml2 signing")
    idp_cfg = IdPConfig().load(
        {
            "entityid": IDP_EID,
            "xmlsec_binary": _XMLSEC1_BIN,
            "service": {
                "idp": {"endpoints": {"single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)]}}
            },
            "key_file": certs["idp_key"],
            "cert_file": certs["idp_crt"],
        }
    )
    md = create_metadata_string(
        None, config=idp_cfg, sign=True, keyfile=certs["idp_key"], cert=certs["idp_crt"]
    )
    return md.decode() if isinstance(md, bytes) else md


@pytest.fixture
def make_idp(certs):
    """Return a factory that builds an in-memory IdP Server bound to given SP metadata."""
    if _XMLSEC1_BIN is None:
        pytest.skip("xmlsec1 binary not found on PATH; required for pysaml2 signing")

    def _factory(sp_metadata_xml: str) -> Server:
        idp_cfg = {
            "entityid": IDP_EID,
            "xmlsec_binary": _XMLSEC1_BIN,
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [(SSO, BINDING_HTTP_REDIRECT)],
                        "single_logout_service": [(SLO, BINDING_HTTP_REDIRECT)],
                    }
                }
            },
            "key_file": certs["idp_key"],
            "cert_file": certs["idp_crt"],
            "metadata": {"inline": [sp_metadata_xml]},
        }
        return Server(config=IdPConfig().load(idp_cfg))

    return _factory


def mint_response(
    idp: Server,
    request_id: str,
    ava: dict[str, list[str]],
    name_id_text: str = "u123-persistent",
    *,
    sign_response: bool = True,
    sign_assertion: bool = True,
    encrypt_cert: str | None = None,
    in_response_to: str | None = _UNSET,
) -> str:
    """Mint a base64 SAML response as an IdP would POST to the ACS.

    ``sign_response``/``sign_assertion`` default to ``True`` (a properly signed
    response); pass ``False`` to mint an unsigned one for negative tests.
    ``encrypt_cert`` defaults to ``None`` (unencrypted assertion); pass the
    SP's encryption certificate PEM to mint an ``EncryptedAssertion`` instead.
    ``in_response_to`` defaults to ``request_id`` (a solicited response); pass
    ``in_response_to=None`` explicitly to mint an unsolicited (IdP-initiated)
    response, which omits the ``InResponseTo`` attribute entirely. Passing an
    empty string instead of ``None`` breaks pysaml2's XSD validation, so this
    is not exposed -- only ``None`` or the default.
    """
    resolved_in_response_to = request_id if in_response_to is _UNSET else in_response_to
    name_id = NameID(format=NAMEID_FORMAT_PERSISTENT, text=name_id_text)
    extra_kwargs: dict[str, Any] = {}
    if encrypt_cert is not None:
        extra_kwargs["encrypt_assertion"] = True
        extra_kwargs["encrypt_cert_assertion"] = encrypt_cert
    xml = idp.create_authn_response(
        identity=ava,
        in_response_to=resolved_in_response_to,
        destination=ACS,
        sp_entity_id=SP_EID,
        name_id=name_id,
        sign_response=sign_response,
        sign_assertion=sign_assertion,
        authn={
            "class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "authn_auth": IDP_EID,
        },
        **extra_kwargs,
    )
    # pysaml2 only returns a plain string when a signing step ran (it hands back
    # the signed_instance_factory output); an entirely unsigned response comes
    # back as the samlp.Response object itself, so normalize before encoding.
    xml_str = xml if isinstance(xml, str) else str(xml)
    return base64.b64encode(xml_str.encode()).decode()
