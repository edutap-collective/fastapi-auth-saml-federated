"""MDQ metadata source: per-entity signed fetch, mocked with `responses`."""

import hashlib

import responses

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.settings import SamlSettings


def _sha1_transform(entity_id: str) -> str:
    return "{sha1}" + hashlib.sha1(entity_id.encode()).hexdigest()  # noqa: S324 - MDQ spec mandates sha1


@responses.activate
def test_mdq_fetches_and_validates_signed_idp(tmp_path, certs, signed_idp_metadata):
    idp_eid = "urn:test:idp"
    mdq_url = "https://mdq.example"
    responses.add(
        responses.GET,
        f"{mdq_url}/entities/{_sha1_transform(idp_eid)}",
        body=signed_idp_metadata,  # signed EntityDescriptor bytes/str, signer = trust anchor
        content_type="application/samlmetadata+xml",
        status=200,
    )
    s = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        fixed_idp_entity_id=idp_eid,
        metadata_source="mdq",
        mdq_url=mdq_url,
        trust_anchor_cert=certs["idp_crt"],
        session_secret="x",
    )
    engine = SamlEngine(s)
    # A successful create_authn_request proves the IdP metadata was fetched+validated via MDQ.
    reqid, location = engine._prepare("/app", idp_eid)  # sync helper; MDQ fetch happens on demand
    assert location.startswith("https://idp")  # IdP SSO location from fetched metadata
