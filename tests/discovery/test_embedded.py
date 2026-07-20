"""IdP enumeration from federation metadata."""

from tests.conftest import build_signed_aggregate

from fastapi_auth.saml.engine.client import SamlEngine
from fastapi_auth.saml.settings import SamlSettings


def test_list_idps_from_aggregate(tmp_path, certs):
    agg = build_signed_aggregate(tmp_path, certs, ["urn:idp:a", "urn:idp:b"])
    s = SamlSettings(
        entity_id="urn:test:sp",
        base_url="https://sp.example",
        key_file=certs["sp_key"],
        cert_file=certs["sp_crt"],
        fixed_idp_entity_id="urn:idp:a",
        metadata_source="aggregate",
        aggregate_file=agg,
        session_secret="x",
    )
    idps = SamlEngine(s).list_idps()
    ids = {c.entity_id for c in idps}
    assert {"urn:idp:a", "urn:idp:b"} <= ids
