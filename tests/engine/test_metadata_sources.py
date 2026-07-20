# SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""build_metadata_config emits the right pysaml2 metadata dict per source."""

from typing import Any

from saml2.config import SPConfig

from fastapi_auth.saml.engine.config import build_metadata_config, build_sp_config
from fastapi_auth.saml.settings import SamlSettings

_SP: dict[str, Any] = dict(
    entity_id="urn:test:sp", base_url="https://sp.example", key_file="/tmp/k", cert_file="/tmp/c"
)


def test_direct_source_is_inline(tmp_path):
    md = tmp_path / "idp.xml"
    md.write_text('<EntityDescriptor entityID="urn:test:idp"/>')
    s = SamlSettings(
        **_SP, fixed_idp_entity_id="urn:test:idp", idp_metadata_file=str(md), session_secret="x"
    )
    assert "inline" in build_metadata_config(s)


def test_aggregate_file_is_local(tmp_path):
    agg = tmp_path / "agg.xml"
    agg.write_text("<x/>")
    s = SamlSettings(
        **_SP,
        fixed_idp_entity_id="urn:i",
        metadata_source="aggregate",
        aggregate_file=str(agg),
        session_secret="x",
    )
    assert build_metadata_config(s) == {"local": [str(agg)]}


def test_aggregate_url_is_remote_with_cert():
    s = SamlSettings(
        **_SP,
        fixed_idp_entity_id="urn:i",
        metadata_source="aggregate",
        aggregate_url="https://md.dfn.de/agg.xml",
        trust_anchor_cert="/tmp/ta.pem",
        session_secret="x",
    )
    assert build_metadata_config(s) == {
        "remote": [{"url": "https://md.dfn.de/agg.xml", "cert": "/tmp/ta.pem"}]
    }


def test_mdq_is_mdq_with_cert():
    s = SamlSettings(
        **_SP,
        fixed_idp_entity_id="urn:i",
        metadata_source="mdq",
        mdq_url="https://mdq.dfn.de",
        trust_anchor_cert="/tmp/ta.pem",
        session_secret="x",
    )
    assert build_metadata_config(s) == {
        "mdq": [{"url": "https://mdq.dfn.de", "cert": "/tmp/ta.pem"}]
    }


def test_aggregate_local_loads_multi_idp_in_pysaml2(tmp_path, certs):
    # Build a real signed aggregate of two IdPs and confirm SPConfig loads it.
    from tests.conftest import build_signed_aggregate  # helper added in this task

    agg = build_signed_aggregate(tmp_path, certs, ["urn:idp:a", "urn:idp:b"])
    s = SamlSettings(
        **{**_SP, "key_file": certs["sp_key"], "cert_file": certs["sp_crt"]},
        fixed_idp_entity_id="urn:idp:a",
        metadata_source="aggregate",
        aggregate_file=agg,
        session_secret="x",
    )
    cfg = SPConfig().load(build_sp_config(s))
    idps = cfg.metadata.identity_providers()
    assert "urn:idp:a" in idps and "urn:idp:b" in idps
