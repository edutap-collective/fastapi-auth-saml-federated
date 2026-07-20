"""IdP enumeration from federation metadata and embedded WAYF rendering."""

from pathlib import Path
from urllib.parse import quote

from jinja2 import Environment, FileSystemLoader, select_autoescape
from tests.conftest import build_signed_aggregate

from fastapi_auth.saml.discovery.embedded import render_wayf
from fastapi_auth.saml.engine.client import IdPChoice, SamlEngine
from fastapi_auth.saml.settings import SamlSettings

TEMPLATES_DIR = Path(__file__).parents[2] / "src" / "fastapi_auth" / "saml" / "wayf" / "templates"


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


def test_render_wayf_lists_idps_with_encoded_links():
    idps = [
        IdPChoice(entity_id="urn:idp:a", display_name="IdP A"),
        IdPChoice(entity_id="urn:idp:b & Co", display_name="IdP <B>"),
    ]
    jinja_env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(),
    )

    html = render_wayf(idps, "/saml/login", "https://sp.example/after", jinja_env)

    assert "IdP A" in html
    # Untrusted display name must be escaped, not injected raw.
    assert "<B>" not in html
    # HTML-autoescaped: '&' between query params becomes '&amp;' in the attribute.
    assert f"/saml/login?idp={quote('urn:idp:a', safe='')}&amp;next=" in html
    assert f"/saml/login?idp={quote('urn:idp:b & Co', safe='')}&amp;next=" in html
    assert quote("https://sp.example/after", safe="") in html
