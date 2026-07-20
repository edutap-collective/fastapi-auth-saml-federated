"""External Discovery Service protocol URL building + return parsing."""

from urllib.parse import parse_qs, urlparse

from fastapi_auth.saml.discovery.external import ds_redirect_url, parse_ds_return


def test_ds_redirect_url_encodes_params():
    url = ds_redirect_url("https://ds.dfn.de/DS", "urn:test:sp", "https://sp.example/saml/disco")
    q = parse_qs(urlparse(url).query)
    assert q["entityID"] == ["urn:test:sp"]
    assert q["return"] == ["https://sp.example/saml/disco"]


def test_parse_ds_return_reads_entity_id():
    assert parse_ds_return({"entityID": "urn:chosen:idp"}) == "urn:chosen:idp"
    assert parse_ds_return({}) is None
