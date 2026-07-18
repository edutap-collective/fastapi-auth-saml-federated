"""Tests for entity-category shorthand resolution."""

from fastapi_auth.saml.engine.entity_categories import resolve_entity_categories


def test_known_shorthands_resolve_to_uris():
    result = resolve_entity_categories(["code-of-conduct", "research-and-scholarship"])
    assert all(isinstance(x, str) and x.startswith("http") for x in result)
    assert len(result) >= 2


def test_unknown_value_passed_through():
    assert "https://custom/category" in resolve_entity_categories(["https://custom/category"])


def test_empty():
    assert resolve_entity_categories([]) == []
