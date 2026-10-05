"""Smoke tests for the package scaffold and namespace layout."""

from importlib.metadata import version

import fastapi_auth.saml as saml


def test_package_imports_via_namespace():
    assert saml.__version__ == "0.2.0"


def test_version_matches_distribution_metadata():
    assert saml.__version__ == version("fastapi-auth-saml-federated")


def test_namespace_has_no_init_module():
    import fastapi_auth

    # PEP 420 namespace packages expose no single __file__.
    assert getattr(fastapi_auth, "__file__", None) is None
