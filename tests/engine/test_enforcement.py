"""Tests for mandatory-attribute enforcement."""

import pytest

from fastapi_auth.saml.engine.enforcement import check_required_attributes
from fastapi_auth.saml.engine.errors import AttributeReleaseError
from fastapi_auth.saml.identity.model import FederatedIdentity


def test_passes_when_all_required_present():
    ident = FederatedIdentity(eppn="u@lmu.de", mail=["u@lmu.de"])
    check_required_attributes(ident, ["eduPersonPrincipalName", "mail"])  # no raise


def test_raises_with_missing_list():
    ident = FederatedIdentity(eppn="u@lmu.de")  # no mail
    with pytest.raises(AttributeReleaseError) as exc:
        check_required_attributes(ident, ["eduPersonPrincipalName", "mail"])
    assert "mail" in exc.value.missing


def test_empty_required_always_passes():
    check_required_attributes(FederatedIdentity(), [])  # no raise


def test_empty_list_value_counts_as_missing():
    ident = FederatedIdentity(eppn="u@lmu.de", mail=[])
    with pytest.raises(AttributeReleaseError):
        check_required_attributes(ident, ["mail"])
