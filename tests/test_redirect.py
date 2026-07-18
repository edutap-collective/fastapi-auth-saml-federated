"""Tests for safe-redirect resolution (local paths + host allowlist)."""

import pytest

from fastapi_auth.saml.redirect import is_safe_redirect


@pytest.mark.parametrize("value", ["/", "/app", "/a/b?x=1"])
def test_local_paths_allowed(value):
    assert is_safe_redirect(value, []) == value


@pytest.mark.parametrize(
    "value", ["//evil.com", "/\\evil.com", "https://evil.com", "\\\\evil.com", "http://x"]
)
def test_unsafe_normalized_to_root(value):
    assert is_safe_redirect(value, []) == "/"


def test_absolute_url_allowed_when_host_in_allowlist():
    assert (
        is_safe_redirect("https://app.lmu.de/dashboard", ["app.lmu.de"])
        == "https://app.lmu.de/dashboard"
    )


def test_absolute_url_rejected_when_host_not_in_allowlist():
    assert is_safe_redirect("https://evil.com/x", ["app.lmu.de"]) == "/"


def test_allowlist_comparison_is_case_insensitive():
    assert is_safe_redirect("https://app.lmu.de/x", ["APP.LMU.DE"]) == "https://app.lmu.de/x"


def test_control_character_in_value_normalized_to_root():
    assert is_safe_redirect("/\t/evil.com", []) == "/"
