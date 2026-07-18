"""SAML engine error types.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations


class SamlResponseError(Exception):
    """A SAML response could not be parsed or failed validation."""


class AttributeReleaseError(Exception):
    """The IdP did not release all attributes this SP marks as mandatory."""

    def __init__(self, missing: list[str]) -> None:
        """Initialize with list of missing attribute friendly names."""
        self.missing = missing
        super().__init__(f"Missing required attributes: {', '.join(missing)}")
