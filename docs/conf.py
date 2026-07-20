"""Sphinx configuration for the fastapi-auth-saml-federated documentation.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

project = "fastapi-auth-saml-federated"
author = "Alexander Loechel"
copyright = f"2026, {author}"  # noqa: A001 - Sphinx-mandated config name

extensions = ["myst_parser"]

source_suffix = {".md": "markdown"}

# `docs/superpowers/` holds the internal SDD planning artifacts (specs, plans,
# task briefs) used to build this package. They are not part of the published
# documentation, so they must not be picked up as Sphinx source documents.
exclude_patterns = ["_build", "superpowers", "Thumbs.db", ".DS_Store"]

html_theme = "furo"
