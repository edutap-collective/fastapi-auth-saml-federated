"""Resolve entity-category shorthands to their canonical URIs.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from saml2.entity_category.edugain import COC
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP


def _flatten(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_flatten(item))
        return out
    return [str(value)]


_SHORTHANDS: dict[str, list[str]] = {
    "code-of-conduct": _flatten(COC),
    "research-and-scholarship": _flatten(RESEARCH_AND_SCHOLARSHIP),
    "refeds-rs": _flatten(RESEARCH_AND_SCHOLARSHIP),
}


def resolve_entity_categories(shorthands: list[str]) -> list[str]:
    """Map known shorthands to category URIs; pass unknown values through."""
    result: list[str] = []
    for name in shorthands:
        result.extend(_SHORTHANDS.get(name, [name]))
    return result
