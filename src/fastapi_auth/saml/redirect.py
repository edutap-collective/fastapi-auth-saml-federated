"""Resolve a post-login redirect target safely (open-redirect protection).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from urllib.parse import urlparse


def is_safe_redirect(value: str, allowed_hosts: list[str]) -> str:
    r"""Return value if it is a safe local path or an allow-listed absolute URL, else '/'.

    Local paths must be single-slash-prefixed and must not start with '//' or '/\\'
    (both resolve to a cross-origin URL in browsers).
    """
    if value.startswith("/") and not value.startswith(("//", "/\\")):
        return value
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.hostname in allowed_hosts:
        return value
    return "/"
