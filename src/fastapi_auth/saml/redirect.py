"""Resolve a post-login redirect target safely (open-redirect protection).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from urllib.parse import urlparse


def is_safe_redirect(value: str, allowed_hosts: list[str]) -> str:
    r"""Return value if it is a safe local path or an allow-listed absolute URL, else '/'.

    Local paths must be single-slash-prefixed and must not start with '//' or '/\\'
    (both resolve to a cross-origin URL in browsers). Values containing ASCII
    control characters are rejected outright (defense in depth against
    header/response-splitting or smuggling tricks upstream parsers might miss).
    """
    if any(ord(c) < 0x20 for c in value):
        return "/"
    if value.startswith("/") and not value.startswith(("//", "/\\")):
        return value
    parsed = urlparse(value)
    allowed_hosts_lower = {h.lower() for h in allowed_hosts}
    if parsed.scheme in ("http", "https") and parsed.hostname in allowed_hosts_lower:
        return value
    return "/"
