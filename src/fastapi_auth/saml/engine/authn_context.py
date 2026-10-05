"""Requested authentication context: build ``<samlp:RequestedAuthnContext>`` and check the result.

SAML 2.0 Core, section 3.3.2.2.1, defines four comparison methods for a
``RequestedAuthnContext``:

``exact``
    the asserted context must be one of the requested contexts;
``minimum``
    at least as strong as one of them;
``maximum``
    as strong as possible without exceeding the strength of at least one of them;
``better``
    stronger than any one of them.

What "stronger" means is left to requester and responder. This module
therefore never guesses: an ordering exists only where the caller supplies
one via ``ranking`` (weakest first, e.g. ``STORK-QAA-Level-1`` to ``-4``).
Without a ranking, ``minimum`` and ``maximum`` accept exactly the requested
class refs -- an unknown class ref can never be proven strong enough.

pysaml2 sends the request but leaves checking the returned
``AuthnContextClassRef`` to the caller; :func:`check_authn_context` is that check.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from saml2 import samlp
from saml2.saml import AuthnContextClassRef

#: REFEDS Multi-Factor Authentication Profile, https://refeds.org/profile/mfa
REFEDS_MFA = "https://refeds.org/profile/mfa"

Comparison = Literal["exact", "minimum", "maximum", "better"]


class RequestedAuthnContext(BaseModel):
    """The authentication context one login asks the IdP for.

    ``class_refs`` are the requested ``AuthnContextClassRef`` URIs,
    ``comparison`` the SAML comparison method. ``ranking`` optionally orders
    class refs from weakest to strongest; it is never sent to the IdP and is
    only used to evaluate ``minimum``, ``maximum`` and ``better``.
    """

    model_config = ConfigDict(frozen=True)

    class_refs: tuple[str, ...] = Field(min_length=1)
    comparison: Comparison = "exact"
    ranking: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_consistency(self) -> RequestedAuthnContext:
        """Reject blank class refs and rankings that cannot evaluate the comparison."""
        if any(not ref.strip() for ref in self.class_refs):
            msg = "class_refs must not contain blank entries"
            raise ValueError(msg)
        if len(set(self.ranking)) != len(self.ranking):
            msg = "ranking must not contain duplicate entries"
            raise ValueError(msg)
        if self.comparison == "better" and not self.ranking:
            msg = "comparison='better' requires a ranking (weakest first)"
            raise ValueError(msg)
        if self.ranking:
            unranked = [ref for ref in self.class_refs if ref not in self.ranking]
            if unranked:
                msg = f"class_refs missing from ranking: {', '.join(unranked)}"
                raise ValueError(msg)
        return self

    def to_saml(self) -> samlp.RequestedAuthnContext:
        """Return the pysaml2 protocol element for the AuthnRequest."""
        return samlp.RequestedAuthnContext(
            authn_context_class_ref=[AuthnContextClassRef(text=ref) for ref in self.class_refs],
            comparison=self.comparison,
        )

    def is_satisfied_by(self, class_ref: str) -> bool:
        """Return whether one asserted ``AuthnContextClassRef`` satisfies this request."""
        if self.comparison == "exact":
            return class_ref in self.class_refs
        if class_ref in self.class_refs and self.comparison != "better":
            return True
        if class_ref not in self.ranking:
            return False
        rank = self.ranking.index(class_ref)
        requested_ranks = [self.ranking.index(ref) for ref in self.class_refs]
        if self.comparison == "minimum":
            return rank >= min(requested_ranks)
        if self.comparison == "maximum":
            return rank <= max(requested_ranks)
        return rank > max(requested_ranks)  # better: stronger than every requested one


class AuthnContextError(Exception):
    """The IdP asserted an authentication context that does not satisfy the request."""

    def __init__(self, requested: RequestedAuthnContext, returned: list[str]) -> None:
        """Initialize with the request and the class refs the assertion actually carried."""
        self.requested = requested
        self.returned = returned
        asserted = ", ".join(returned) if returned else "none"
        super().__init__(
            f"Authentication context {asserted} does not satisfy "
            f"{requested.comparison} {', '.join(requested.class_refs)}"
        )


def check_authn_context(requested: RequestedAuthnContext, returned: Sequence[str]) -> None:
    """Raise :class:`AuthnContextError` unless every returned class ref satisfies ``requested``.

    ``returned`` holds the ``AuthnContextClassRef`` of each ``AuthnStatement``
    in the assertion. An assertion without any class ref is rejected, and so
    is one in which any statement falls short -- the caller cannot know which
    statement a consumer will rely on.
    """
    returned_list = list(returned)
    if not returned_list or not all(requested.is_satisfied_by(ref) for ref in returned_list):
        raise AuthnContextError(requested, returned_list)
