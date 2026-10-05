"""RequestedAuthnContext: model, SAML element, and validation of the returned class ref."""

import pytest
from pydantic import ValidationError
from saml2 import saml, samlp

from fastapi_auth.saml.engine.authn_context import (
    REFEDS_MFA,
    AuthnContextError,
    RequestedAuthnContext,
    asserted_class_refs,
    check_authn_context,
)

PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
STORK = tuple(f"STORK-QAA-Level-{n}" for n in range(1, 5))


# --- model ---


def test_defaults_to_exact_comparison():
    assert RequestedAuthnContext(class_refs=(REFEDS_MFA,)).comparison == "exact"


def test_requires_at_least_one_class_ref():
    with pytest.raises(ValidationError):
        RequestedAuthnContext(class_refs=())


def test_rejects_blank_class_ref():
    with pytest.raises(ValidationError):
        RequestedAuthnContext(class_refs=(" ",))


def test_rejects_unknown_comparison():
    with pytest.raises(ValidationError):
        RequestedAuthnContext(class_refs=(REFEDS_MFA,), comparison="stronger")  # ty: ignore[invalid-argument-type]


def test_better_requires_a_ranking():
    with pytest.raises(ValidationError, match="ranking"):
        RequestedAuthnContext(class_refs=(STORK[2],), comparison="better")


def test_ranked_class_refs_must_appear_in_ranking():
    with pytest.raises(ValidationError, match="ranking"):
        RequestedAuthnContext(class_refs=(REFEDS_MFA,), comparison="minimum", ranking=STORK)


def test_ranking_must_not_repeat_entries():
    with pytest.raises(ValidationError, match="ranking"):
        RequestedAuthnContext(class_refs=(STORK[0],), ranking=(STORK[0], STORK[0]))


def test_is_immutable():
    rac = RequestedAuthnContext(class_refs=(REFEDS_MFA,))
    with pytest.raises(ValidationError):
        rac.comparison = "minimum"  # ty: ignore[invalid-assignment]


def test_to_saml_builds_the_protocol_element():
    element = RequestedAuthnContext(
        class_refs=(STORK[3],), comparison="minimum", ranking=STORK
    ).to_saml()

    assert isinstance(element, samlp.RequestedAuthnContext)
    assert element.comparison == "minimum"
    assert [ref.text for ref in element.authn_context_class_ref] == [STORK[3]]


# --- exact ---


def test_exact_accepts_a_requested_class_ref():
    rac = RequestedAuthnContext(class_refs=(REFEDS_MFA,))
    check_authn_context(rac, [REFEDS_MFA])


def test_exact_rejects_another_class_ref():
    rac = RequestedAuthnContext(class_refs=(REFEDS_MFA,))
    with pytest.raises(AuthnContextError) as excinfo:
        check_authn_context(rac, [PPT])
    assert excinfo.value.requested is rac
    assert excinfo.value.returned == [PPT]


def test_exact_ignores_a_ranking():
    rac = RequestedAuthnContext(class_refs=(STORK[1],), ranking=STORK)
    with pytest.raises(AuthnContextError):
        check_authn_context(rac, [STORK[3]])


def test_missing_class_ref_is_rejected():
    rac = RequestedAuthnContext(class_refs=(REFEDS_MFA,))
    with pytest.raises(AuthnContextError):
        check_authn_context(rac, [])


def test_every_returned_statement_must_satisfy_the_request():
    rac = RequestedAuthnContext(class_refs=(REFEDS_MFA,))
    with pytest.raises(AuthnContextError):
        check_authn_context(rac, [REFEDS_MFA, PPT])


# --- minimum ---


def test_minimum_without_ranking_accepts_only_the_requested_class_refs():
    rac = RequestedAuthnContext(class_refs=(REFEDS_MFA,), comparison="minimum")
    check_authn_context(rac, [REFEDS_MFA])
    with pytest.raises(AuthnContextError):
        check_authn_context(rac, [PPT])


@pytest.mark.parametrize("returned", [STORK[2], STORK[3]])
def test_minimum_accepts_equal_or_stronger(returned):
    rac = RequestedAuthnContext(class_refs=(STORK[2],), comparison="minimum", ranking=STORK)
    check_authn_context(rac, [returned])


@pytest.mark.parametrize("returned", [STORK[0], STORK[1], "urn:unranked"])
def test_minimum_rejects_weaker_or_unranked(returned):
    rac = RequestedAuthnContext(class_refs=(STORK[2],), comparison="minimum", ranking=STORK)
    with pytest.raises(AuthnContextError):
        check_authn_context(rac, [returned])


def test_minimum_is_measured_against_the_weakest_requested():
    rac = RequestedAuthnContext(
        class_refs=(STORK[3], STORK[1]), comparison="minimum", ranking=STORK
    )
    check_authn_context(rac, [STORK[1]])
    with pytest.raises(AuthnContextError):
        check_authn_context(rac, [STORK[0]])


# --- maximum ---


@pytest.mark.parametrize("returned", [STORK[0], STORK[1]])
def test_maximum_accepts_equal_or_weaker(returned):
    rac = RequestedAuthnContext(class_refs=(STORK[1],), comparison="maximum", ranking=STORK)
    check_authn_context(rac, [returned])


@pytest.mark.parametrize("returned", [STORK[2], "urn:unranked"])
def test_maximum_rejects_stronger_or_unranked(returned):
    rac = RequestedAuthnContext(class_refs=(STORK[1],), comparison="maximum", ranking=STORK)
    with pytest.raises(AuthnContextError):
        check_authn_context(rac, [returned])


# --- better ---


def test_better_accepts_only_strictly_stronger_than_every_requested():
    rac = RequestedAuthnContext(class_refs=(STORK[0], STORK[1]), comparison="better", ranking=STORK)
    check_authn_context(rac, [STORK[2]])
    for returned in (STORK[0], STORK[1], "urn:unranked"):
        with pytest.raises(AuthnContextError):
            check_authn_context(rac, [returned])


# --- asserted_class_refs: read straight from the validated assertion ---


def _assertion(*contexts: saml.AuthnContext | None) -> saml.Assertion:
    return saml.Assertion(
        authn_statement=[
            saml.AuthnStatement(authn_instant="2026-10-05T00:00:00Z", authn_context=context)
            for context in contexts
        ]
    )


def test_asserted_class_refs_reads_each_statement():
    assertion = _assertion(
        saml.AuthnContext(authn_context_class_ref=saml.AuthnContextClassRef(text=REFEDS_MFA)),
        saml.AuthnContext(authn_context_class_ref=saml.AuthnContextClassRef(text=PPT)),
    )
    assert asserted_class_refs(assertion) == [REFEDS_MFA, PPT]


def test_a_declaration_ref_is_not_a_class_ref():
    """pysaml2's authn_info falls back to AuthnContextDeclRef; the check must not."""
    assertion = _assertion(
        saml.AuthnContext(authn_context_decl_ref=saml.AuthnContextDeclRef(text=REFEDS_MFA))
    )
    refs = asserted_class_refs(assertion)
    with pytest.raises(AuthnContextError):
        check_authn_context(RequestedAuthnContext(class_refs=(REFEDS_MFA,)), refs)


def test_a_statement_without_context_is_not_skipped():
    """pysaml2's authn_info drops such statements; the check must see and reject them."""
    assertion = _assertion(
        saml.AuthnContext(authn_context_class_ref=saml.AuthnContextClassRef(text=REFEDS_MFA)),
        None,
    )
    refs = asserted_class_refs(assertion)
    with pytest.raises(AuthnContextError):
        check_authn_context(RequestedAuthnContext(class_refs=(REFEDS_MFA,)), refs)


def test_no_assertion_yields_no_class_refs():
    assert asserted_class_refs(None) == []


def test_ranking_rejects_blank_entries():
    with pytest.raises(ValidationError, match="ranking"):
        RequestedAuthnContext(class_refs=(STORK[0],), ranking=(STORK[0], ""))
