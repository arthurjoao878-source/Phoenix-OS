from __future__ import annotations

from dataclasses import replace
from uuid import UUID

from phoenix_os.authority import AuthoritySubject, authority_subject_fingerprint
from phoenix_os.policy import PrincipalType, SecurityContext

_SESSION = UUID("10000000-0000-4000-8000-000000000033")
_OTHER_SESSION = UUID("20000000-0000-4000-8000-000000000033")


def test_structural_session_identity_is_distinct_from_untrusted_attributes() -> None:
    context = SecurityContext(
        principal="arthur",
        principal_type=PrincipalType.USER,
        authenticated=True,
        session_id=_SESSION,
        attributes={"session_id": str(_OTHER_SESSION)},
    )
    assert context.session_id == _SESSION
    assert context.attributes["session_id"] == str(_OTHER_SESSION)


def test_session_agent_and_run_substitution_change_authority_subject() -> None:
    base = AuthoritySubject(
        principal_type=PrincipalType.USER,
        principal="arthur",
        session_id=_SESSION,
        agent_id="parent",
        run_id="run-a",
    )
    substitutions = (
        replace(base, session_id=_OTHER_SESSION),
        replace(base, agent_id="child"),
        replace(base, run_id="run-b"),
    )
    base_fingerprint = authority_subject_fingerprint(base)
    assert all(
        authority_subject_fingerprint(candidate) != base_fingerprint for candidate in substitutions
    )


def test_cross_agent_authority_borrowing_has_no_subject_equivalence() -> None:
    parent = AuthoritySubject(
        principal_type=PrincipalType.SERVICE,
        principal="service:requester",
        agent_id="parent",
        run_id="parent-run",
    )
    child = replace(parent, agent_id="child", run_id="child-run")
    assert authority_subject_fingerprint(parent) != authority_subject_fingerprint(child)
