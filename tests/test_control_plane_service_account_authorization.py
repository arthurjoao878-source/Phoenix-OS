from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneServiceAccountAuthorization,
    ControlPlaneServiceAccountAuthorizer,
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
)

_NOW = datetime(
    2026,
    7,
    20,
    12,
    tzinfo=UTC,
)
_JOB_ID = UUID("20000000-0000-0000-0000-000000000001")
_WORKFLOW_ID = UUID("30000000-0000-0000-0000-000000000001")


def _authentication(
    *,
    scopes: frozenset[str],
    resources: frozenset[str],
) -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=UUID("10000000-0000-0000-0000-000000000001"),
        token_id=UUID("10000000-0000-0000-0000-000000000002"),
        account_name="release.bot",
        scopes=scopes,
        resources=resources,
        token_version=1,
        account_revision=1,
        token_revision=1,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )


def test_exact_action_and_resource_are_allowed() -> None:
    authentication = _authentication(
        scopes=frozenset(
            {
                "jobs.read",
                "job.cancel",
            }
        ),
        resources=frozenset(
            {
                f"job:{_JOB_ID}",
            }
        ),
    )
    authorizer = ControlPlaneServiceAccountAuthorizer()

    decision = authorizer.decide(
        authentication,
        action="job.cancel",
        resource=f"job:{_JOB_ID}",
    )

    assert decision == (
        ControlPlaneServiceAccountAuthorization(
            action="job.cancel",
            resource=f"job:{_JOB_ID}",
            allowed=True,
        )
    )


@pytest.mark.parametrize(
    "action",
    [
        "job",
        "job.cancel.extra",
        "jobs.cancel",
    ],
)
def test_action_scope_requires_exact_match(
    action: str,
) -> None:
    authentication = _authentication(
        scopes=frozenset({"job.cancel"}),
        resources=frozenset({"*"}),
    )

    decision = ControlPlaneServiceAccountAuthorizer().decide(
        authentication,
        action=action,
        resource=f"job:{_JOB_ID}",
    )

    assert not decision.allowed


@pytest.mark.parametrize(
    "action",
    [
        " Job.cancel",
        "Job.cancel",
        "job.cancel ",
        "job.*",
        "job cancel",
    ],
)
def test_action_request_must_be_canonical(
    action: str,
) -> None:
    authentication = _authentication(
        scopes=frozenset({"job.cancel"}),
        resources=frozenset({"*"}),
    )

    with pytest.raises(
        ValueError,
        match="canonical",
    ):
        ControlPlaneServiceAccountAuthorizer().decide(
            authentication,
            action=action,
            resource=f"job:{_JOB_ID}",
        )


def test_global_resource_grant_allows_any_concrete_resource() -> None:
    authentication = _authentication(
        scopes=frozenset({"jobs.read"}),
        resources=frozenset({"*"}),
    )
    authorizer = ControlPlaneServiceAccountAuthorizer()

    assert authorizer.decide(
        authentication,
        action="jobs.read",
        resource=f"job:{_JOB_ID}",
    ).allowed

    assert authorizer.decide(
        authentication,
        action="jobs.read",
        resource=(f"workflow:{_WORKFLOW_ID}"),
    ).allowed


def test_namespace_wildcard_is_bounded_to_resource_kind() -> None:
    authentication = _authentication(
        scopes=frozenset({"jobs.read"}),
        resources=frozenset({"job:*"}),
    )
    authorizer = ControlPlaneServiceAccountAuthorizer()

    assert authorizer.decide(
        authentication,
        action="jobs.read",
        resource=f"job:{_JOB_ID}",
    ).allowed

    assert not authorizer.decide(
        authentication,
        action="jobs.read",
        resource=(f"workflow:{_WORKFLOW_ID}"),
    ).allowed


def test_exact_resource_matching_is_case_sensitive() -> None:
    authentication = _authentication(
        scopes=frozenset({"jobs.create"}),
        resources=frozenset(
            {
                "capability:Backup.Database",
            }
        ),
    )
    authorizer = ControlPlaneServiceAccountAuthorizer()

    assert authorizer.decide(
        authentication,
        action="jobs.create",
        resource="capability:Backup.Database",
    ).allowed

    assert not authorizer.decide(
        authentication,
        action="jobs.create",
        resource="capability:backup.database",
    ).allowed


def test_unsupported_partial_wildcard_never_matches() -> None:
    authentication = _authentication(
        scopes=frozenset({"jobs.read"}),
        resources=frozenset(
            {
                "job:20000000*",
            }
        ),
    )

    decision = ControlPlaneServiceAccountAuthorizer().decide(
        authentication,
        action="jobs.read",
        resource=f"job:{_JOB_ID}",
    )

    assert not decision.allowed


@pytest.mark.parametrize(
    "resource",
    [
        "*",
        "job:*",
        "job:",
        " job:123",
        "job:123 ",
        "",
    ],
)
def test_requested_resource_must_be_concrete(
    resource: str,
) -> None:
    authentication = _authentication(
        scopes=frozenset({"jobs.read"}),
        resources=frozenset({"*"}),
    )

    with pytest.raises(
        ValueError,
        match="concrete resource",
    ):
        ControlPlaneServiceAccountAuthorizer().decide(
            authentication,
            action="jobs.read",
            resource=resource,
        )


def test_missing_scope_denies_even_when_resource_matches() -> None:
    authentication = _authentication(
        scopes=frozenset({"jobs.read"}),
        resources=frozenset(
            {
                f"job:{_JOB_ID}",
            }
        ),
    )

    decision = ControlPlaneServiceAccountAuthorizer().decide(
        authentication,
        action="job.cancel",
        resource=f"job:{_JOB_ID}",
    )

    assert not decision.allowed


def test_missing_resource_denies_even_when_scope_matches() -> None:
    authentication = _authentication(
        scopes=frozenset({"job.cancel"}),
        resources=frozenset(
            {
                f"job:{UUID(int=2)}",
            }
        ),
    )

    decision = ControlPlaneServiceAccountAuthorizer().decide(
        authentication,
        action="job.cancel",
        resource=f"job:{_JOB_ID}",
    )

    assert not decision.allowed


def test_require_raises_one_generic_denial() -> None:
    authentication = _authentication(
        scopes=frozenset({"jobs.read"}),
        resources=frozenset({"job:*"}),
    )
    authorizer = ControlPlaneServiceAccountAuthorizer()

    with pytest.raises(
        ControlPlaneServiceAccountPermissionDeniedError,
    ) as captured:
        authorizer.require(
            authentication,
            action="workflow.cancel",
            resource=(f"workflow:{_WORKFLOW_ID}"),
        )

    assert str(captured.value) == ("service-account authorization denied")
    assert "workflow" not in str(captured.value)


def test_authorizer_rejects_human_or_arbitrary_identity() -> None:
    with pytest.raises(
        TypeError,
        match="service-account authentication",
    ):
        ControlPlaneServiceAccountAuthorizer().decide(
            object(),  # type: ignore[arg-type]
            action="jobs.read",
            resource=f"job:{_JOB_ID}",
        )


def test_authorization_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert (
        control_plane.ControlPlaneServiceAccountAuthorization
        is ControlPlaneServiceAccountAuthorization
    )
    assert (
        control_plane.ControlPlaneServiceAccountAuthorizer is ControlPlaneServiceAccountAuthorizer
    )
    assert (
        control_plane.ControlPlaneServiceAccountPermissionDeniedError
        is ControlPlaneServiceAccountPermissionDeniedError
    )
