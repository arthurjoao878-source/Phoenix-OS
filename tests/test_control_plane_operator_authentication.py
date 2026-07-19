from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane.auth import CONTROL_PLANE_READ_PERMISSION
from phoenix_os.control_plane.errors import ControlPlaneOperatorRegistryClosedError
from phoenix_os.control_plane.operator_authentication import (
    ControlPlaneOperatorAuthentication,
    ControlPlaneOperatorAuthenticator,
)
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry

_NOW = datetime(2026, 7, 19, 16, tzinfo=UTC)
_TOKEN = ControlPlaneOperatorToken("alice-token-0123456789abcdef-operator")
_OTHER_TOKEN = ControlPlaneOperatorToken("other-token-0123456789abcdef-operator")


def _record(
    *,
    operator_id: UUID | None = None,
    token: ControlPlaneOperatorToken = _TOKEN,
    role: ControlPlaneOperatorRole = ControlPlaneOperatorRole.VIEWER,
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    token_version: int = 1,
) -> ControlPlaneOperatorRecord:
    return ControlPlaneOperatorRecord(
        id=operator_id or uuid4(),
        username="alice",
        display_name="Alice Operator",
        role=role,
        token_digest=token.digest,
        created_at=_NOW,
        updated_at=_NOW,
        additional_permissions=frozenset({"audit.read"}),
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        token_version=token_version,
    )


class _RecordingRegistry(InMemoryControlPlaneOperatorRegistry):
    def __init__(self) -> None:
        super().__init__()
        self.requested_digests: list[str] = []

    async def get_by_token_digest(self, token_digest: str) -> ControlPlaneOperatorRecord | None:
        self.requested_digests.append(token_digest)
        return await super().get_by_token_digest(token_digest)


class _MismatchedRegistry(InMemoryControlPlaneOperatorRegistry):
    def __init__(self, record: ControlPlaneOperatorRecord) -> None:
        super().__init__()
        self._returned_record = record

    async def get_by_token_digest(self, token_digest: str) -> ControlPlaneOperatorRecord | None:
        del token_digest
        return self._returned_record


@pytest.mark.asyncio
async def test_authenticator_returns_identified_operator_evidence() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(role=ControlPlaneOperatorRole.OPERATOR, token_version=3)
    await registry.add(record)
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=lambda: _NOW)

    result = await authenticator.authenticate(f"Bearer {_TOKEN.value}")

    assert result == ControlPlaneOperatorAuthentication(
        operator_id=record.id,
        principal=record.principal(),
        token_version=3,
        authenticated_at=_NOW,
    )
    assert result is not None
    assert result.principal.name == "alice"
    assert CONTROL_PLANE_READ_PERMISSION in result.principal.permissions
    assert "audit.read" in result.principal.permissions


@pytest.mark.asyncio
async def test_authenticator_accepts_case_insensitive_bearer_scheme() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_record())
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=lambda: _NOW)
    assert await authenticator.authenticate(f"bEaReR {_TOKEN.value}") is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        "Bearer",
        "Basic " + _TOKEN.value,
        "Bearer ",
        "Bearer  " + _TOKEN.value,
        "Bearer " + _TOKEN.value + " ",
        "Bearer short",
        "Bearer " + "á" * 32,
        "Bearer " + "a" * 257,
    ],
)
async def test_authenticator_rejects_missing_or_malformed_authorization(
    authorization: str | None,
) -> None:
    registry = _RecordingRegistry()
    await registry.add(_record())
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=lambda: _NOW)

    assert await authenticator.authenticate(authorization) is None
    assert len(registry.requested_digests) == 1
    requested = registry.requested_digests[0]
    assert len(requested) == 64
    int(requested, 16)


@pytest.mark.asyncio
async def test_authenticator_rejects_unknown_token_with_generic_none() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_record())
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=lambda: _NOW)
    assert await authenticator.authenticate(f"Bearer {_OTHER_TOKEN.value}") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "disabled_at", "revoked_at"),
    [
        (ControlPlaneOperatorStatus.DISABLED, _NOW, None),
        (ControlPlaneOperatorStatus.REVOKED, None, _NOW),
    ],
)
async def test_authenticator_rejects_inactive_operator(
    status: ControlPlaneOperatorStatus,
    disabled_at: datetime | None,
    revoked_at: datetime | None,
) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_record(status=status, disabled_at=disabled_at, revoked_at=revoked_at))
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=lambda: _NOW)
    assert await authenticator.authenticate(f"Bearer {_TOKEN.value}") is None


@pytest.mark.asyncio
async def test_authenticator_compares_returned_record_digest() -> None:
    record = _record(token=_OTHER_TOKEN)
    authenticator = ControlPlaneOperatorAuthenticator(
        _MismatchedRegistry(record),
        clock=lambda: _NOW,
    )
    assert await authenticator.authenticate(f"Bearer {_TOKEN.value}") is None


@pytest.mark.asyncio
async def test_authenticator_does_not_include_credential_material_in_result_repr() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_record())
    result = await ControlPlaneOperatorAuthenticator(
        registry,
        clock=lambda: _NOW,
    ).authenticate(f"Bearer {_TOKEN.value}")
    assert result is not None
    assert _TOKEN.value not in repr(result)
    assert _TOKEN.digest not in repr(result)


@pytest.mark.asyncio
async def test_authenticator_uses_current_record_permissions() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    await registry.replace(
        replace(
            record,
            role=ControlPlaneOperatorRole.MAINTAINER,
            updated_at=_NOW,
            revision=2,
        ),
        expected_revision=1,
    )
    result = await ControlPlaneOperatorAuthenticator(
        registry,
        clock=lambda: _NOW,
    ).authenticate(f"Bearer {_TOKEN.value}")
    assert result is not None
    assert result.principal.permissions == ControlPlaneOperatorRole.MAINTAINER.permissions | {
        "audit.read"
    }


@pytest.mark.asyncio
async def test_authenticator_rejects_naive_success_clock() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_record())
    authenticator = ControlPlaneOperatorAuthenticator(
        registry,
        clock=lambda: datetime(2026, 7, 19, 16),
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        await authenticator.authenticate(f"Bearer {_TOKEN.value}")


@pytest.mark.asyncio
async def test_authenticator_does_not_call_clock_for_rejected_token() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_record())

    def fail_clock() -> datetime:
        raise AssertionError("rejected authentication must not read the success clock")

    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=fail_clock)
    assert await authenticator.authenticate(f"Bearer {_OTHER_TOKEN.value}") is None


@pytest.mark.asyncio
async def test_authenticator_propagates_registry_closed_failure() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.close()
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=lambda: _NOW)
    with pytest.raises(ControlPlaneOperatorRegistryClosedError):
        await authenticator.authenticate(f"Bearer {_TOKEN.value}")


def test_authenticator_requires_callable_clock() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    with pytest.raises(TypeError, match="clock"):
        ControlPlaneOperatorAuthenticator(registry, clock=None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"token_version": 0},
        {"authenticated_at": datetime(2026, 7, 19, 16)},
        {"schema_version": 2},
    ],
)
def test_operator_authentication_contract_rejects_invalid_fields(
    kwargs: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "operator_id": uuid4(),
        "principal": _record().principal(),
        "token_version": 1,
        "authenticated_at": _NOW,
    }
    values.update(kwargs)
    with pytest.raises(ValueError):
        ControlPlaneOperatorAuthentication(**values)  # type: ignore[arg-type]


def test_unknown_token_digest_differs_from_known_digest() -> None:
    assert hashlib.sha256(_OTHER_TOKEN.value.encode("ascii")).hexdigest() != _TOKEN.digest
