from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    CONTROL_PLANE_READ_PERMISSION,
    ControlPlaneCommandAction,
    ControlPlaneCommandAuthorizer,
    ControlPlaneCommandIntent,
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneCommandReceipt,
    ControlPlaneCommandStateError,
    ControlPlaneCommandStatus,
    ControlPlaneIdempotencyCapacityError,
    ControlPlaneIdempotencyConflictError,
    ControlPlaneIdempotencyStoreClosedError,
    ControlPlanePrincipal,
    IdempotencyKey,
    InMemoryControlPlaneIdempotencyStore,
    command_payload_digest,
)

_NOW = datetime(2026, 7, 19, 3, 0, tzinfo=UTC)
_EMPTY_DIGEST = command_payload_digest(b"{}")


@pytest.mark.parametrize(
    ("action", "permission"),
    [
        (ControlPlaneCommandAction.CREATE_JOB, "control-plane.jobs.create"),
        (ControlPlaneCommandAction.CANCEL_JOB, "control-plane.jobs.cancel"),
        (ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB, "control-plane.jobs.retry"),
        (ControlPlaneCommandAction.CANCEL_WORKFLOW, "control-plane.workflows.cancel"),
    ],
)
def test_command_action_maps_to_exact_permission(
    action: ControlPlaneCommandAction,
    permission: str,
) -> None:
    assert action.permission == permission


@pytest.mark.parametrize(
    ("action", "destructive"),
    [
        (ControlPlaneCommandAction.CREATE_JOB, False),
        (ControlPlaneCommandAction.CANCEL_JOB, True),
        (ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB, False),
        (ControlPlaneCommandAction.CANCEL_WORKFLOW, True),
    ],
)
def test_command_action_marks_destructive_operations(
    action: ControlPlaneCommandAction,
    destructive: bool,
) -> None:
    assert action.destructive is destructive


def test_idempotency_key_accepts_safe_value_and_redacts_representation() -> None:
    value = "job-create:request-0001"
    key = IdempotencyKey(value)

    assert key.digest == IdempotencyKey(value).digest
    assert value not in repr(key)
    assert value not in str(key)


@pytest.mark.parametrize(
    "value",
    [
        "short",
        " leading-key-0001",
        "trailing-key-0001 ",
        "contains space 0001",
        "contains/slash/0001",
        "á" * 16,
        "x" * 129,
        "line-break-0001\n",
    ],
)
def test_idempotency_key_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(ValueError, match="idempotency key"):
        IdempotencyKey(value)


def test_command_payload_digest_is_deterministic() -> None:
    assert command_payload_digest(b'{"a":1}') == command_payload_digest(bytearray(b'{"a":1}'))
    assert command_payload_digest(b'{"a":1}') != command_payload_digest(b'{"a":2}')


def test_command_intent_normalizes_safe_fields() -> None:
    intent = _intent(target=" job-123 ", payload_digest=_EMPTY_DIGEST.upper())

    assert intent.target == "job-123"
    assert intent.payload_digest == _EMPTY_DIGEST
    assert len(intent.fingerprint) == 64
    assert intent.fingerprint == _intent(id=intent.id).fingerprint


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"target": " "}, "target"),
        ({"target": "bad\nvalue"}, "control characters"),
        ({"payload_digest": "invalid"}, "SHA-256"),
        ({"requested_at": datetime(2026, 7, 19)}, "timezone-aware"),
    ],
)
def test_command_intent_rejects_invalid_contracts(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _intent(**overrides)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": ControlPlaneCommandStatus.PENDING, "completed_at": _NOW},
        {"status": ControlPlaneCommandStatus.PENDING, "result_code": "accepted"},
        {"status": ControlPlaneCommandStatus.SUCCEEDED},
        {
            "status": ControlPlaneCommandStatus.FAILED,
            "completed_at": _NOW,
            "result_code": "Bad Code",
        },
        {
            "status": ControlPlaneCommandStatus.SUCCEEDED,
            "completed_at": _NOW - timedelta(seconds=1),
            "result_code": "ok",
        },
    ],
)
def test_command_receipt_rejects_inconsistent_lifecycle(
    kwargs: dict[str, object],
) -> None:
    values: dict[str, Any] = {
        "command_id": UUID(int=1),
        "action": ControlPlaneCommandAction.CREATE_JOB,
        "target": "mail.send",
        "status": ControlPlaneCommandStatus.PENDING,
        "created_at": _NOW,
    }
    values.update(kwargs)

    with pytest.raises(ValueError):
        ControlPlaneCommandReceipt(**values)


@pytest.mark.parametrize("action", tuple(ControlPlaneCommandAction))
def test_command_authorizer_allows_exact_permission(
    action: ControlPlaneCommandAction,
) -> None:
    principal = ControlPlanePrincipal(
        "operator",
        frozenset({CONTROL_PLANE_READ_PERMISSION, action.permission}),
    )

    decision = ControlPlaneCommandAuthorizer().require(principal, action)

    assert decision.allowed is True
    assert decision.permission == action.permission


@pytest.mark.parametrize("action", tuple(ControlPlaneCommandAction))
def test_command_authorizer_denies_missing_permission(
    action: ControlPlaneCommandAction,
) -> None:
    principal = ControlPlanePrincipal("observer")

    decision = ControlPlaneCommandAuthorizer().decide(principal, action)

    assert decision.allowed is False
    assert decision.permission == action.permission


def test_command_authorizer_require_raises_generic_error() -> None:
    with pytest.raises(ControlPlaneCommandPermissionDeniedError, match="permission denied"):
        ControlPlaneCommandAuthorizer().require(
            ControlPlanePrincipal("observer"),
            ControlPlaneCommandAction.CANCEL_JOB,
        )


@pytest.mark.asyncio
async def test_idempotency_store_reserves_new_command() -> None:
    store = InMemoryControlPlaneIdempotencyStore()
    intent = _intent()

    reservation = await store.reserve(intent)

    assert reservation.replayed is False
    assert reservation.receipt.command_id == intent.id
    assert reservation.receipt.status is ControlPlaneCommandStatus.PENDING


@pytest.mark.asyncio
async def test_idempotency_store_replays_same_fingerprint() -> None:
    store = InMemoryControlPlaneIdempotencyStore()
    intent = _intent()
    await store.reserve(intent)

    replay = await store.reserve(_intent(id=UUID(int=99)))

    assert replay.replayed is True
    assert replay.receipt.command_id == intent.id


@pytest.mark.asyncio
async def test_idempotency_store_rejects_key_reuse_for_different_command() -> None:
    store = InMemoryControlPlaneIdempotencyStore()
    await store.reserve(_intent())

    with pytest.raises(ControlPlaneIdempotencyConflictError, match="another command"):
        await store.reserve(_intent(target="job-456"))


@pytest.mark.asyncio
async def test_idempotency_store_completes_command() -> None:
    store = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW + timedelta(seconds=1))
    intent = _intent()
    await store.reserve(intent)

    receipt = await store.complete(intent, result_code="job.created")

    assert receipt.status is ControlPlaneCommandStatus.SUCCEEDED
    assert receipt.completed_at == _NOW + timedelta(seconds=1)
    assert receipt.result_code == "job.created"


@pytest.mark.asyncio
async def test_idempotency_store_fails_command_with_safe_code() -> None:
    store = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW + timedelta(seconds=1))
    intent = _intent()
    await store.reserve(intent)

    receipt = await store.fail(intent, result_code="target.not_found")

    assert receipt.status is ControlPlaneCommandStatus.FAILED
    assert receipt.result_code == "target.not_found"


@pytest.mark.asyncio
async def test_idempotency_store_returns_same_terminal_result() -> None:
    store = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW + timedelta(seconds=1))
    intent = _intent()
    await store.reserve(intent)
    first = await store.complete(intent, result_code="ok")

    second = await store.complete(intent, result_code="ok")

    assert second is first


@pytest.mark.asyncio
async def test_idempotency_store_rejects_terminal_result_replacement() -> None:
    store = InMemoryControlPlaneIdempotencyStore(clock=lambda: _NOW + timedelta(seconds=1))
    intent = _intent()
    await store.reserve(intent)
    await store.complete(intent, result_code="ok")

    with pytest.raises(ControlPlaneCommandStateError, match="cannot be replaced"):
        await store.fail(intent, result_code="failed")


@pytest.mark.asyncio
async def test_idempotency_store_requires_reservation_before_completion() -> None:
    store = InMemoryControlPlaneIdempotencyStore()

    with pytest.raises(ControlPlaneCommandStateError, match="reserved"):
        await store.complete(_intent(), result_code="ok")


@pytest.mark.asyncio
async def test_idempotency_store_get_returns_none_for_unknown_key() -> None:
    store = InMemoryControlPlaneIdempotencyStore()

    assert await store.get(IdempotencyKey("unknown-request-0001")) is None


@pytest.mark.asyncio
async def test_idempotency_store_evicts_oldest_terminal_entry_at_capacity() -> None:
    store = InMemoryControlPlaneIdempotencyStore(capacity=1, clock=lambda: _NOW)
    first = _intent(idempotency_key=IdempotencyKey("request-key-old-0001"))
    second = _intent(idempotency_key=IdempotencyKey("request-key-new-0002"), id=UUID(int=2))
    await store.reserve(first)
    await store.complete(first, result_code="ok")

    reservation = await store.reserve(second)

    assert reservation.replayed is False
    assert await store.get(first.idempotency_key) is None


@pytest.mark.asyncio
async def test_idempotency_store_rejects_capacity_when_all_entries_are_pending() -> None:
    store = InMemoryControlPlaneIdempotencyStore(capacity=1)
    await store.reserve(_intent())

    with pytest.raises(ControlPlaneIdempotencyCapacityError, match="pending commands"):
        await store.reserve(
            _intent(
                idempotency_key=IdempotencyKey("another-request-0002"),
                id=UUID(int=2),
            )
        )


@pytest.mark.asyncio
async def test_idempotency_store_snapshot_contains_only_counters() -> None:
    store = InMemoryControlPlaneIdempotencyStore(capacity=3, clock=lambda: _NOW)
    pending = _intent(idempotency_key=IdempotencyKey("pending-request-0001"))
    succeeded = _intent(
        idempotency_key=IdempotencyKey("success-request-0002"),
        id=UUID(int=2),
    )
    failed = _intent(
        idempotency_key=IdempotencyKey("failure-request-0003"),
        id=UUID(int=3),
    )
    await store.reserve(pending)
    await store.reserve(succeeded)
    await store.complete(succeeded, result_code="ok")
    await store.reserve(failed)
    await store.fail(failed, result_code="failed")

    snapshot = await store.snapshot()

    assert snapshot.entries == 3
    assert snapshot.pending == 1
    assert snapshot.succeeded == 1
    assert snapshot.failed == 1
    assert snapshot.capacity == 3


@pytest.mark.asyncio
async def test_idempotency_store_close_clears_and_rejects_operations() -> None:
    store = InMemoryControlPlaneIdempotencyStore()
    await store.reserve(_intent())

    await store.close()

    assert (await store.snapshot()).closed is True
    with pytest.raises(ControlPlaneIdempotencyStoreClosedError, match="closed"):
        await store.reserve(_intent())


def _intent(**overrides: object) -> ControlPlaneCommandIntent:
    values: dict[str, Any] = {
        "action": ControlPlaneCommandAction.CREATE_JOB,
        "target": "job-123",
        "idempotency_key": IdempotencyKey("request-key-0000001"),
        "payload_digest": _EMPTY_DIGEST,
        "requested_at": _NOW,
        "id": UUID(int=1),
    }
    values.update(overrides)
    return ControlPlaneCommandIntent(**values)
