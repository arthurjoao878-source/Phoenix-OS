from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    CONTROL_PLANE_READ_PERMISSION,
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
    ControlPlaneConfirmationCapacityError,
    ControlPlaneConfirmationNotRequiredError,
    ControlPlaneConfirmationProof,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneConfirmationStoreClosedError,
    ControlPlanePrincipal,
    IdempotencyKey,
    InMemoryControlPlaneConfirmationService,
    command_payload_digest,
)

_NOW = datetime(2026, 7, 19, 4, 30, tzinfo=UTC)
_SECRET = b"p" * 32
_PRINCIPAL = ControlPlanePrincipal("operator", frozenset({CONTROL_PLANE_READ_PERMISSION}))


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _Nonces:
    def __init__(self) -> None:
        self._value = 0

    def __call__(self, size: int) -> bytes:
        self._value += 1
        return bytes([self._value]) * size


def _intent(**overrides: object) -> ControlPlaneCommandIntent:
    values: dict[str, Any] = {
        "action": ControlPlaneCommandAction.CANCEL_JOB,
        "target": "job-123",
        "idempotency_key": IdempotencyKey("confirmation-key-0001"),
        "payload_digest": command_payload_digest(b"{}"),
        "requested_at": _NOW,
        "id": UUID(int=1),
    }
    values.update(overrides)
    return ControlPlaneCommandIntent(**values)


@pytest.mark.parametrize("secret", [b"short", b"x" * 129])
def test_confirmation_service_rejects_unsafe_secret_sizes(secret: bytes) -> None:
    with pytest.raises(ValueError, match="secret"):
        InMemoryControlPlaneConfirmationService(secret)


@pytest.mark.parametrize("capacity", [0, -1, 100_001])
def test_confirmation_service_rejects_unsafe_capacity(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        InMemoryControlPlaneConfirmationService(_SECRET, capacity=capacity)


@pytest.mark.parametrize(
    "ttl",
    [timedelta(0), timedelta(seconds=-1), timedelta(minutes=10, seconds=1)],
)
def test_confirmation_service_rejects_unsafe_ttl(ttl: timedelta) -> None:
    with pytest.raises(ValueError, match="TTL"):
        InMemoryControlPlaneConfirmationService(_SECRET, ttl=ttl)


@pytest.mark.asyncio
async def test_confirmation_service_issues_safe_challenge() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    intent = _intent()

    challenge = await service.issue(_PRINCIPAL, intent)

    assert challenge.command_id == intent.id
    assert challenge.action is ControlPlaneCommandAction.CANCEL_JOB
    assert challenge.target == "job-123"
    assert challenge.issued_at == _NOW
    assert challenge.expires_at == _NOW + timedelta(minutes=2)
    assert challenge.proof.value not in repr(challenge)
    assert challenge.proof.value not in repr(challenge.proof)
    assert challenge.proof.value not in str(challenge.proof)


@pytest.mark.asyncio
async def test_confirmation_service_rejects_non_destructive_action() -> None:
    service = InMemoryControlPlaneConfirmationService(_SECRET)
    intent = _intent(action=ControlPlaneCommandAction.CREATE_JOB)

    with pytest.raises(ControlPlaneConfirmationNotRequiredError, match="does not require"):
        await service.issue(_PRINCIPAL, intent)


@pytest.mark.asyncio
async def test_confirmation_service_verifies_and_consumes_once() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    intent = _intent()
    challenge = await service.issue(_PRINCIPAL, intent)

    verification = await service.verify_and_consume(_PRINCIPAL, intent, challenge.proof)

    assert verification.command_id == intent.id
    assert verification.action is ControlPlaneCommandAction.CANCEL_JOB
    assert verification.target == intent.target
    assert verification.confirmed_at == _NOW

    with pytest.raises(ControlPlaneConfirmationRejectedError, match="confirmation failed"):
        await service.verify_and_consume(_PRINCIPAL, intent, challenge.proof)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed",
    [
        {"id": UUID(int=2)},
        {"target": "job-456"},
        {"idempotency_key": IdempotencyKey("confirmation-key-0002")},
        {"payload_digest": command_payload_digest(b'{"reason":"other"}')},
        {"action": ControlPlaneCommandAction.CANCEL_WORKFLOW},
    ],
)
async def test_confirmation_proof_is_bound_to_exact_intent(changed: dict[str, object]) -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    challenge = await service.issue(_PRINCIPAL, _intent())

    with pytest.raises(ControlPlaneConfirmationRejectedError, match="confirmation failed"):
        await service.verify_and_consume(_PRINCIPAL, _intent(**changed), challenge.proof)


@pytest.mark.asyncio
async def test_confirmation_proof_is_bound_to_exact_principal() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    intent = _intent()
    challenge = await service.issue(_PRINCIPAL, intent)

    with pytest.raises(ControlPlaneConfirmationRejectedError, match="confirmation failed"):
        await service.verify_and_consume(
            ControlPlanePrincipal("other"),
            intent,
            challenge.proof,
        )


@pytest.mark.asyncio
async def test_confirmation_service_rejects_tampered_proof() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    intent = _intent()
    challenge = await service.issue(_PRINCIPAL, intent)
    replacement = "A" if challenge.proof.value[-1] != "A" else "B"
    proof = ControlPlaneConfirmationProof(challenge.proof.value[:-1] + replacement)

    with pytest.raises(ControlPlaneConfirmationRejectedError, match="confirmation failed"):
        await service.verify_and_consume(_PRINCIPAL, intent, proof)


@pytest.mark.asyncio
async def test_confirmation_service_rejects_expired_proof() -> None:
    clock = _Clock()
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        ttl=timedelta(seconds=30),
        clock=clock,
        nonce_source=_Nonces(),
    )
    intent = _intent()
    challenge = await service.issue(_PRINCIPAL, intent)
    clock.value = _NOW + timedelta(seconds=30)

    with pytest.raises(ControlPlaneConfirmationRejectedError, match="confirmation failed"):
        await service.verify_and_consume(_PRINCIPAL, intent, challenge.proof)


@pytest.mark.asyncio
async def test_confirmation_service_rejects_unknown_validly_signed_proof() -> None:
    issuer = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    verifier = InMemoryControlPlaneConfirmationService(_SECRET, clock=lambda: _NOW)
    intent = _intent()
    challenge = await issuer.issue(_PRINCIPAL, intent)

    with pytest.raises(ControlPlaneConfirmationRejectedError, match="confirmation failed"):
        await verifier.verify_and_consume(_PRINCIPAL, intent, challenge.proof)


@pytest.mark.asyncio
async def test_confirmation_service_snapshot_contains_only_counters() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        capacity=3,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    first = _intent()
    second = _intent(
        id=UUID(int=2),
        idempotency_key=IdempotencyKey("confirmation-key-0002"),
    )
    first_challenge = await service.issue(_PRINCIPAL, first)
    await service.issue(_PRINCIPAL, second)
    await service.verify_and_consume(_PRINCIPAL, first, first_challenge.proof)

    snapshot = await service.snapshot()

    assert snapshot.entries == 2
    assert snapshot.active == 1
    assert snapshot.consumed == 1
    assert snapshot.capacity == 3


@pytest.mark.asyncio
async def test_confirmation_service_evicts_consumed_entry_at_capacity() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        capacity=1,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    first = _intent()
    first_challenge = await service.issue(_PRINCIPAL, first)
    await service.verify_and_consume(_PRINCIPAL, first, first_challenge.proof)

    second = _intent(
        id=UUID(int=2),
        idempotency_key=IdempotencyKey("confirmation-key-0002"),
    )
    challenge = await service.issue(_PRINCIPAL, second)

    assert challenge.command_id == UUID(int=2)
    assert (await service.snapshot()).entries == 1


@pytest.mark.asyncio
async def test_confirmation_service_evicts_expired_entry_at_capacity() -> None:
    clock = _Clock()
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        capacity=1,
        ttl=timedelta(seconds=30),
        clock=clock,
        nonce_source=_Nonces(),
    )
    await service.issue(_PRINCIPAL, _intent())
    clock.value = _NOW + timedelta(seconds=30)

    second = _intent(
        id=UUID(int=2),
        idempotency_key=IdempotencyKey("confirmation-key-0002"),
    )
    challenge = await service.issue(_PRINCIPAL, second)

    assert challenge.command_id == UUID(int=2)


@pytest.mark.asyncio
async def test_confirmation_service_rejects_capacity_with_only_active_entries() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        capacity=1,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    await service.issue(_PRINCIPAL, _intent())

    with pytest.raises(ControlPlaneConfirmationCapacityError, match="active challenges"):
        await service.issue(
            _PRINCIPAL,
            _intent(
                id=UUID(int=2),
                idempotency_key=IdempotencyKey("confirmation-key-0002"),
            ),
        )


@pytest.mark.asyncio
async def test_confirmation_service_close_clears_and_rejects_operations() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    await service.issue(_PRINCIPAL, _intent())

    await service.close()

    assert service.closed is True
    assert (await service.snapshot()).closed is True
    assert (await service.snapshot()).entries == 0
    with pytest.raises(ControlPlaneConfirmationStoreClosedError, match="closed"):
        await service.issue(_PRINCIPAL, _intent())


@pytest.mark.asyncio
async def test_confirmation_service_rejects_invalid_nonce_source() -> None:
    service = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=lambda _: b"short",
    )

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        await service.issue(_PRINCIPAL, _intent())
