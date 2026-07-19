from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    CONTROL_PLANE_READ_PERMISSION,
    ControlPlaneBrowserOrigin,
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
    ControlPlaneCommandProtector,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneCsrfProtector,
    ControlPlaneCsrfRejectedError,
    ControlPlanePrincipal,
    IdempotencyKey,
    InMemoryControlPlaneConfirmationService,
    command_payload_digest,
)

_NOW = datetime(2026, 7, 19, 5, 0, tzinfo=UTC)
_SECRET = b"s" * 32
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:8765")
_PRINCIPAL = ControlPlanePrincipal("operator", frozenset({CONTROL_PLANE_READ_PERMISSION}))


class _Nonces:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, size: int) -> bytes:
        self.value += 1
        return bytes([self.value]) * size


def _intent(**overrides: object) -> ControlPlaneCommandIntent:
    values: dict[str, Any] = {
        "action": ControlPlaneCommandAction.CANCEL_JOB,
        "target": "job-123",
        "idempotency_key": IdempotencyKey("protection-key-0001"),
        "payload_digest": command_payload_digest(b"{}"),
        "requested_at": _NOW,
        "id": UUID(int=1),
    }
    values.update(overrides)
    return ControlPlaneCommandIntent(**values)


def _protector() -> tuple[ControlPlaneCommandProtector, ControlPlaneCsrfProtector]:
    csrf = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    confirmations = InMemoryControlPlaneConfirmationService(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_Nonces(),
    )
    return ControlPlaneCommandProtector(csrf, confirmations), csrf


@pytest.mark.asyncio
async def test_command_protector_allows_non_destructive_command_with_csrf_only() -> None:
    protector, csrf = _protector()
    intent = _intent(action=ControlPlaneCommandAction.CREATE_JOB)
    token = csrf.issue(_PRINCIPAL, _ORIGIN)

    result = await protector.verify(
        _PRINCIPAL,
        intent,
        origin=_ORIGIN,
        csrf_token=token,
    )

    assert result.csrf.principal == _PRINCIPAL.name
    assert result.confirmation is None


@pytest.mark.asyncio
async def test_command_protector_rejects_destructive_command_without_confirmation() -> None:
    protector, csrf = _protector()

    with pytest.raises(ControlPlaneConfirmationRejectedError, match="confirmation failed"):
        await protector.verify(
            _PRINCIPAL,
            _intent(),
            origin=_ORIGIN,
            csrf_token=csrf.issue(_PRINCIPAL, _ORIGIN),
        )


@pytest.mark.asyncio
async def test_command_protector_issues_and_consumes_destructive_confirmation() -> None:
    protector, csrf = _protector()
    intent = _intent()
    token = csrf.issue(_PRINCIPAL, _ORIGIN)
    challenge = await protector.issue_confirmation(
        _PRINCIPAL,
        intent,
        origin=_ORIGIN,
        csrf_token=token,
    )

    result = await protector.verify(
        _PRINCIPAL,
        intent,
        origin=_ORIGIN,
        csrf_token=token,
        confirmation=challenge.proof,
    )

    assert result.confirmation is not None
    assert result.confirmation.command_id == intent.id


@pytest.mark.asyncio
async def test_command_protector_validates_csrf_before_issuing_confirmation() -> None:
    protector, csrf = _protector()
    token = csrf.issue(_PRINCIPAL, _ORIGIN)

    with pytest.raises(ControlPlaneCsrfRejectedError, match="validation failed"):
        await protector.issue_confirmation(
            _PRINCIPAL,
            _intent(),
            origin=ControlPlaneBrowserOrigin("http://127.0.0.1:9999"),
            csrf_token=token,
        )


@pytest.mark.asyncio
async def test_command_protector_validates_csrf_before_consuming_confirmation() -> None:
    protector, csrf = _protector()
    intent = _intent()
    token = csrf.issue(_PRINCIPAL, _ORIGIN)
    challenge = await protector.issue_confirmation(
        _PRINCIPAL,
        intent,
        origin=_ORIGIN,
        csrf_token=token,
    )

    with pytest.raises(ControlPlaneCsrfRejectedError, match="validation failed"):
        await protector.verify(
            _PRINCIPAL,
            intent,
            origin=ControlPlaneBrowserOrigin("http://127.0.0.1:9999"),
            csrf_token=token,
            confirmation=challenge.proof,
        )

    result = await protector.verify(
        _PRINCIPAL,
        intent,
        origin=_ORIGIN,
        csrf_token=token,
        confirmation=challenge.proof,
    )
    assert result.confirmation is not None
