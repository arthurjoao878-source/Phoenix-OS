from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import ClassVar
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneBrowserOrigin,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneInferenceHttpAdapter,
    ControlPlanePrincipal,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.operator_contracts import ControlPlaneOperatorRole
from phoenix_os.control_plane.step_up import ControlPlaneStepUpAction
from phoenix_os.events import EventBus
from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceProviderConfiguration,
    InferenceRuntimeStack,
    InferenceServiceConfiguration,
    ModelCapabilities,
    ModelDescriptor,
    ModelEndpointPolicy,
    ModelId,
    ModelProviderId,
    create_inference_runtime_stack,
    inference_model_resource,
)
from phoenix_os.policy import PolicyEffect, PolicyEngine, PolicyRule

_NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:9443")
_SESSION_ID = UUID("00000000-0000-4000-8000-000000004201")
_OPERATOR_ID = UUID("00000000-0000-4000-8000-000000005201")


class _Boundary:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.calls = 0

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object:
        self.calls += 1
        if self.reject:
            raise ControlPlaneDurableSessionCsrfRejectedError("CSRF rejected")
        assert token_value == "csrf-value"
        assert authentication.session_id == _SESSION_ID
        assert supplied_origin == _ORIGIN
        assert expected_origin == _ORIGIN
        return object()


class _StepUp:
    calls: ClassVar[
        list[
            tuple[
                str | None,
                ControlPlaneDurableSessionAuthentication,
                ControlPlaneStepUpAction,
            ]
        ]
    ] = []

    def __init__(self, *, reject: bool = False) -> None:
        type(self).calls = []
        self.reject = reject

    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object:
        type(self).calls.append((token_value, session, action))
        if self.reject:
            raise ControlPlaneStepUpRejectedError("step-up rejected")
        assert token_value == "step-up-value"
        return object()


def _configuration() -> InferenceServiceConfiguration:
    return InferenceServiceConfiguration(
        providers=(
            InferenceProviderConfiguration(
                ModelProviderId("deterministic"),
                endpoint_policy=ModelEndpointPolicy("https://api.example.test/private"),
                metadata={"private": "PROVIDER-METADATA-MUST-NOT-LEAK"},
            ),
        ),
        models=(
            ModelDescriptor(
                provider_id=ModelProviderId("deterministic"),
                model_id=ModelId("chat"),
                provider_model_name="PRIVATE-PROVIDER-MODEL-NAME",
                capabilities=ModelCapabilities(
                    complete=True,
                    streaming=True,
                ),
                metadata={"private": "MODEL-METADATA-MUST-NOT-LEAK"},
            ),
        ),
    )


def _policy() -> PolicyEngine:
    return PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.inference",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"model.infer"}),
                resources=frozenset(
                    {
                        inference_model_resource(
                            ModelProviderId("deterministic"),
                            ModelId("chat"),
                        )
                    }
                ),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )


def _stack() -> InferenceRuntimeStack:
    return create_inference_runtime_stack(
        configuration=_configuration(),
        providers=(
            DeterministicModelProvider(
                {"chat": "RESPONSE-MUST-NOT-LEAK"},
                provider_id="deterministic",
            ),
        ),
        policy=_policy(),
        events=EventBus(),
    )


def _principal(*, maintainer: bool = True) -> ControlPlanePrincipal:
    role = ControlPlaneOperatorRole.MAINTAINER if maintainer else ControlPlaneOperatorRole.OPERATOR
    return ControlPlanePrincipal(
        "maintainer" if maintainer else "operator",
        role.permissions,
    )


def _authentication(
    *,
    maintainer: bool = True,
) -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=_SESSION_ID,
        operator_id=_OPERATOR_ID,
        principal=_principal(maintainer=maintainer),
        generation=1,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=2),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _adapter(
    *,
    maintainer: bool = True,
    reject_csrf: bool = False,
    reject_step_up: bool = False,
) -> tuple[
    ControlPlaneInferenceHttpAdapter,
    _Boundary,
    _StepUp,
    ControlPlaneDurableSessionAuthentication,
]:
    stack = _stack()
    boundary = _Boundary(reject=reject_csrf)
    step_up = _StepUp(reject=reject_step_up)
    adapter = ControlPlaneInferenceHttpAdapter(
        administration=stack.administration,
        boundary=boundary,
        step_up=step_up,
    )
    return (
        adapter,
        boundary,
        step_up,
        _authentication(maintainer=maintainer),
    )


def _headers(*, step_up: bool = True) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {
        "origin": (str(_ORIGIN),),
        "x-phoenix-csrf": ("csrf-value",),
    }
    if step_up:
        result["x-phoenix-step-up"] = ("step-up-value",)
    return result


def _body(document: Mapping[str, object]) -> bytes:
    return json.dumps(dict(document)).encode("utf-8")


@pytest.mark.asyncio
async def test_inference_http_lists_content_free_inventory_and_health() -> None:
    adapter, _boundary, _step_up, authentication = _adapter()

    provider_status, providers, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/inference/providers",
        query={"limit": ("10",)},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    model_status, models, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/inference/models",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    health_status, health, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/inference/health",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    serialized = repr((providers, models, health))
    assert provider_status is HTTPStatus.OK
    assert model_status is HTTPStatus.OK
    assert health_status is HTTPStatus.OK
    assert providers["page"]["total"] == 1  # type: ignore[index]
    assert models["page"]["total"] == 1  # type: ignore[index]
    assert health["providers"] == {"providers": 1, "enabled": 1}
    assert "api.example.test" not in serialized
    assert "PRIVATE-PROVIDER-MODEL-NAME" not in serialized
    assert "PROVIDER-METADATA-MUST-NOT-LEAK" not in serialized
    assert "MODEL-METADATA-MUST-NOT-LEAK" not in serialized
    assert "RESPONSE-MUST-NOT-LEAK" not in serialized


@pytest.mark.asyncio
async def test_inference_http_disable_requires_csrf_but_not_step_up() -> None:
    adapter, boundary, _step_up, authentication = _adapter()

    status, payload, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=("/v1/control-plane/inference/providers/deterministic/disable"),
        query={},
        headers=_headers(step_up=False),
        body=_body({"expected_revision": 1}),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["status"] == "disabled"
    assert payload["revision"] == 2
    assert boundary.calls == 1
    assert _StepUp.calls == []


@pytest.mark.asyncio
async def test_inference_http_enable_requires_action_bound_step_up() -> None:
    adapter, _boundary, _step_up, authentication = _adapter()

    disabled_status, disabled, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/inference/models/deterministic/chat/disable",
        query={},
        headers=_headers(step_up=False),
        body=_body({"expected_revision": 1}),
        server_origin=_ORIGIN,
    )
    enabled_status, enabled, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/inference/models/deterministic/chat/enable",
        query={},
        headers=_headers(),
        body=_body({"expected_revision": disabled["revision"]}),
        server_origin=_ORIGIN,
    )

    assert disabled_status is HTTPStatus.OK
    assert enabled_status is HTTPStatus.OK
    assert enabled["status"] == "active"
    assert _StepUp.calls[-1][2] is (ControlPlaneStepUpAction.ENABLE_INFERENCE_MODEL)


@pytest.mark.asyncio
async def test_inference_http_rejects_non_maintainer_without_inventory_leak() -> None:
    adapter, _boundary, _step_up, authentication = _adapter(maintainer=False)

    status, payload, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/inference/providers/deterministic",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}


@pytest.mark.asyncio
async def test_inference_http_maps_revision_and_protection_failures_safely() -> None:
    adapter, _boundary, _step_up, authentication = _adapter()

    conflict_status, conflict, _headers_out = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=("/v1/control-plane/inference/providers/deterministic/disable"),
        query={},
        headers=_headers(step_up=False),
        body=_body({"expected_revision": 99}),
        server_origin=_ORIGIN,
    )

    rejected_adapter, _boundary, _step_up, rejected_auth = _adapter(reject_step_up=True)
    rejected_status, rejected, _headers_out = await rejected_adapter.dispatch(
        authentication=rejected_auth,
        method="POST",
        path=("/v1/control-plane/inference/providers/deterministic/enable"),
        query={},
        headers=_headers(),
        body=_body({"expected_revision": 1}),
        server_origin=_ORIGIN,
    )

    assert conflict_status is HTTPStatus.CONFLICT
    assert conflict == {"error": "inference_conflict"}
    assert rejected_status is HTTPStatus.FORBIDDEN
    assert rejected == {"error": "request_rejected"}
