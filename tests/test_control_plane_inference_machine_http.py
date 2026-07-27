from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from uuid import UUID

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    Configuration,
    EventBus,
    Kernel,
    Router,
    RuntimeAssembler,
)
from phoenix_os.control_plane import (
    CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH,
    CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE,
    ControlPlaneInferenceMachineAdministration,
    ControlPlaneNetworkPolicy,
    ControlPlaneOperatorToken,
    control_plane_inference_machine_routes,
)
from phoenix_os.control_plane import (
    service_account_authentication as service_account_authentication_module,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentitySource,
)
from phoenix_os.control_plane.service_account_audit import (
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditProtector,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRequest,
)
from phoenix_os.inference import (
    INFERENCE_HEALTH_READ_PERMISSION,
    INFERENCE_MODELS_DISABLE_PERMISSION,
    INFERENCE_MODELS_ENABLE_PERMISSION,
    INFERENCE_MODELS_READ_PERMISSION,
    INFERENCE_PROVIDERS_DISABLE_PERMISSION,
    INFERENCE_PROVIDERS_ENABLE_PERMISSION,
    INFERENCE_PROVIDERS_READ_PERMISSION,
    INFERENCE_RUNTIME_RESOURCE,
    DeterministicModelProvider,
    InferenceAdministration,
    InferenceProviderConfiguration,
    InferenceServiceConfiguration,
    ModelCapabilities,
    ModelDescriptor,
    ModelEndpointPolicy,
    ModelId,
    ModelProviderId,
    create_inference_runtime_stack,
    inference_model_resource,
    inference_provider_resource,
)
from phoenix_os.policy import PolicyEngine

_NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
_ACCOUNT_ID = UUID("10000000-0000-4000-8000-000000000026")
_TOKEN_ID = UUID("20000000-0000-4000-8000-000000000026")
_PROVIDER_ID = ModelProviderId("deterministic")
_MODEL_ID = ModelId("chat")

_HEALTH = f"{CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH}/health"
_PROVIDER = f"{CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH}/provider"
_PROVIDER_DISABLE = f"{_PROVIDER}/disable"
_PROVIDER_ENABLE = f"{_PROVIDER}/enable"
_MODEL = f"{CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH}/model"
_MODEL_DISABLE = f"{_MODEL}/disable"
_MODEL_ENABLE = f"{_MODEL}/enable"

_ALL_SCOPES = frozenset(
    {
        INFERENCE_HEALTH_READ_PERMISSION,
        INFERENCE_PROVIDERS_READ_PERMISSION,
        INFERENCE_PROVIDERS_DISABLE_PERMISSION,
        INFERENCE_PROVIDERS_ENABLE_PERMISSION,
        INFERENCE_MODELS_READ_PERMISSION,
        INFERENCE_MODELS_DISABLE_PERMISSION,
        INFERENCE_MODELS_ENABLE_PERMISSION,
    }
)


class _Authentication:
    def __init__(
        self,
        evidence: (ControlPlaneServiceAccountAuthentication | None),
    ) -> None:
        self.evidence = evidence
        self.calls = 0

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext),
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        del authorization, context, request
        self.calls += 1
        return self.evidence


class _Policy:
    def __init__(
        self,
        *,
        denied: bool = False,
    ) -> None:
        self.denied = denied
        self.calls: list[tuple[str, str]] = []

    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> object:
        del context
        self.calls.append((action, resource))
        if self.denied:
            raise ControlPlaneServiceAccountPermissionDeniedError(
                "service-account authorization denied"
            )
        return object()


def _configuration() -> InferenceServiceConfiguration:
    return InferenceServiceConfiguration(
        providers=(
            InferenceProviderConfiguration(
                _PROVIDER_ID,
                endpoint_policy=ModelEndpointPolicy("https://api.example.test/private"),
                metadata={"private": ("PROVIDER-METADATA-MUST-NOT-LEAK")},
            ),
        ),
        models=(
            ModelDescriptor(
                provider_id=_PROVIDER_ID,
                model_id=_MODEL_ID,
                provider_model_name=("PRIVATE-PROVIDER-MODEL-NAME"),
                capabilities=ModelCapabilities(
                    complete=True,
                    streaming=True,
                ),
                metadata={"private": "MODEL-METADATA-MUST-NOT-LEAK"},
            ),
        ),
    )


def _administration() -> InferenceAdministration:
    stack = create_inference_runtime_stack(
        configuration=_configuration(),
        providers=(
            DeterministicModelProvider(
                {
                    "chat": "RESPONSE-MUST-NOT-LEAK",
                },
                provider_id="deterministic",
            ),
        ),
        policy=PolicyEngine(),
        events=EventBus(),
    )
    return stack.administration


def _resources() -> frozenset[str]:
    return frozenset(
        {
            CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE,
            INFERENCE_RUNTIME_RESOURCE,
            inference_provider_resource(_PROVIDER_ID),
            inference_model_resource(
                _PROVIDER_ID,
                _MODEL_ID,
            ),
        }
    )


def _evidence(
    *,
    scopes: frozenset[str] = _ALL_SCOPES,
    resources: frozenset[str] | None = None,
) -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="inference.bot",
        scopes=scopes,
        resources=(_resources() if resources is None else resources),
        token_version=1,
        account_revision=1,
        token_revision=1,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )


def _transport_context() -> ControlPlaneServiceAccountAuthenticationContext:
    return ControlPlaneServiceAccountAuthenticationContext(
        client_address="127.0.0.1",
        peer_address="127.0.0.1",
        identity_source=(ControlPlaneClientIdentitySource.DIRECT),
        _authority=(service_account_authentication_module._CONTEXT_AUTHORITY),
    )


def _system(
    *,
    evidence: (ControlPlaneServiceAccountAuthentication | None) = None,
    policy_denied: bool = False,
) -> tuple[
    InferenceAdministration,
    ControlPlaneServiceAccountMachineHttpAdapter,
    _Authentication,
    _Policy,
]:
    administration = _administration()
    authentication = _Authentication(_evidence() if evidence is None else evidence)
    policy = _Policy(denied=policy_denied)
    audit = ControlPlaneServiceAccountAudit(
        None,
        ControlPlaneServiceAccountAuditProtector(b"a" * 32),
    )
    adapter = ControlPlaneServiceAccountMachineHttpAdapter(
        authentication=authentication,
        policy=policy,
        audit=audit,
        routes=control_plane_inference_machine_routes(administration),
    )
    return (
        administration,
        adapter,
        authentication,
        policy,
    )


def _headers() -> dict[str, tuple[str, ...]]:
    return {
        "authorization": ("Bearer phx_sa_" + "A" * 48,),
        "x-phoenix-request-nonce": ("N" * 32,),
        "x-phoenix-request-timestamp": (_NOW.isoformat(),),
        "content-type": ("application/json",),
    }


async def _dispatch(
    adapter: ControlPlaneServiceAccountMachineHttpAdapter,
    *,
    method: str,
    path: str,
    query: (Mapping[str, tuple[str, ...]] | None) = None,
    document: Mapping[str, object] | None = None,
    headers: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[
    HTTPStatus,
    Mapping[str, object],
    dict[str, str],
]:
    return await adapter.dispatch(
        context=_transport_context(),
        method=method,
        path=path,
        query={} if query is None else query,
        headers=(_headers() if headers is None else headers),
        body=(b"" if document is None else json.dumps(dict(document)).encode("utf-8")),
    )


@pytest.mark.asyncio
async def test_machine_inventory_and_health_are_content_free() -> None:
    (
        administration,
        adapter,
        authentication,
        policy,
    ) = _system()

    health_status, health, health_headers = await _dispatch(
        adapter,
        method="GET",
        path=_HEALTH,
    )
    provider_status, provider, provider_headers = await _dispatch(
        adapter,
        method="GET",
        path=_PROVIDER,
        query={
            "provider_id": (str(_PROVIDER_ID),),
        },
    )
    model_status, model, model_headers = await _dispatch(
        adapter,
        method="GET",
        path=_MODEL,
        query={
            "provider_id": (str(_PROVIDER_ID),),
            "model_id": (str(_MODEL_ID),),
        },
    )

    serialized = repr(
        (
            health,
            provider,
            model,
        )
    )

    assert isinstance(
        ControlPlaneInferenceMachineAdministration(administration),
        ControlPlaneInferenceMachineAdministration,
    )
    assert health_status is HTTPStatus.OK
    assert provider_status is HTTPStatus.OK
    assert model_status is HTTPStatus.OK
    assert health_headers == {"Cache-Control": "no-store"}
    assert provider_headers == {"Cache-Control": "no-store"}
    assert model_headers == {"Cache-Control": "no-store"}
    assert provider["provider_id"] == "deterministic"
    assert model["model_id"] == "chat"
    assert authentication.calls == 3
    assert all(
        resource == CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE for _action, resource in policy.calls
    )

    forbidden = (
        "api.example.test",
        "PRIVATE-PROVIDER-MODEL-NAME",
        "PROVIDER-METADATA-MUST-NOT-LEAK",
        "MODEL-METADATA-MUST-NOT-LEAK",
        "RESPONSE-MUST-NOT-LEAK",
    )
    for value in forbidden:
        assert value not in serialized


@pytest.mark.asyncio
async def test_machine_lifecycle_uses_exact_revisions() -> None:
    _administration_service, adapter, _auth, _policy = _system()

    provider_disabled_status, provider_disabled, _ = await _dispatch(
        adapter,
        method="POST",
        path=_PROVIDER_DISABLE,
        document={
            "provider_id": str(_PROVIDER_ID),
            "expected_revision": 1,
        },
    )
    provider_enabled_status, provider_enabled, _ = await _dispatch(
        adapter,
        method="POST",
        path=_PROVIDER_ENABLE,
        document={
            "provider_id": str(_PROVIDER_ID),
            "expected_revision": (provider_disabled["revision"]),
        },
    )
    model_disabled_status, model_disabled, _ = await _dispatch(
        adapter,
        method="POST",
        path=_MODEL_DISABLE,
        document={
            "provider_id": str(_PROVIDER_ID),
            "model_id": str(_MODEL_ID),
            "expected_revision": 1,
        },
    )
    model_enabled_status, model_enabled, _ = await _dispatch(
        adapter,
        method="POST",
        path=_MODEL_ENABLE,
        document={
            "provider_id": str(_PROVIDER_ID),
            "model_id": str(_MODEL_ID),
            "expected_revision": (model_disabled["revision"]),
        },
    )

    assert provider_disabled_status is HTTPStatus.OK
    assert provider_disabled["status"] == "disabled"
    assert provider_enabled_status is HTTPStatus.OK
    assert provider_enabled["status"] == "active"
    assert model_disabled_status is HTTPStatus.OK
    assert model_disabled["status"] == "disabled"
    assert model_enabled_status is HTTPStatus.OK
    assert model_enabled["status"] == "active"


@pytest.mark.asyncio
async def test_machine_routes_require_exact_scope_and_resource() -> None:
    missing_scope = _evidence(
        scopes=frozenset(
            _ALL_SCOPES
            - {
                INFERENCE_MODELS_DISABLE_PERMISSION,
            }
        )
    )
    _administration_service, adapter, _auth, _policy = _system(evidence=missing_scope)

    scope_status, scope_payload, _ = await _dispatch(
        adapter,
        method="POST",
        path=_MODEL_DISABLE,
        document={
            "provider_id": str(_PROVIDER_ID),
            "model_id": str(_MODEL_ID),
            "expected_revision": 1,
        },
    )

    missing_resource = _evidence(
        resources=frozenset(
            {
                CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE,
                INFERENCE_RUNTIME_RESOURCE,
                inference_provider_resource(_PROVIDER_ID),
            }
        )
    )
    (
        _administration_service,
        resource_adapter,
        _auth,
        _policy,
    ) = _system(evidence=missing_resource)

    resource_status, resource_payload, _ = await _dispatch(
        resource_adapter,
        method="GET",
        path=_MODEL,
        query={
            "provider_id": (str(_PROVIDER_ID),),
            "model_id": (str(_MODEL_ID),),
        },
    )

    assert scope_status is HTTPStatus.FORBIDDEN
    assert scope_payload == {"error": "forbidden"}
    assert resource_status is HTTPStatus.FORBIDDEN
    assert resource_payload == {"error": "forbidden"}


@pytest.mark.asyncio
async def test_machine_routes_fail_closed_for_invalid_requests() -> None:
    _administration_service, adapter, _auth, _policy = _system()

    bad_query_status, bad_query, _ = await _dispatch(
        adapter,
        method="GET",
        path=_PROVIDER,
        query={
            "provider_id": (str(_PROVIDER_ID),),
            "unexpected": ("must-not-be-accepted",),
        },
    )
    conflict_status, conflict, _ = await _dispatch(
        adapter,
        method="POST",
        path=_PROVIDER_DISABLE,
        document={
            "provider_id": str(_PROVIDER_ID),
            "expected_revision": 99,
        },
    )
    browser_status, browser, _ = await _dispatch(
        adapter,
        method="GET",
        path=_HEALTH,
        headers={
            **_headers(),
            "cookie": ("phoenix_session=must-not-be-accepted",),
        },
    )

    assert bad_query_status is HTTPStatus.BAD_REQUEST
    assert bad_query == {"error": "invalid_inference_request"}
    assert conflict_status is HTTPStatus.CONFLICT
    assert conflict == {"error": "inference_conflict"}
    assert browser_status is HTTPStatus.FORBIDDEN
    assert browser == {"error": "request_rejected"}


def _runtime_assembler(
    *,
    machine_administration: bool,
    service_accounts: bool = True,
    secure_network: bool = True,
    inference_enabled: bool = True,
) -> RuntimeAssembler:
    events = EventBus()
    arguments: dict[str, object] = {
        "kernel": Kernel(
            router=Router(),
            authorizer=AllowAllAuthorizer(),
            events=events,
        ),
        "events": events,
        "capabilities": CapabilityRegistry(events=events),
        "configuration": Configuration({}, {}),
        "policy": PolicyEngine(),
        "inference_enabled": inference_enabled,
        "inference_service_account_administration_enabled": (machine_administration),
        "control_plane_operator_token": (ControlPlaneOperatorToken("O" * 32)),
        "control_plane_service_accounts_enabled": (service_accounts),
    }

    if inference_enabled:
        arguments["inference_configuration"] = _configuration()
        arguments["inference_providers"] = (
            DeterministicModelProvider(
                {
                    "chat": "ok",
                },
                provider_id="deterministic",
            ),
        )

    if secure_network:
        arguments["control_plane_network_policy"] = ControlPlaneNetworkPolicy(
            port=45126,
            public_origin=("http://127.0.0.1:45126"),
        )

    return RuntimeAssembler(**arguments)  # type: ignore[arg-type]


def test_machine_administration_requires_inference() -> None:
    with pytest.raises(
        ValueError,
        match="require inference_enabled",
    ):
        _runtime_assembler(
            machine_administration=True,
            inference_enabled=False,
        )


def test_machine_administration_requires_service_accounts() -> None:
    with pytest.raises(
        ValueError,
        match="requires service accounts",
    ):
        _runtime_assembler(
            machine_administration=True,
            service_accounts=False,
        )


def test_machine_administration_requires_secure_network() -> None:
    with pytest.raises(
        ValueError,
        match="secure network policy",
    ):
        _runtime_assembler(
            machine_administration=True,
            secure_network=False,
        )


@pytest.mark.asyncio
async def test_machine_routes_are_opt_in_and_share_secure_listener() -> None:
    without_machine = await _runtime_assembler(
        machine_administration=False,
        secure_network=False,
    ).assemble()
    assert "control_plane.service-account-machine-http" not in without_machine.services
    await without_machine.stop()

    runtime = await _runtime_assembler(
        machine_administration=True,
    ).assemble()
    machine_http = runtime.service("control_plane.service-account-machine-http")
    assert isinstance(
        machine_http,
        ControlPlaneServiceAccountMachineHttpAdapter,
    )
    for path in (
        _HEALTH,
        _PROVIDER,
        _PROVIDER_DISABLE,
        _PROVIDER_ENABLE,
        _MODEL,
        _MODEL_DISABLE,
        _MODEL_ENABLE,
    ):
        assert machine_http.handles(path)

    assert "control_plane.secure-http" in runtime.services
    await runtime.stop()
