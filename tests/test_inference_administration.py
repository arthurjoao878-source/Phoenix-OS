from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.events import Event, EventBus
from phoenix_os.inference import (
    INFERENCE_HEALTH_READ_PERMISSION,
    INFERENCE_MODELS_DISABLE_PERMISSION,
    INFERENCE_MODELS_ENABLE_PERMISSION,
    INFERENCE_MODELS_READ_PERMISSION,
    INFERENCE_PROVIDERS_DISABLE_PERMISSION,
    INFERENCE_PROVIDERS_ENABLE_PERMISSION,
    INFERENCE_PROVIDERS_READ_PERMISSION,
    DeterministicModelProvider,
    InferenceAdministrationAccessDeniedError,
    InferenceAdministrationConflictError,
    InferenceAdminPageRequest,
    InferenceMessage,
    InferenceProviderConfiguration,
    InferenceRequest,
    InferenceRole,
    InferenceRuntimeStack,
    InferenceServiceConfiguration,
    ModelCapabilities,
    ModelDescriptor,
    ModelEndpointPolicy,
    ModelId,
    ModelProviderExecutionError,
    ModelProviderId,
    create_inference_runtime_stack,
    inference_administration_snapshot_to_dict,
    inference_model_resource,
    inference_model_view_to_dict,
    inference_provider_resource,
    inference_provider_view_to_dict,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.runtime import RuntimeContext


def _configuration() -> InferenceServiceConfiguration:
    return InferenceServiceConfiguration(
        providers=(
            InferenceProviderConfiguration(
                ModelProviderId("deterministic"),
                endpoint_policy=ModelEndpointPolicy("https://api.example.test/v1"),
            ),
        ),
        models=(
            ModelDescriptor(
                provider_id=ModelProviderId("deterministic"),
                model_id=ModelId("chat"),
                provider_model_name="private-provider-model-name",
                capabilities=ModelCapabilities(complete=True, streaming=True),
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
                resources=frozenset({"model-provider:deterministic/model:chat"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )


def _admin_context() -> SecurityContext:
    return SecurityContext(
        principal="operator:maintainer",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(
            {
                INFERENCE_PROVIDERS_READ_PERMISSION,
                INFERENCE_PROVIDERS_DISABLE_PERMISSION,
                INFERENCE_PROVIDERS_ENABLE_PERMISSION,
                INFERENCE_MODELS_READ_PERMISSION,
                INFERENCE_MODELS_DISABLE_PERMISSION,
                INFERENCE_MODELS_ENABLE_PERMISSION,
                INFERENCE_HEALTH_READ_PERMISSION,
            }
        ),
        correlation_id="admin-correlation",
    )


def _service_context(resource: str, permission: str) -> SecurityContext:
    return SecurityContext(
        principal="service:inference-admin",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({permission}),
        attributes={"resource": resource},
    )


def _request() -> InferenceRequest:
    now = datetime.now(UTC)
    return InferenceRequest(
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        messages=(InferenceMessage(InferenceRole.USER, "PROMPT-MUST-NOT-LEAK"),),
        created_at=now,
        deadline=now + timedelta(minutes=1),
    )


def _inference_context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _stack(events: EventBus | None = None) -> InferenceRuntimeStack:
    return create_inference_runtime_stack(
        configuration=_configuration(),
        providers=(
            DeterministicModelProvider(
                {"chat": "RESPONSE-MUST-NOT-LEAK"},
                provider_id="deterministic",
            ),
        ),
        policy=_policy(),
        events=EventBus() if events is None else events,
    )


@pytest.mark.asyncio
async def test_administration_lists_only_allowlisted_provider_and_model_metadata() -> None:
    stack = _stack()
    context = _admin_context()

    providers = await stack.administration.list_providers(
        context,
        InferenceAdminPageRequest(limit=10),
    )
    models = await stack.administration.list_models(context)

    provider_document = inference_provider_view_to_dict(providers.items[0])
    model_document = inference_model_view_to_dict(models.items[0])
    serialized = repr((provider_document, model_document))

    assert provider_document["provider_id"] == "deterministic"
    assert provider_document["endpoint_mode"] == "hosted_https"
    assert provider_document["credential_configured"] is False
    assert model_document["model_id"] == "chat"
    assert "api.example.test" not in serialized
    assert "private-provider-model-name" not in serialized
    assert "MODEL-METADATA-MUST-NOT-LEAK" not in serialized
    assert "PROMPT-MUST-NOT-LEAK" not in serialized
    assert "RESPONSE-MUST-NOT-LEAK" not in serialized


@pytest.mark.asyncio
async def test_provider_and_model_lifecycle_use_optimistic_revisions() -> None:
    stack = _stack()
    context = _admin_context()

    provider = await stack.administration.provider("deterministic", context)
    disabled_provider = await stack.administration.set_provider_enabled(
        "deterministic",
        context,
        enabled=False,
        expected_revision=provider.revision,
    )
    assert disabled_provider.status.value == "disabled"
    assert disabled_provider.revision == provider.revision + 1

    with pytest.raises(InferenceAdministrationConflictError):
        await stack.administration.set_provider_enabled(
            "deterministic",
            context,
            enabled=True,
            expected_revision=provider.revision,
        )

    enabled_provider = await stack.administration.set_provider_enabled(
        "deterministic",
        context,
        enabled=True,
        expected_revision=disabled_provider.revision,
    )
    assert enabled_provider.status.value == "active"

    model = await stack.administration.model("deterministic", "chat", context)
    disabled_model = await stack.administration.set_model_enabled(
        "deterministic",
        "chat",
        context,
        enabled=False,
        expected_revision=model.revision,
    )
    assert disabled_model.status.value == "disabled"


@pytest.mark.asyncio
async def test_disabled_registration_rejects_new_execution_after_authorization() -> None:
    stack = _stack()
    runtime_context = RuntimeContext(services={})
    await stack.service.start(runtime_context)
    context = _admin_context()
    model = await stack.administration.model("deterministic", "chat", context)
    await stack.administration.set_model_enabled(
        "deterministic",
        "chat",
        context,
        enabled=False,
        expected_revision=model.revision,
    )

    with pytest.raises(ModelProviderExecutionError):
        await stack.service.infer(_request(), _inference_context())

    await stack.service.stop(runtime_context)


@pytest.mark.asyncio
async def test_service_account_context_requires_the_exact_concrete_resource() -> None:
    stack = _stack()
    provider_resource = inference_provider_resource("deterministic")

    provider = await stack.administration.provider(
        "deterministic",
        _service_context(provider_resource, INFERENCE_PROVIDERS_READ_PERMISSION),
    )
    assert str(provider.provider_id) == "deterministic"

    with pytest.raises(InferenceAdministrationAccessDeniedError):
        await stack.administration.provider(
            "deterministic",
            _service_context(
                inference_model_resource(ModelProviderId("deterministic"), ModelId("chat")),
                INFERENCE_PROVIDERS_READ_PERMISSION,
            ),
        )


@pytest.mark.asyncio
async def test_health_snapshot_is_content_free_and_bounded() -> None:
    stack = _stack()
    snapshot = await stack.administration.snapshot(_admin_context())
    document = inference_administration_snapshot_to_dict(snapshot)
    serialized = repr(document)

    assert document["providers"] == {"providers": 1, "enabled": 1}
    assert document["models"] == {"models": 1, "enabled": 1}
    invocations = document["invocations"]
    assert isinstance(invocations, dict)
    assert invocations["active"] == 0
    assert "PROMPT-MUST-NOT-LEAK" not in serialized
    assert "RESPONSE-MUST-NOT-LEAK" not in serialized
    assert "api.example.test" not in serialized


@pytest.mark.asyncio
async def test_lifecycle_events_have_empty_payloads_and_safe_metadata() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("inference.provider."):
            captured.append(event)

    await events.subscribe("*", capture)
    stack = _stack(events)
    context = _admin_context()
    provider = await stack.administration.provider("deterministic", context)

    await stack.administration.set_provider_enabled(
        "deterministic",
        context,
        enabled=False,
        expected_revision=provider.revision,
    )

    assert len(captured) == 1
    assert captured[0].payload == {}
    assert captured[0].metadata["identifier"] == "deterministic"
    assert captured[0].metadata["status"] == "disabled"
    assert "PROMPT-MUST-NOT-LEAK" not in repr(captured[0])
