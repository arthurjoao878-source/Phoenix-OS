from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
)
from phoenix_os.configuration import Configuration
from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceAdministration,
    InferenceMessage,
    InferenceProviderConfiguration,
    InferenceRequest,
    InferenceRole,
    InferenceRuntime,
    InferenceService,
    InferenceServiceConfiguration,
    InferenceServiceState,
    ModelCapabilities,
    ModelDescriptor,
    ModelId,
    ModelProviderId,
    ModelProviderRegistry,
    inference_model_resource,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)


async def _base() -> tuple[Configuration, EventBus, Kernel, CapabilityRegistry]:
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    events = EventBus()
    kernel = Kernel(
        router=Router(),
        authorizer=AllowAllAuthorizer(),
        events=events,
    )
    capabilities = CapabilityRegistry(events=events)
    return configuration, events, kernel, capabilities


def _inference_configuration() -> InferenceServiceConfiguration:
    return InferenceServiceConfiguration(
        providers=(InferenceProviderConfiguration(ModelProviderId("deterministic")),),
        models=(
            ModelDescriptor(
                provider_id=ModelProviderId("deterministic"),
                model_id=ModelId("chat"),
                provider_model_name="chat",
                capabilities=ModelCapabilities(complete=True, streaming=True),
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


def _request() -> InferenceRequest:
    now = datetime.now(UTC)
    return InferenceRequest(
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        messages=(InferenceMessage(InferenceRole.USER, "hello"),),
        created_at=now,
        deadline=now + timedelta(minutes=1),
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


@pytest.mark.asyncio
async def test_runtime_assembler_preserves_compatibility_when_inference_is_omitted() -> None:
    configuration, events, kernel, capabilities = await _base()
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
    ).assemble()

    assert "inference" not in runtime.services
    assert "inference.runtime" not in runtime.services
    assert "inference.registry" not in runtime.services
    await runtime.start()
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_composes_and_owns_enabled_inference() -> None:
    configuration, events, kernel, capabilities = await _base()
    policy = _policy()
    provider = DeterministicModelProvider(
        {"chat": "runtime inference"},
        provider_id="deterministic",
    )
    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=policy,
        inference_enabled=True,
        inference_configuration=_inference_configuration(),
        inference_providers=(provider,),
    ).assemble()

    service = runtime.service("inference")
    assert isinstance(service, InferenceService)
    assert runtime.service("inference.health") is service
    assert isinstance(runtime.service("inference.runtime"), InferenceRuntime)
    assert isinstance(runtime.service("inference.registry"), ModelProviderRegistry)
    assert isinstance(
        runtime.service("inference.administration"),
        InferenceAdministration,
    )

    await runtime.start()
    response = await service.infer(_request(), _context())
    assert response.text == "runtime inference"
    assert (await service.snapshot()).state is InferenceServiceState.RUNNING

    await runtime.stop()
    assert (await service.snapshot()).state is InferenceServiceState.STOPPED
    assert policy.closed


@pytest.mark.asyncio
async def test_inference_options_require_explicit_enablement() -> None:
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(ValueError, match="require inference_enabled"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            inference_configuration=_inference_configuration(),
        )


@pytest.mark.asyncio
async def test_enabled_inference_requires_policy_configuration_and_provider() -> None:
    configuration, events, kernel, capabilities = await _base()

    with pytest.raises(ValueError, match="PolicyEngine"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            inference_enabled=True,
            inference_configuration=_inference_configuration(),
            inference_providers=(
                DeterministicModelProvider(
                    {"chat": "ok"},
                    provider_id="deterministic",
                ),
            ),
        )

    with pytest.raises(ValueError, match="configuration"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=_policy(),
            inference_enabled=True,
            inference_providers=(
                DeterministicModelProvider(
                    {"chat": "ok"},
                    provider_id="deterministic",
                ),
            ),
        )

    with pytest.raises(ValueError, match="provider"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=_policy(),
            inference_enabled=True,
            inference_configuration=_inference_configuration(),
        )


@pytest.mark.asyncio
async def test_assembly_fails_closed_for_provider_configuration_mismatch() -> None:
    configuration, events, kernel, capabilities = await _base()
    assembler = RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=_policy(),
        inference_enabled=True,
        inference_configuration=_inference_configuration(),
        inference_providers=(
            DeterministicModelProvider(
                {"chat": "wrong"},
                provider_id="other",
            ),
        ),
    )

    with pytest.raises(ValueError, match="exactly match"):
        await assembler.assemble()
