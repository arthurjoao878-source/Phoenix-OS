from datetime import timedelta

import pytest

from phoenix_os.events import EventBus
from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceAdmissionLimits,
    InferenceExecutionLimits,
    InferenceProviderConfiguration,
    InferenceServiceConfiguration,
    ModelCapabilities,
    ModelCredentialPolicy,
    ModelDescriptor,
    ModelEndpointPolicy,
    ModelId,
    ModelProviderId,
    create_inference_runtime_stack,
)
from phoenix_os.policy import PolicyEngine
from phoenix_os.secrets import SecretRef


def _descriptor(
    provider: str = "deterministic",
    model: str = "chat",
) -> ModelDescriptor:
    return ModelDescriptor(
        provider_id=ModelProviderId(provider),
        model_id=ModelId(model),
        provider_model_name=model,
        capabilities=ModelCapabilities(complete=True, streaming=True),
    )


def _configuration(
    provider: str = "deterministic",
) -> InferenceServiceConfiguration:
    return InferenceServiceConfiguration(
        providers=(InferenceProviderConfiguration(ModelProviderId(provider)),),
        models=(_descriptor(provider),),
    )


def test_provider_configuration_accepts_typed_endpoint_and_credential_policies() -> None:
    provider = InferenceProviderConfiguration(
        ModelProviderId("hosted"),
        endpoint_policy=ModelEndpointPolicy("https://api.example.com/v1"),
        credential_policy=ModelCredentialPolicy(
            SecretRef("api-key", namespace="models", version=3)
        ),
        metadata={"Region": "test"},
    )

    assert provider.endpoint_policy is not None
    assert provider.endpoint_policy.url == "https://api.example.com/v1"
    assert provider.credential_policy is not None
    assert provider.credential_policy.secret_ref.version == 3
    assert provider.metadata == {"region": "test"}
    assert "api.example.com" not in repr(provider)
    assert "api-key" not in repr(provider)


def test_service_configuration_is_finite_and_immutable() -> None:
    configuration = InferenceServiceConfiguration(
        providers=(InferenceProviderConfiguration(ModelProviderId("deterministic")),),
        models=(_descriptor(),),
        execution_limits=InferenceExecutionLimits(
            total_timeout=timedelta(seconds=10),
        ),
        admission_limits=InferenceAdmissionLimits(
            global_concurrency=4,
            provider_concurrency=2,
            model_concurrency=1,
        ),
        drain_timeout=timedelta(seconds=2),
        source="Phoenix.Inference",
    )

    assert configuration.provider_ids == (ModelProviderId("deterministic"),)
    assert configuration.source == "phoenix.inference"
    assert configuration.models[0].model_id == ModelId("chat")


def test_configuration_rejects_duplicate_or_unbound_entries() -> None:
    provider = InferenceProviderConfiguration(ModelProviderId("deterministic"))

    with pytest.raises(ValueError, match="duplicate providers"):
        InferenceServiceConfiguration(
            providers=(provider, provider),
            models=(_descriptor(),),
        )

    with pytest.raises(ValueError, match="unconfigured provider"):
        InferenceServiceConfiguration(
            providers=(provider,),
            models=(_descriptor("other"),),
        )

    with pytest.raises(ValueError, match="requires a model"):
        InferenceServiceConfiguration(
            providers=(
                provider,
                InferenceProviderConfiguration(ModelProviderId("unused")),
            ),
            models=(_descriptor(),),
        )


def test_configuration_requires_finite_drain_timeout() -> None:
    with pytest.raises(ValueError, match="positive"):
        InferenceServiceConfiguration(
            providers=(InferenceProviderConfiguration(ModelProviderId("deterministic")),),
            models=(_descriptor(),),
            drain_timeout=timedelta(0),
        )


def test_composition_requires_exactly_configured_installed_providers() -> None:
    configuration = _configuration()

    with pytest.raises(ValueError, match="exactly match"):
        create_inference_runtime_stack(
            configuration=configuration,
            providers=(),
            policy=PolicyEngine(),
            events=EventBus(),
        )

    with pytest.raises(ValueError, match="exactly match"):
        create_inference_runtime_stack(
            configuration=configuration,
            providers=(
                DeterministicModelProvider(
                    {"chat": "ok"},
                    provider_id="deterministic",
                ),
                DeterministicModelProvider(
                    {"chat": "extra"},
                    provider_id="extra",
                ),
            ),
            policy=PolicyEngine(),
            events=EventBus(),
        )


def test_composition_registers_configuration_order_deterministically() -> None:
    configuration = InferenceServiceConfiguration(
        providers=(
            InferenceProviderConfiguration(ModelProviderId("one")),
            InferenceProviderConfiguration(ModelProviderId("two")),
        ),
        models=(
            _descriptor("one"),
            _descriptor("two"),
        ),
    )
    stack = create_inference_runtime_stack(
        configuration=configuration,
        providers=(
            DeterministicModelProvider({"chat": "one"}, provider_id="one"),
            DeterministicModelProvider({"chat": "two"}, provider_id="two"),
        ),
        policy=PolicyEngine(),
        events=EventBus(),
    )

    assert stack.registry.list_provider_ids() == (
        ModelProviderId("one"),
        ModelProviderId("two"),
    )
    assert tuple(model.provider_id for model in stack.registry.list_models()) == (
        ModelProviderId("one"),
        ModelProviderId("two"),
    )


def test_credential_backed_composition_requires_secrets_manager() -> None:
    configuration = InferenceServiceConfiguration(
        providers=(
            InferenceProviderConfiguration(
                ModelProviderId("hosted"),
                credential_policy=ModelCredentialPolicy(SecretRef("api-key", version=1)),
            ),
        ),
        models=(_descriptor("hosted"),),
    )

    with pytest.raises(ValueError, match="SecretsManager"):
        create_inference_runtime_stack(
            configuration=configuration,
            providers=(
                DeterministicModelProvider(
                    {"chat": "ok"},
                    provider_id="hosted",
                ),
            ),
            policy=PolicyEngine(),
            events=EventBus(),
        )
