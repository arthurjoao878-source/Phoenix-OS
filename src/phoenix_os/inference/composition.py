"""Deterministic optional composition for the inference subsystem."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from phoenix_os.audit import AuditLedger
from phoenix_os.events import EventBus
from phoenix_os.inference.administration import InferenceAdministration
from phoenix_os.inference.admission import InferenceAdmissionController
from phoenix_os.inference.authorization import PolicyEngineInferenceAuthorizer
from phoenix_os.inference.configuration import (
    InferenceProviderConfiguration,
    InferenceServiceConfiguration,
)
from phoenix_os.inference.contracts import (
    ModelDescriptor,
    ModelProvider,
    ModelProviderId,
)
from phoenix_os.inference.execution import InferenceRuntime
from phoenix_os.inference.registry import ModelProviderRegistry
from phoenix_os.inference.service import InferenceService
from phoenix_os.observability import ObservabilityHub
from phoenix_os.policy import PolicyEngine
from phoenix_os.secrets import SecretsManager


@dataclass(frozen=True, slots=True)
class InferenceRuntimeStack:
    """Reviewed services created for one enabled inference subsystem."""

    configuration: InferenceServiceConfiguration
    registry: ModelProviderRegistry
    runtime: InferenceRuntime
    service: InferenceService
    administration: InferenceAdministration


@runtime_checkable
class InferenceConfigurationBoundProvider(ModelProvider, Protocol):
    """Installed adapter bound to the exact reviewed provider/model configuration."""

    @property
    def provider_configuration(self) -> InferenceProviderConfiguration: ...

    @property
    def model_descriptors(self) -> tuple[ModelDescriptor, ...]: ...


def _validate_configuration_bound_provider(
    provider: ModelProvider,
    configuration: InferenceServiceConfiguration,
) -> None:
    if not isinstance(provider, InferenceConfigurationBoundProvider):
        return

    provider_configuration = provider.provider_configuration
    if not isinstance(provider_configuration, InferenceProviderConfiguration):
        raise TypeError(
            "configuration-bound inference provider must expose InferenceProviderConfiguration"
        )

    expected_provider_configuration = next(
        (item for item in configuration.providers if item.provider_id == provider.provider_id),
        None,
    )
    if provider_configuration != expected_provider_configuration:
        raise ValueError("configuration-bound inference provider configuration mismatch")

    descriptors = provider.model_descriptors
    if not isinstance(descriptors, tuple):
        raise TypeError("configuration-bound inference provider model_descriptors must be a tuple")
    if any(not isinstance(item, ModelDescriptor) for item in descriptors):
        raise TypeError(
            "configuration-bound inference provider descriptors must be ModelDescriptor values"
        )

    provider_models: dict[object, ModelDescriptor] = {}
    for descriptor in descriptors:
        if descriptor.provider_id != provider.provider_id:
            raise ValueError("configuration-bound inference provider descriptor provider mismatch")
        if descriptor.model_id in provider_models:
            raise ValueError(
                "configuration-bound inference provider contains duplicate model descriptors"
            )
        provider_models[descriptor.model_id] = descriptor

    configured_models = {
        descriptor.model_id: descriptor
        for descriptor in configuration.models
        if descriptor.provider_id == provider.provider_id
    }
    if provider_models != configured_models:
        raise ValueError("configuration-bound inference provider model descriptor mismatch")


def create_inference_runtime_stack(
    *,
    configuration: InferenceServiceConfiguration,
    providers: Iterable[ModelProvider],
    policy: PolicyEngine,
    events: EventBus,
    secrets: SecretsManager | None = None,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> InferenceRuntimeStack:
    """Validate installed adapters and compose a closed provider registry."""

    if not isinstance(configuration, InferenceServiceConfiguration):
        raise TypeError("configuration must be InferenceServiceConfiguration")
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be PolicyEngine")
    if not isinstance(events, EventBus):
        raise TypeError("events must be EventBus")
    if secrets is not None and not isinstance(secrets, SecretsManager):
        raise TypeError("secrets must be SecretsManager")
    if (
        any(provider.credential_policy is not None for provider in configuration.providers)
        and secrets is None
    ):
        raise ValueError("credential-backed inference providers require a SecretsManager")
    if audit is not None and not isinstance(audit, AuditLedger):
        raise TypeError("audit must be AuditLedger")
    if observability is not None and not isinstance(
        observability,
        ObservabilityHub,
    ):
        raise TypeError("observability must be ObservabilityHub")

    installed: dict[ModelProviderId, ModelProvider] = {}
    for provider in tuple(providers):
        provider_id = getattr(provider, "provider_id", None)
        if not isinstance(provider_id, ModelProviderId):
            raise TypeError("installed provider must expose ModelProviderId")
        if provider_id in installed:
            raise ValueError("installed inference providers contain a duplicate")
        installed[provider_id] = provider

    configured_ids = set(configuration.provider_ids)
    if set(installed) != configured_ids:
        raise ValueError("installed inference providers must exactly match configuration")

    for provider in installed.values():
        _validate_configuration_bound_provider(provider, configuration)

    registry = ModelProviderRegistry()
    try:
        for provider_config in configuration.providers:
            registry.register_provider(installed[provider_config.provider_id])
        for descriptor in configuration.models:
            registry.register_model(descriptor)

        runtime = InferenceRuntime(
            registry,
            PolicyEngineInferenceAuthorizer(policy),
            execution_limits=configuration.execution_limits,
            admission=InferenceAdmissionController(
                configuration.admission_limits,
            ),
        )
        service = InferenceService(
            runtime,
            registry,
            configuration,
            events=events,
            audit=audit,
            observability=observability,
        )
        administration = InferenceAdministration(
            registry,
            service,
            configuration,
            events=events,
            audit=audit,
            observability=observability,
        )
    except BaseException:
        registry.close()
        raise

    return InferenceRuntimeStack(
        configuration=configuration,
        registry=registry,
        runtime=runtime,
        service=service,
        administration=administration,
    )
