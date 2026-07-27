"""Deterministic optional composition for the inference subsystem."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from phoenix_os.audit import AuditLedger
from phoenix_os.events import EventBus
from phoenix_os.inference.administration import InferenceAdministration
from phoenix_os.inference.admission import InferenceAdmissionController
from phoenix_os.inference.authorization import PolicyEngineInferenceAuthorizer
from phoenix_os.inference.configuration import InferenceServiceConfiguration
from phoenix_os.inference.contracts import ModelProvider, ModelProviderId
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
