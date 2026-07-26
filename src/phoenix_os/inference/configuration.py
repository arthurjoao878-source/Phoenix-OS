"""Typed immutable configuration for optional inference composition."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from types import MappingProxyType

from phoenix_os.inference.admission import InferenceAdmissionLimits
from phoenix_os.inference.contracts import ModelDescriptor, ModelProviderId
from phoenix_os.inference.credentials import ModelCredentialPolicy
from phoenix_os.inference.endpoints import ModelEndpointPolicy
from phoenix_os.inference.execution import InferenceExecutionLimits

MAX_INFERENCE_CONFIG_PROVIDERS = 256
MAX_INFERENCE_CONFIG_MODELS = 4_096
MAX_INFERENCE_CONFIG_METADATA_ITEMS = 64
MAX_INFERENCE_CONFIG_METADATA_TEXT = 1_024
MAX_INFERENCE_DRAIN_TIMEOUT = timedelta(minutes=5)

_SOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")


def _freeze_metadata(values: Mapping[str, str]) -> Mapping[str, str]:
    if len(values) > MAX_INFERENCE_CONFIG_METADATA_ITEMS:
        raise ValueError("inference provider metadata exceeds the supported item count")
    frozen: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("inference provider metadata must contain strings")
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if not normalized_key or not normalized_value:
            raise ValueError("inference provider metadata must not contain blank values")
        if (
            len(normalized_key) > MAX_INFERENCE_CONFIG_METADATA_TEXT
            or len(normalized_value) > MAX_INFERENCE_CONFIG_METADATA_TEXT
        ):
            raise ValueError("inference provider metadata exceeds the supported text length")
        if normalized_key in frozen:
            raise ValueError("inference provider metadata contains duplicate normalized keys")
        frozen[normalized_key] = normalized_value
    return MappingProxyType(frozen)


@dataclass(frozen=True, slots=True)
class InferenceProviderConfiguration:
    """One reviewed provider registration and its optional security policies."""

    provider_id: ModelProviderId
    endpoint_policy: ModelEndpointPolicy | None = field(default=None, repr=False)
    credential_policy: ModelCredentialPolicy | None = field(default=None, repr=False)
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if self.endpoint_policy is not None and not isinstance(
            self.endpoint_policy,
            ModelEndpointPolicy,
        ):
            raise TypeError("endpoint_policy must be ModelEndpointPolicy")
        if self.credential_policy is not None and not isinstance(
            self.credential_policy,
            ModelCredentialPolicy,
        ):
            raise TypeError("credential_policy must be ModelCredentialPolicy")
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class InferenceServiceConfiguration:
    """Finite configuration for one optional Runtime-owned inference service."""

    providers: tuple[InferenceProviderConfiguration, ...]
    models: tuple[ModelDescriptor, ...]
    execution_limits: InferenceExecutionLimits = field(default_factory=InferenceExecutionLimits)
    admission_limits: InferenceAdmissionLimits = field(default_factory=InferenceAdmissionLimits)
    drain_timeout: timedelta = timedelta(seconds=5)
    source: str = "phoenix.inference"

    def __post_init__(self) -> None:
        providers = tuple(self.providers)
        models = tuple(self.models)
        if not providers:
            raise ValueError("enabled inference requires at least one provider")
        if len(providers) > MAX_INFERENCE_CONFIG_PROVIDERS:
            raise ValueError("inference provider configuration exceeds the supported count")
        if not models:
            raise ValueError("enabled inference requires at least one model")
        if len(models) > MAX_INFERENCE_CONFIG_MODELS:
            raise ValueError("inference model configuration exceeds the supported count")
        if any(not isinstance(provider, InferenceProviderConfiguration) for provider in providers):
            raise TypeError("providers must contain InferenceProviderConfiguration values")
        if any(not isinstance(model, ModelDescriptor) for model in models):
            raise TypeError("models must contain ModelDescriptor values")
        if not isinstance(self.execution_limits, InferenceExecutionLimits):
            raise TypeError("execution_limits must be InferenceExecutionLimits")
        if not isinstance(self.admission_limits, InferenceAdmissionLimits):
            raise TypeError("admission_limits must be InferenceAdmissionLimits")
        if not isinstance(self.drain_timeout, timedelta):
            raise TypeError("drain_timeout must be timedelta")
        if self.drain_timeout <= timedelta(0):
            raise ValueError("drain_timeout must be positive")
        if self.drain_timeout > MAX_INFERENCE_DRAIN_TIMEOUT:
            raise ValueError("drain_timeout exceeds the supported maximum")

        provider_ids = tuple(provider.provider_id for provider in providers)
        if len(provider_ids) != len(set(provider_ids)):
            raise ValueError("inference configuration contains duplicate providers")

        model_keys = tuple((model.provider_id, model.model_id) for model in models)
        if len(model_keys) != len(set(model_keys)):
            raise ValueError("inference configuration contains duplicate models")

        configured_provider_ids = set(provider_ids)
        referenced_provider_ids = {model.provider_id for model in models}
        if not referenced_provider_ids.issubset(configured_provider_ids):
            raise ValueError("inference model references an unconfigured provider")
        if configured_provider_ids != referenced_provider_ids:
            raise ValueError("every configured inference provider requires a model")

        if not isinstance(self.source, str):
            raise TypeError("source must be a string")
        source = self.source.strip().lower()
        if _SOURCE_PATTERN.fullmatch(source) is None:
            raise ValueError("source must be a lowercase Phoenix identifier")

        object.__setattr__(self, "providers", providers)
        object.__setattr__(self, "models", models)
        object.__setattr__(self, "source", source)

    @property
    def provider_ids(self) -> tuple[ModelProviderId, ...]:
        return tuple(provider.provider_id for provider in self.providers)
