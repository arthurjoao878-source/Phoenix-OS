"""Deterministic provider and model registry for RFC-0026."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from uuid import UUID, uuid4

from phoenix_os.inference.contracts import (
    ModelCapabilities,
    ModelDescriptor,
    ModelId,
    ModelProvider,
    ModelProviderId,
    normalize_model_id,
    normalize_provider_id,
)
from phoenix_os.inference.errors import (
    InferenceRegistryClosedError,
    ModelAlreadyRegisteredError,
    ModelCapabilityMismatchError,
    ModelNotFoundError,
    ModelProviderAlreadyRegisteredError,
    ModelProviderNotFoundError,
)


@dataclass(frozen=True, slots=True)
class ModelProviderRegistration:
    id: UUID
    provider_id: ModelProviderId


@dataclass(frozen=True, slots=True)
class ModelRegistration:
    id: UUID
    provider_id: ModelProviderId
    model_id: ModelId


@dataclass(slots=True)
class _RegisteredProvider:
    registration: ModelProviderRegistration
    provider: ModelProvider
    capabilities: ModelCapabilities
    sequence: int


@dataclass(slots=True)
class _RegisteredModel:
    registration: ModelRegistration
    descriptor: ModelDescriptor
    sequence: int


class ModelProviderRegistry:
    """Own deterministic provider/model registration and compatibility checks."""

    def __init__(self) -> None:
        self._providers: dict[ModelProviderId, _RegisteredProvider] = {}
        self._models: dict[tuple[ModelProviderId, ModelId], _RegisteredModel] = {}
        self._provider_sequence = 0
        self._model_sequence = 0
        self._closed = False
        self._lock = RLock()

    @property
    def closed(self) -> bool:
        return self._closed

    def register_provider(self, provider: ModelProvider) -> ModelProviderRegistration:
        self._ensure_open()
        provider_id = getattr(provider, "provider_id", None)
        capabilities = getattr(provider, "capabilities", None)
        if not isinstance(provider_id, ModelProviderId):
            raise TypeError("provider.provider_id must be ModelProviderId")
        if not isinstance(capabilities, ModelCapabilities):
            raise TypeError("provider.capabilities must be ModelCapabilities")
        if not callable(getattr(provider, "infer", None)):
            raise TypeError("provider.infer must be callable")
        if not callable(getattr(provider, "stream", None)):
            raise TypeError("provider.stream must be callable")

        with self._lock:
            self._ensure_open()
            if provider_id in self._providers:
                raise ModelProviderAlreadyRegisteredError(
                    f"model provider already registered: {provider_id}"
                )
            registration = ModelProviderRegistration(id=uuid4(), provider_id=provider_id)
            self._providers[provider_id] = _RegisteredProvider(
                registration=registration,
                provider=provider,
                capabilities=capabilities,
                sequence=self._provider_sequence,
            )
            self._provider_sequence += 1
            return registration

    def register_model(self, descriptor: ModelDescriptor) -> ModelRegistration:
        self._ensure_open()
        if not isinstance(descriptor, ModelDescriptor):
            raise TypeError("descriptor must be ModelDescriptor")
        key = (descriptor.provider_id, descriptor.model_id)

        with self._lock:
            self._ensure_open()
            provider = self._providers.get(descriptor.provider_id)
            if provider is None:
                raise ModelProviderNotFoundError(
                    f"model provider not found: {descriptor.provider_id}"
                )
            if key in self._models:
                raise ModelAlreadyRegisteredError(
                    f"model already registered: {descriptor.provider_id}/{descriptor.model_id}"
                )
            if not provider.capabilities.supports(descriptor.capabilities):
                raise ModelCapabilityMismatchError(
                    "model capabilities exceed provider capabilities"
                )
            registration = ModelRegistration(
                id=uuid4(),
                provider_id=descriptor.provider_id,
                model_id=descriptor.model_id,
            )
            self._models[key] = _RegisteredModel(
                registration=registration,
                descriptor=descriptor,
                sequence=self._model_sequence,
            )
            self._model_sequence += 1
            return registration

    def resolve_provider(self, provider_id: ModelProviderId | str) -> ModelProvider:
        normalized = normalize_provider_id(provider_id)
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            registered = self._providers.get(normalized)
            if registered is None:
                raise ModelProviderNotFoundError(f"model provider not found: {normalized}")
            return registered.provider

    def resolve_model(
        self,
        provider_id: ModelProviderId | str,
        model_id: ModelId | str,
    ) -> ModelDescriptor:
        normalized_provider = normalize_provider_id(provider_id)
        normalized_model = normalize_model_id(model_id)
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            registered = self._models.get((normalized_provider, normalized_model))
            if registered is None:
                raise ModelNotFoundError(
                    f"model not found: {normalized_provider}/{normalized_model}"
                )
            return registered.descriptor

    def list_provider_ids(self) -> tuple[ModelProviderId, ...]:
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            ordered = sorted(self._providers.values(), key=lambda item: item.sequence)
            return tuple(item.registration.provider_id for item in ordered)

    def list_models(
        self,
        provider_id: ModelProviderId | str | None = None,
    ) -> tuple[ModelDescriptor, ...]:
        normalized = None if provider_id is None else normalize_provider_id(provider_id)
        self._ensure_open()
        with self._lock:
            self._ensure_open()
            ordered = sorted(self._models.values(), key=lambda item: item.sequence)
            return tuple(
                item.descriptor
                for item in ordered
                if normalized is None or item.descriptor.provider_id == normalized
            )

    def close(self) -> None:
        with self._lock:
            self._models.clear()
            self._providers.clear()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise InferenceRegistryClosedError("model provider registry is closed")
