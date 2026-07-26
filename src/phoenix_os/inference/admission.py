"""Fail-fast global, provider, and model inference admission controls."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from phoenix_os.inference.contracts import ModelId, ModelProviderId
from phoenix_os.inference.errors import InferenceSaturatedError

MAX_INFERENCE_CONCURRENCY = 10_000


def _require_capacity(value: int, *, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > MAX_INFERENCE_CONCURRENCY:
        raise ValueError(f"{label} exceeds the supported maximum")


@dataclass(frozen=True, slots=True)
class InferenceAdmissionLimits:
    """Finite concurrency ceilings enforced without an implicit wait queue."""

    global_concurrency: int = 64
    provider_concurrency: int = 16
    model_concurrency: int = 8

    def __post_init__(self) -> None:
        _require_capacity(self.global_concurrency, label="global_concurrency")
        _require_capacity(self.provider_concurrency, label="provider_concurrency")
        _require_capacity(self.model_concurrency, label="model_concurrency")
        if self.provider_concurrency > self.global_concurrency:
            raise ValueError("provider_concurrency cannot exceed global_concurrency")
        if self.model_concurrency > self.provider_concurrency:
            raise ValueError("model_concurrency cannot exceed provider_concurrency")


class InferenceAdmissionController:
    """Atomically admit or reject one request at all three concurrency levels."""

    def __init__(self, limits: InferenceAdmissionLimits | None = None) -> None:
        self._limits = InferenceAdmissionLimits() if limits is None else limits
        if not isinstance(self._limits, InferenceAdmissionLimits):
            raise TypeError("limits must be InferenceAdmissionLimits")
        self._active_global = 0
        self._active_providers: dict[ModelProviderId, int] = {}
        self._active_models: dict[tuple[ModelProviderId, ModelId], int] = {}
        self._lock = asyncio.Lock()

    @property
    def limits(self) -> InferenceAdmissionLimits:
        return self._limits

    @asynccontextmanager
    async def admit(
        self,
        provider_id: ModelProviderId,
        model_id: ModelId,
    ) -> AsyncIterator[None]:
        if not isinstance(provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if not isinstance(model_id, ModelId):
            raise TypeError("model_id must be ModelId")

        key = (provider_id, model_id)
        async with self._lock:
            provider_active = self._active_providers.get(provider_id, 0)
            model_active = self._active_models.get(key, 0)
            if (
                self._active_global >= self._limits.global_concurrency
                or provider_active >= self._limits.provider_concurrency
                or model_active >= self._limits.model_concurrency
            ):
                raise InferenceSaturatedError()
            self._active_global += 1
            self._active_providers[provider_id] = provider_active + 1
            self._active_models[key] = model_active + 1

        try:
            yield
        finally:
            async with self._lock:
                self._active_global -= 1
                provider_remaining = self._active_providers[provider_id] - 1
                model_remaining = self._active_models[key] - 1
                if provider_remaining:
                    self._active_providers[provider_id] = provider_remaining
                else:
                    del self._active_providers[provider_id]
                if model_remaining:
                    self._active_models[key] = model_remaining
                else:
                    del self._active_models[key]
