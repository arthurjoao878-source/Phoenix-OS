"""Fail-closed current-configuration compatibility for durable recovery."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, cast, runtime_checkable

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.durable_contracts import (
    CURRENT_CHECKPOINT_SCHEMA_VERSION,
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointPayloadProfile,
    CompatibilityDigests,
)
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.tools import canonical_tool_descriptor_bytes
from phoenix_os.inference.configuration import InferenceProviderConfiguration
from phoenix_os.inference.ollama import (
    OLLAMA_PROVIDER_ID,
    OllamaModelBinding,
    OllamaModelProvider,
    OllamaTransportLimits,
)

_KEY_VERSION_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")

_COMPATIBILITY_DOCUMENT_VERSION = 1
_CHECKPOINT_CODEC_COMPATIBILITY_VERSION = 1
_OLLAMA_PROVIDER_COMPATIBILITY_VERSION = 1

_CONFIGURATION_COMPATIBILITY_KIND = "phoenix.agent.durable-configuration-compatibility"
_TOOL_REGISTRY_COMPATIBILITY_KIND = "phoenix.agent.durable-tool-registry-compatibility"
_MODEL_PROVIDER_COMPATIBILITY_KIND = "phoenix.agent.durable-model-provider-compatibility"
_CHECKPOINT_CODEC_COMPATIBILITY_KIND = "phoenix.agent.durable-checkpoint-codec-compatibility"


def _duration_microseconds(value: timedelta) -> int:
    if not isinstance(value, timedelta):
        raise TypeError("compatibility duration must be timedelta")
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _compatibility_value(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("compatibility floats must be finite")
        return value
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, timedelta):
        return {"microseconds": _duration_microseconds(value)}
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("compatibility mappings must use string keys")
        return {cast(str, key): _compatibility_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_compatibility_value(item) for item in value]
    if isinstance(value, frozenset):
        converted = [_compatibility_value(item) for item in value]
        return sorted(converted, key=_compatibility_sort_key)
    if is_dataclass(value) and not isinstance(value, type):
        typed = cast(Any, value)
        return {
            item.name: _compatibility_value(getattr(typed, item.name)) for item in fields(typed)
        }
    raise TypeError("unsupported typed compatibility value")


def _compatibility_sort_key(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _compatibility_digest(kind: str, record: Mapping[str, object]) -> CheckpointDigest:
    document = {
        "schema_version": _COMPATIBILITY_DOCUMENT_VERSION,
        "kind": kind,
        "record": _compatibility_value(record),
    }
    try:
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError) as exception:
        raise ValueError("compatibility evidence is not canonically encodable") from exception
    return CheckpointDigest(hashlib.sha256(encoded).hexdigest())


def _configuration_compatibility_digest(
    configuration: AgentServiceConfiguration,
) -> CheckpointDigest:
    return _compatibility_digest(
        _CONFIGURATION_COMPATIBILITY_KIND,
        {
            "agent_id": str(configuration.agent_id),
            "provider_id": str(configuration.provider_id),
            "model_id": str(configuration.model_id),
            "tool_ids": tuple(str(tool_id) for tool_id in configuration.tool_ids),
            "limits": configuration.limits,
            "observability": configuration.observability,
            "source": configuration.source,
            "metadata": configuration.metadata,
        },
    )


def _require_registry_matches_configuration(
    configuration: AgentServiceConfiguration,
    registry: ToolRegistry,
) -> None:
    if registry.closed:
        raise ValueError("durable compatibility requires an open tool registry")
    if not registry.sealed:
        raise ValueError("durable compatibility requires a sealed tool registry")
    states = registry.list_states()
    if len(states) != len(configuration.tools):
        raise ValueError("tool registry does not match agent configuration")
    for configured, state in zip(configuration.tools, states, strict=True):
        expected = configured.descriptor
        current = state.descriptor
        if current.tool_id != expected.tool_id:
            raise ValueError("tool registry order does not match agent configuration")
        normalized = replace(current, availability=expected.availability)
        if normalized != expected:
            raise ValueError("tool registry descriptor does not match agent configuration")


def _tool_registry_compatibility_digest(
    configuration: AgentServiceConfiguration,
    registry: ToolRegistry,
) -> CheckpointDigest:
    _require_registry_matches_configuration(configuration, registry)
    entries: list[dict[str, object]] = []
    for state in registry.list_states():
        descriptor_bytes = canonical_tool_descriptor_bytes(state.descriptor)
        entries.append(
            {
                "tool_id": str(state.descriptor.tool_id),
                "revision": state.revision,
                "descriptor_sha256": hashlib.sha256(descriptor_bytes).hexdigest(),
            }
        )
    return _compatibility_digest(
        _TOOL_REGISTRY_COMPATIBILITY_KIND,
        {"entries": tuple(entries)},
    )


def _ollama_model_provider_compatibility_digest(
    configuration: AgentServiceConfiguration,
    provider_configuration: InferenceProviderConfiguration,
    binding: OllamaModelBinding,
    transport_limits: OllamaTransportLimits,
) -> CheckpointDigest:
    if configuration.provider_id != OLLAMA_PROVIDER_ID:
        raise ValueError("agent configuration is not bound to the Ollama provider")
    if provider_configuration.provider_id != configuration.provider_id:
        raise ValueError("provider configuration does not match agent configuration")
    if binding.descriptor.provider_id != configuration.provider_id:
        raise ValueError("model binding provider does not match agent configuration")
    if binding.descriptor.model_id != configuration.model_id:
        raise ValueError("model binding does not match agent configuration")
    if binding.expected_digest is None:
        raise ValueError("durable compatibility requires a pinned Ollama model digest")

    provider = OllamaModelProvider(
        provider_configuration,
        (binding,),
        transport_limits=transport_limits,
    )
    return _compatibility_digest(
        _MODEL_PROVIDER_COMPATIBILITY_KIND,
        {
            "implementation": "phoenix.inference.ollama.OllamaModelProvider",
            "implementation_compatibility_version": _OLLAMA_PROVIDER_COMPATIBILITY_VERSION,
            "provider_configuration": provider.provider_configuration,
            "model_binding": provider.model_bindings[0],
            "transport_limits": transport_limits,
        },
    )


def _checkpoint_codec_compatibility_digest() -> CheckpointDigest:
    return _compatibility_digest(
        _CHECKPOINT_CODEC_COMPATIBILITY_KIND,
        {
            "implementation": "phoenix.agent.durable_codec.CanonicalCheckpointCodec",
            "implementation_compatibility_version": _CHECKPOINT_CODEC_COMPATIBILITY_VERSION,
            "checkpoint_schema_version": CURRENT_CHECKPOINT_SCHEMA_VERSION,
        },
    )


class DurableCompatibilityCategory(StrEnum):
    """Content-free result category for one current-configuration comparison."""

    EXACT = "exact"
    REVIEWED_COMPATIBLE = "reviewed_compatible"
    AGENT_UNAVAILABLE = "agent_unavailable"
    PAYLOAD_PROFILE_CHANGED = "payload_profile_changed"
    CONFIGURATION_CHANGED = "configuration_changed"
    TOOL_REGISTRY_CHANGED = "tool_registry_changed"
    MODEL_PROVIDER_CHANGED = "model_provider_changed"
    CHECKPOINT_CODEC_CHANGED = "checkpoint_codec_changed"
    PAYLOAD_CODEC_CHANGED = "payload_codec_changed"
    PROTECTION_KEY_UNAVAILABLE = "protection_key_unavailable"

    @property
    def compatible(self) -> bool:
        return self in {
            self.EXACT,
            self.REVIEWED_COMPATIBLE,
        }


@dataclass(frozen=True, slots=True)
class DurableCompatibilityAssessment:
    """Content-free compatibility result that grants no execution authority."""

    agent_id: AgentId
    category: DurableCompatibilityCategory

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.category, DurableCompatibilityCategory):
            raise TypeError("category must be DurableCompatibilityCategory")

    @property
    def compatible(self) -> bool:
        return self.category.compatible


def _freeze_digests(
    values: Iterable[CheckpointDigest],
    *,
    label: str,
) -> frozenset[CheckpointDigest]:
    try:
        frozen = frozenset(values)
    except TypeError as exception:
        raise TypeError(f"{label} must be an iterable of CheckpointDigest") from exception
    if any(not isinstance(value, CheckpointDigest) for value in frozen):
        raise TypeError(f"{label} must contain CheckpointDigest values")
    return frozen


def _freeze_key_versions(values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, str):
        raise TypeError("available_protection_key_versions must be an iterable")
    try:
        items = tuple(values)
    except TypeError as exception:
        raise TypeError("available_protection_key_versions must be an iterable") from exception
    frozen: set[str] = set()
    for value in items:
        if not isinstance(value, str):
            raise TypeError("protection key versions must be strings")
        normalized = value.strip()
        if _KEY_VERSION_PATTERN.fullmatch(normalized) is None:
            raise ValueError("protection key version is invalid")
        frozen.add(normalized)
    return frozenset(frozen)


@dataclass(frozen=True, slots=True)
class DurableCompatibilityPolicy:
    """Trusted current profile and explicitly reviewed historical compatibility."""

    agent_id: AgentId
    current: CompatibilityDigests
    payload_profile: CheckpointPayloadProfile
    compatible_configuration: frozenset[CheckpointDigest] = field(default_factory=frozenset)
    compatible_tool_registry: frozenset[CheckpointDigest] = field(default_factory=frozenset)
    compatible_model_provider: frozenset[CheckpointDigest] = field(default_factory=frozenset)
    compatible_checkpoint_codec: frozenset[CheckpointDigest] = field(default_factory=frozenset)
    compatible_payload_codec: frozenset[CheckpointDigest] = field(default_factory=frozenset)
    available_protection_key_versions: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.current, CompatibilityDigests):
            raise TypeError("current must be CompatibilityDigests")
        if not isinstance(self.payload_profile, CheckpointPayloadProfile):
            raise TypeError("payload_profile must be CheckpointPayloadProfile")

        digest_fields = (
            ("compatible_configuration", self.compatible_configuration),
            ("compatible_tool_registry", self.compatible_tool_registry),
            ("compatible_model_provider", self.compatible_model_provider),
            ("compatible_checkpoint_codec", self.compatible_checkpoint_codec),
            ("compatible_payload_codec", self.compatible_payload_codec),
        )
        for label, values in digest_fields:
            object.__setattr__(
                self,
                label,
                _freeze_digests(values, label=label),
            )

        key_versions = _freeze_key_versions(self.available_protection_key_versions)
        object.__setattr__(
            self,
            "available_protection_key_versions",
            key_versions,
        )

        if self.payload_profile is CheckpointPayloadProfile.METADATA_ONLY:
            if self.current.payload_codec is not None:
                raise ValueError("metadata-only compatibility cannot require a payload codec")
            if self.compatible_payload_codec:
                raise ValueError("metadata-only compatibility cannot allow payload codecs")
            if key_versions:
                raise ValueError("metadata-only compatibility cannot expose protection keys")
        else:
            if self.current.payload_codec is None:
                raise ValueError("protected-content compatibility requires a payload codec")
            if not key_versions:
                raise ValueError("protected-content compatibility requires protection keys")


def create_ollama_metadata_only_durable_compatibility_policy(
    *,
    configuration: AgentServiceConfiguration,
    registry: ToolRegistry,
    provider_configuration: InferenceProviderConfiguration,
    binding: OllamaModelBinding,
    transport_limits: OllamaTransportLimits | None = None,
) -> DurableCompatibilityPolicy:
    """Derive one recovery policy from the exact trusted live composition."""

    if not isinstance(configuration, AgentServiceConfiguration):
        raise TypeError("configuration must be AgentServiceConfiguration")
    if not isinstance(registry, ToolRegistry):
        raise TypeError("registry must be ToolRegistry")
    if not isinstance(provider_configuration, InferenceProviderConfiguration):
        raise TypeError("provider_configuration must be InferenceProviderConfiguration")
    if not isinstance(binding, OllamaModelBinding):
        raise TypeError("binding must be OllamaModelBinding")
    selected_limits = OllamaTransportLimits() if transport_limits is None else transport_limits
    if not isinstance(selected_limits, OllamaTransportLimits):
        raise TypeError("transport_limits must be OllamaTransportLimits or None")

    current = CompatibilityDigests(
        configuration=_configuration_compatibility_digest(configuration),
        tool_registry=_tool_registry_compatibility_digest(configuration, registry),
        model_provider=_ollama_model_provider_compatibility_digest(
            configuration,
            provider_configuration,
            binding,
            selected_limits,
        ),
        checkpoint_codec=_checkpoint_codec_compatibility_digest(),
    )
    return DurableCompatibilityPolicy(
        agent_id=configuration.agent_id,
        current=current,
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
    )


@runtime_checkable
class DurableCompatibilityValidator(Protocol):
    """Resolve and compare current trusted dependencies for one checkpoint."""

    def validate(
        self,
        checkpoint: CheckpointEnvelope,
    ) -> DurableCompatibilityAssessment: ...


class StaticDurableCompatibilityValidator(DurableCompatibilityValidator):
    """Deterministic validator backed by immutable trusted agent policies."""

    def __init__(self, policies: Iterable[DurableCompatibilityPolicy]) -> None:
        try:
            values = tuple(policies)
        except TypeError as exception:
            raise TypeError("policies must be an iterable") from exception
        if any(not isinstance(value, DurableCompatibilityPolicy) for value in values):
            raise TypeError("policies must contain DurableCompatibilityPolicy values")

        indexed: dict[AgentId, DurableCompatibilityPolicy] = {}
        for policy in values:
            if policy.agent_id in indexed:
                raise ValueError("compatibility policies contain a duplicate agent id")
            indexed[policy.agent_id] = policy
        self._policies = MappingProxyType(indexed)

    @property
    def agent_ids(self) -> tuple[AgentId, ...]:
        return tuple(sorted(self._policies))

    def validate(
        self,
        checkpoint: CheckpointEnvelope,
    ) -> DurableCompatibilityAssessment:
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")

        agent_id = checkpoint.metadata.agent_id
        policy = self._policies.get(agent_id)
        if policy is None:
            return DurableCompatibilityAssessment(
                agent_id=agent_id,
                category=DurableCompatibilityCategory.AGENT_UNAVAILABLE,
            )

        if checkpoint.metadata.payload_profile is not policy.payload_profile:
            return DurableCompatibilityAssessment(
                agent_id=agent_id,
                category=DurableCompatibilityCategory.PAYLOAD_PROFILE_CHANGED,
            )

        persisted = checkpoint.metadata.compatibility
        reviewed = False

        mismatch, matched_reviewed = _compare_digest(
            persisted.configuration,
            policy.current.configuration,
            policy.compatible_configuration,
        )
        if mismatch:
            return DurableCompatibilityAssessment(
                agent_id=agent_id,
                category=DurableCompatibilityCategory.CONFIGURATION_CHANGED,
            )
        reviewed = reviewed or matched_reviewed

        mismatch, matched_reviewed = _compare_digest(
            persisted.tool_registry,
            policy.current.tool_registry,
            policy.compatible_tool_registry,
        )
        if mismatch:
            return DurableCompatibilityAssessment(
                agent_id=agent_id,
                category=DurableCompatibilityCategory.TOOL_REGISTRY_CHANGED,
            )
        reviewed = reviewed or matched_reviewed

        mismatch, matched_reviewed = _compare_digest(
            persisted.model_provider,
            policy.current.model_provider,
            policy.compatible_model_provider,
        )
        if mismatch:
            return DurableCompatibilityAssessment(
                agent_id=agent_id,
                category=DurableCompatibilityCategory.MODEL_PROVIDER_CHANGED,
            )
        reviewed = reviewed or matched_reviewed

        mismatch, matched_reviewed = _compare_digest(
            persisted.checkpoint_codec,
            policy.current.checkpoint_codec,
            policy.compatible_checkpoint_codec,
        )
        if mismatch:
            return DurableCompatibilityAssessment(
                agent_id=agent_id,
                category=DurableCompatibilityCategory.CHECKPOINT_CODEC_CHANGED,
            )
        reviewed = reviewed or matched_reviewed

        mismatch, matched_reviewed = _compare_optional_digest(
            persisted.payload_codec,
            policy.current.payload_codec,
            policy.compatible_payload_codec,
        )
        if mismatch:
            return DurableCompatibilityAssessment(
                agent_id=agent_id,
                category=DurableCompatibilityCategory.PAYLOAD_CODEC_CHANGED,
            )
        reviewed = reviewed or matched_reviewed

        reference = checkpoint.metadata.payload_reference
        if reference is not None:
            if reference.key_version not in policy.available_protection_key_versions:
                return DurableCompatibilityAssessment(
                    agent_id=agent_id,
                    category=DurableCompatibilityCategory.PROTECTION_KEY_UNAVAILABLE,
                )

        return DurableCompatibilityAssessment(
            agent_id=agent_id,
            category=(
                DurableCompatibilityCategory.REVIEWED_COMPATIBLE
                if reviewed
                else DurableCompatibilityCategory.EXACT
            ),
        )


def _compare_digest(
    persisted: CheckpointDigest,
    current: CheckpointDigest,
    reviewed: frozenset[CheckpointDigest],
) -> tuple[bool, bool]:
    if persisted == current:
        return False, False
    if persisted in reviewed:
        return False, True
    return True, False


def _compare_optional_digest(
    persisted: CheckpointDigest | None,
    current: CheckpointDigest | None,
    reviewed: frozenset[CheckpointDigest],
) -> tuple[bool, bool]:
    if persisted == current:
        return False, False
    if persisted is not None and persisted in reviewed:
        return False, True
    return True, False
