"""Fail-closed current-configuration compatibility for durable recovery."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointPayloadProfile,
    CompatibilityDigests,
)

_KEY_VERSION_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


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
