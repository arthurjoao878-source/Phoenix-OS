from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.configuration import (
    AgentServiceConfiguration,
    AgentToolConfiguration,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentLimits,
    AgentRunId,
    AgentStepId,
    ToolAvailability,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityAssessment,
    DurableCompatibilityCategory,
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
    create_ollama_metadata_only_durable_compatibility_policy,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    ProtectedPayloadReference,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_recovery import StartupDurableRecoveryCoordinator
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.schemas import ToolInputSchema, ToolOutputSchema, ToolSchema, ToolSchemaType
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.agent.tools import StaticToolResourceResolver, ToolDescriptor
from phoenix_os.inference.configuration import InferenceProviderConfiguration
from phoenix_os.inference.contracts import ModelCapabilities, ModelDescriptor, ModelId
from phoenix_os.inference.endpoints import ModelEndpointMode, ModelEndpointPolicy
from phoenix_os.inference.ollama import (
    OLLAMA_ENDPOINT_URL,
    OLLAMA_PORT,
    OLLAMA_PROVIDER_ID,
    OllamaModelBinding,
)

NOW = datetime(2026, 7, 31, 7, tzinfo=UTC)
RECOVERY_TIME = NOW + timedelta(minutes=10)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
AGENT_ID = AgentId("assistant")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


BASE_COMPATIBILITY = CompatibilityDigests(
    configuration=_digest("a"),
    tool_registry=_digest("b"),
    model_provider=_digest("c"),
    checkpoint_codec=_digest("d"),
)


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=0,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _metadata(
    *,
    agent_id: AgentId = AGENT_ID,
    compatibility: CompatibilityDigests = BASE_COMPATIBILITY,
    payload_profile: CheckpointPayloadProfile = CheckpointPayloadProfile.METADATA_ONLY,
    payload_reference: ProtectedPayloadReference | None = None,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    active_attempt: ExecutionAttempt | None = None,
) -> CheckpointMetadata:
    return CheckpointMetadata(
        agent_id=agent_id,
        actor_id="worker-1",
        next_operation=next_operation,
        budget=_budget(),
        compatibility=compatibility,
        payload_profile=payload_profile,
        retention_deadline=NOW + timedelta(days=7),
        active_attempt=active_attempt,
        payload_reference=payload_reference,
        metadata={"tenant": "demo"},
    )


def _checkpoint(
    sequence: int = 1,
    *,
    compatibility: CompatibilityDigests = BASE_COMPATIBILITY,
    agent_id: AgentId = AGENT_ID,
    payload_profile: CheckpointPayloadProfile = CheckpointPayloadProfile.METADATA_ONLY,
    payload_reference: ProtectedPayloadReference | None = None,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    active_attempt: ExecutionAttempt | None = None,
    previous_digest: CheckpointDigest | None = None,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID(int=1_000 + sequence)),
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=_metadata(
                agent_id=agent_id,
                compatibility=compatibility,
                payload_profile=payload_profile,
                payload_reference=payload_reference,
                next_operation=next_operation,
                active_attempt=active_attempt,
            ),
            created_at=NOW + timedelta(seconds=sequence),
            digest=_digest("0"),
        )
    )


def _policy(
    *,
    current: CompatibilityDigests = BASE_COMPATIBILITY,
    payload_profile: CheckpointPayloadProfile = CheckpointPayloadProfile.METADATA_ONLY,
    compatible_configuration: frozenset[CheckpointDigest] = frozenset(),
    compatible_tool_registry: frozenset[CheckpointDigest] = frozenset(),
    compatible_model_provider: frozenset[CheckpointDigest] = frozenset(),
    compatible_checkpoint_codec: frozenset[CheckpointDigest] = frozenset(),
    compatible_payload_codec: frozenset[CheckpointDigest] = frozenset(),
    available_protection_key_versions: frozenset[str] = frozenset(),
) -> DurableCompatibilityPolicy:
    return DurableCompatibilityPolicy(
        agent_id=AGENT_ID,
        current=current,
        payload_profile=payload_profile,
        compatible_configuration=compatible_configuration,
        compatible_tool_registry=compatible_tool_registry,
        compatible_model_provider=compatible_model_provider,
        compatible_checkpoint_codec=compatible_checkpoint_codec,
        compatible_payload_codec=compatible_payload_codec,
        available_protection_key_versions=available_protection_key_versions,
    )


def _validator(
    policy: DurableCompatibilityPolicy | None = None,
) -> StaticDurableCompatibilityValidator:
    return StaticDurableCompatibilityValidator((_policy() if policy is None else policy,))


def _started_model_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000004")),
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.STARTED,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW,
        started_at=NOW + timedelta(seconds=1),
    )


class _AppendOnAcquireLeaseManager(InMemoryDurableLeaseManager):
    def __init__(self) -> None:
        super().__init__()
        self.store: InMemoryDurableRunStore | None = None
        self.checkpoint: CheckpointEnvelope | None = None

    async def acquire(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableLease:
        lease = await super().acquire(run_id, owner_id=owner_id, now=now)
        if self.store is None or self.checkpoint is None:
            raise AssertionError("append-on-acquire manager is not configured")
        await self.store.append(
            self.checkpoint,
            expected_version=DurableRunVersion(self.checkpoint.run_version.value - 1),
            lease=lease,
            now=now,
        )
        return lease


def test_validator_accepts_exact_current_profile() -> None:
    assessment = _validator().validate(_checkpoint())

    assert assessment.category is DurableCompatibilityCategory.EXACT
    assert assessment.compatible is True


def test_validator_accepts_only_explicitly_reviewed_historical_digest() -> None:
    current = replace(BASE_COMPATIBILITY, configuration=_digest("f"))
    policy = _policy(
        current=current,
        compatible_configuration=frozenset({BASE_COMPATIBILITY.configuration}),
    )

    assessment = _validator(policy).validate(_checkpoint())

    assert assessment.category is DurableCompatibilityCategory.REVIEWED_COMPATIBLE
    assert assessment.compatible is True


@pytest.mark.parametrize(
    ("current", "category"),
    (
        (
            replace(BASE_COMPATIBILITY, configuration=_digest("9")),
            DurableCompatibilityCategory.CONFIGURATION_CHANGED,
        ),
        (
            replace(BASE_COMPATIBILITY, tool_registry=_digest("9")),
            DurableCompatibilityCategory.TOOL_REGISTRY_CHANGED,
        ),
        (
            replace(BASE_COMPATIBILITY, model_provider=_digest("9")),
            DurableCompatibilityCategory.MODEL_PROVIDER_CHANGED,
        ),
        (
            replace(BASE_COMPATIBILITY, checkpoint_codec=_digest("9")),
            DurableCompatibilityCategory.CHECKPOINT_CODEC_CHANGED,
        ),
    ),
)
def test_validator_classifies_unreviewed_dependency_changes(
    current: CompatibilityDigests,
    category: DurableCompatibilityCategory,
) -> None:
    assessment = _validator(_policy(current=current)).validate(_checkpoint())

    assert assessment.category is category
    assert assessment.compatible is False


def test_validator_fails_closed_for_missing_agent_and_profile_change() -> None:
    missing = _validator().validate(_checkpoint(agent_id=AgentId("removed-agent")))
    protected_current = replace(BASE_COMPATIBILITY, payload_codec=_digest("e"))
    changed_profile = _validator(
        _policy(
            current=protected_current,
            payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
            available_protection_key_versions=frozenset({"key-v1"}),
        )
    ).validate(_checkpoint())

    assert missing.category is DurableCompatibilityCategory.AGENT_UNAVAILABLE
    assert changed_profile.category is DurableCompatibilityCategory.PAYLOAD_PROFILE_CHANGED


def test_validator_requires_matching_payload_codec_and_available_key() -> None:
    compatibility = replace(BASE_COMPATIBILITY, payload_codec=_digest("e"))
    reference = ProtectedPayloadReference(
        reference="payload:run-1/checkpoint-1",
        key_version="key-v1",
        plaintext_bytes=32,
        ciphertext_bytes=64,
        ciphertext_digest=_digest("f"),
        created_at=NOW,
    )
    checkpoint = _checkpoint(
        compatibility=compatibility,
        payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
        payload_reference=reference,
    )
    unavailable = _validator(
        _policy(
            current=compatibility,
            payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
            available_protection_key_versions=frozenset({"key-v2"}),
        )
    ).validate(checkpoint)
    codec_changed = _validator(
        _policy(
            current=replace(compatibility, payload_codec=_digest("9")),
            payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
            available_protection_key_versions=frozenset({"key-v1"}),
        )
    ).validate(checkpoint)

    assert unavailable.category is DurableCompatibilityCategory.PROTECTION_KEY_UNAVAILABLE
    assert codec_changed.category is DurableCompatibilityCategory.PAYLOAD_CODEC_CHANGED


def test_policies_reject_ambiguous_or_incomplete_trusted_profiles() -> None:
    with pytest.raises(ValueError, match="duplicate agent"):
        StaticDurableCompatibilityValidator((_policy(), _policy()))

    with pytest.raises(ValueError, match="payload codec"):
        _policy(current=replace(BASE_COMPATIBILITY, payload_codec=_digest("e")))

    with pytest.raises(ValueError, match="protection keys"):
        _policy(
            current=replace(BASE_COMPATIBILITY, payload_codec=_digest("e")),
            payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
        )


async def test_coordinator_blocks_resume_on_current_configuration_mismatch() -> None:
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint())
    current = replace(BASE_COMPATIBILITY, configuration=_digest("9"))
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(_policy(current=current)),
    )

    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )

    assert assessment.compatibility.category is DurableCompatibilityCategory.CONFIGURATION_CHANGED
    assert assessment.point is RecoveryPoint.UNSAFE_STATE
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
    assert await store.lease_manager.get_current(DURABLE_RUN_ID, now=RECOVERY_TIME) is None


async def test_coordinator_preserves_indeterminate_detection_when_incompatible() -> None:
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(active_attempt=_started_model_attempt()))
    current = replace(BASE_COMPATIBILITY, tool_registry=_digest("9"))
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_validator(_policy(current=current)),
    )

    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )

    assert assessment.compatibility.category is DurableCompatibilityCategory.TOOL_REGISTRY_CHANGED
    assert assessment.point is RecoveryPoint.ACTIVE_MODEL_ATTEMPT
    assert assessment.disposition is RecoveryDisposition.MARK_INDETERMINATE_MODEL


async def test_coordinator_validates_authoritative_post_acquisition_configuration() -> None:
    manager = _AppendOnAcquireLeaseManager()
    store = InMemoryDurableRunStore(lease_manager=manager)
    first = _checkpoint()
    changed = replace(BASE_COMPATIBILITY, configuration=_digest("9"))
    second = _checkpoint(
        sequence=2,
        compatibility=changed,
        previous_digest=first.digest,
    )
    await store.create(first)
    manager.store = store
    manager.checkpoint = second
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=manager,
        compatibility_validator=_validator(),
    )

    assessment = await coordinator.assess_candidate(
        DURABLE_RUN_ID,
        owner_id="startup-worker",
        now=RECOVERY_TIME,
    )

    assert assessment.sequence == CheckpointSequence(2)
    assert assessment.compatibility.category is DurableCompatibilityCategory.CONFIGURATION_CHANGED
    assert assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR


class _WrongAgentValidator:
    def validate(
        self,
        checkpoint: CheckpointEnvelope,
    ) -> DurableCompatibilityAssessment:
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        return DurableCompatibilityAssessment(
            agent_id=AgentId("other-agent"),
            category=DurableCompatibilityCategory.EXACT,
        )


async def test_coordinator_rejects_substituted_compatibility_assessment() -> None:
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint())
    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=_WrongAgentValidator(),
    )

    with pytest.raises(AgentStateConflictError):
        await coordinator.assess_candidate(
            DURABLE_RUN_ID,
            owner_id="startup-worker",
            now=RECOVERY_TIME,
        )

    assert await store.lease_manager.get_current(DURABLE_RUN_ID, now=RECOVERY_TIME) is None


class _CompatibilityToolAdapter:
    adapter_id = "compatibility-adapter"
    tool_id = ToolId("lookup")

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise AssertionError("compatibility digest tests never invoke tools")


def _compatibility_tool_descriptor(
    *,
    availability: ToolAvailability = ToolAvailability.ACTIVE,
) -> ToolDescriptor:
    schema = ToolSchema(kind=ToolSchemaType.OBJECT)
    return ToolDescriptor(
        tool_id=ToolId("lookup"),
        name="Lookup",
        description="Return one deterministic record.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=30),
        resolver_id="compatibility-resolver",
        adapter_id="compatibility-adapter",
        availability=availability,
    )


def _compatibility_configuration(
    descriptor: ToolDescriptor | None = None,
    *,
    max_steps: int | None = None,
) -> AgentServiceConfiguration:
    limits = AgentLimits() if max_steps is None else AgentLimits(max_steps=max_steps)
    tools: tuple[AgentToolConfiguration, ...] = (
        () if descriptor is None else (AgentToolConfiguration(descriptor),)
    )
    return AgentServiceConfiguration(
        agent_id=AGENT_ID,
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("dev"),
        tools=tools,
        limits=limits,
        source="phoenix.operator",
    )


def _compatibility_provider_inputs(
    *,
    expected_digest: str | None = "a" * 64,
) -> tuple[InferenceProviderConfiguration, OllamaModelBinding]:
    provider = InferenceProviderConfiguration(
        provider_id=OLLAMA_PROVIDER_ID,
        endpoint_policy=ModelEndpointPolicy(
            OLLAMA_ENDPOINT_URL,
            mode=ModelEndpointMode.LOOPBACK_HTTP,
            allowed_ports=frozenset({OLLAMA_PORT}),
        ),
    )
    descriptor = ModelDescriptor(
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("dev"),
        provider_model_name="qwen3:4b-instruct",
        capabilities=ModelCapabilities(complete=True, streaming=True),
    )
    return provider, OllamaModelBinding(
        descriptor,
        expected_digest=expected_digest,
    )


def _sealed_compatibility_registry(
    descriptor: ToolDescriptor | None = None,
) -> ToolRegistry:
    registry = ToolRegistry()
    if descriptor is not None:
        registry.register_tool(
            descriptor,
            resolver=StaticToolResourceResolver(
                resolver_id="compatibility-resolver",
                resource="record:fixed",
            ),
            adapter=_CompatibilityToolAdapter(),
        )
    registry.seal()
    return registry


def test_typed_ollama_compatibility_policy_is_deterministic_and_validator_exact() -> None:
    configuration = _compatibility_configuration()
    registry = _sealed_compatibility_registry()
    provider, binding = _compatibility_provider_inputs()

    first = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=configuration,
        registry=registry,
        provider_configuration=provider,
        binding=binding,
    )
    second = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=configuration,
        registry=registry,
        provider_configuration=provider,
        binding=binding,
    )

    assert first.current == second.current
    assert first.payload_profile is CheckpointPayloadProfile.METADATA_ONLY
    assert first.current.payload_codec is None
    assessment = StaticDurableCompatibilityValidator((first,)).validate(
        _checkpoint(compatibility=first.current)
    )
    assert assessment.category is DurableCompatibilityCategory.EXACT


def test_configuration_change_moves_only_configuration_digest() -> None:
    configuration = _compatibility_configuration()
    changed = _compatibility_configuration(max_steps=configuration.limits.max_steps + 1)
    registry = _sealed_compatibility_registry()
    provider, binding = _compatibility_provider_inputs()

    first = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=configuration,
        registry=registry,
        provider_configuration=provider,
        binding=binding,
    )
    second = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=changed,
        registry=registry,
        provider_configuration=provider,
        binding=binding,
    )

    assert first.current.configuration != second.current.configuration
    assert first.current.tool_registry == second.current.tool_registry
    assert first.current.model_provider == second.current.model_provider
    assert first.current.checkpoint_codec == second.current.checkpoint_codec


def test_registry_lifecycle_change_moves_only_tool_registry_digest() -> None:
    active = _compatibility_tool_descriptor()
    disabled = replace(active, availability=ToolAvailability.DISABLED)
    configuration = _compatibility_configuration(active)
    active_registry = _sealed_compatibility_registry(active)
    disabled_registry = _sealed_compatibility_registry(disabled)
    provider, binding = _compatibility_provider_inputs()

    first = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=configuration,
        registry=active_registry,
        provider_configuration=provider,
        binding=binding,
    )
    second = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=configuration,
        registry=disabled_registry,
        provider_configuration=provider,
        binding=binding,
    )

    assert first.current.configuration == second.current.configuration
    assert first.current.tool_registry != second.current.tool_registry
    assert first.current.model_provider == second.current.model_provider
    assert first.current.checkpoint_codec == second.current.checkpoint_codec


def test_model_revision_change_moves_only_model_provider_digest() -> None:
    configuration = _compatibility_configuration()
    registry = _sealed_compatibility_registry()
    provider, first_binding = _compatibility_provider_inputs(expected_digest="a" * 64)
    _provider, second_binding = _compatibility_provider_inputs(expected_digest="b" * 64)

    first = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=configuration,
        registry=registry,
        provider_configuration=provider,
        binding=first_binding,
    )
    second = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=configuration,
        registry=registry,
        provider_configuration=provider,
        binding=second_binding,
    )

    assert first.current.configuration == second.current.configuration
    assert first.current.tool_registry == second.current.tool_registry
    assert first.current.model_provider != second.current.model_provider
    assert first.current.checkpoint_codec == second.current.checkpoint_codec


def test_typed_compatibility_policy_rejects_unsealed_registry_and_model_substitution() -> None:
    configuration = _compatibility_configuration()
    provider, binding = _compatibility_provider_inputs()
    unsealed = ToolRegistry()

    with pytest.raises(ValueError, match="sealed"):
        create_ollama_metadata_only_durable_compatibility_policy(
            configuration=configuration,
            registry=unsealed,
            provider_configuration=provider,
            binding=binding,
        )

    substituted = replace(
        binding,
        descriptor=replace(binding.descriptor, model_id=ModelId("other")),
    )
    with pytest.raises(ValueError, match="model binding"):
        create_ollama_metadata_only_durable_compatibility_policy(
            configuration=configuration,
            registry=_sealed_compatibility_registry(),
            provider_configuration=provider,
            binding=substituted,
        )

    _provider, unpinned = _compatibility_provider_inputs(expected_digest=None)
    with pytest.raises(ValueError, match="pinned Ollama model digest"):
        create_ollama_metadata_only_durable_compatibility_policy(
            configuration=configuration,
            registry=_sealed_compatibility_registry(),
            provider_configuration=provider,
            binding=unpinned,
        )
