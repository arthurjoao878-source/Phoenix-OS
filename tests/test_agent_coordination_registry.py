from datetime import timedelta

import pytest

from phoenix_os.agent import (
    AgentDelegationRegistry,
    AgentDelegationRegistryClosedError,
    AgentId,
    AgentLimits,
    AgentRunId,
    AgentServiceConfiguration,
    CoordinationNamespace,
    DelegableAgentAlreadyRegisteredError,
    DelegableAgentDescriptor,
    DelegableAgentNotFoundError,
    DelegationDepth,
    DelegationId,
    DelegationLineage,
    DelegationLineageEntry,
    DelegationRequest,
)
from phoenix_os.inference import ModelId, ModelProviderId


def _descriptor(
    child: str,
    *,
    namespace: str = "default",
    parents: tuple[str, ...] = ("parent",),
    nested: bool = False,
    max_depth: int = 1,
    digest_char: str = "a",
) -> DelegableAgentDescriptor:
    return DelegableAgentDescriptor(
        configuration=AgentServiceConfiguration(
            agent_id=AgentId(child),
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
            limits=AgentLimits(total_duration=timedelta(minutes=10)),
        ),
        namespace=CoordinationNamespace(namespace),
        allowed_parent_agents=tuple(AgentId(parent) for parent in parents),
        compatibility_digest="sha256:" + digest_char * 64,
        allow_nested_delegation=nested,
        max_accepted_depth=DelegationDepth(max_depth),
    )


def _request(
    child: str,
    *,
    parent: str = "parent",
    namespace: str = "default",
    lineage: DelegationLineage | None = None,
) -> DelegationRequest:
    parent_id = AgentId(parent)
    parent_run = AgentRunId()
    selected_lineage = lineage or DelegationLineage(
        (DelegationLineageEntry(parent_id, parent_run),)
    )
    return DelegationRequest(
        parent_agent_id=selected_lineage.parent_agent_id,
        parent_run_id=selected_lineage.parent_run_id,
        child_agent_id=AgentId(child),
        namespace=CoordinationNamespace(namespace),
        lineage=selected_lineage,
        input={"task": "bounded"},
    )


def test_registry_is_duplicate_rejecting_and_deterministic() -> None:
    registry = AgentDelegationRegistry()
    second = _descriptor("second", digest_char="b")
    first = _descriptor("first", digest_char="c")

    second_registration = registry.register_agent(second)
    first_registration = registry.register_agent(first)

    assert second_registration.agent_id == AgentId("second")
    assert first_registration.agent_id == AgentId("first")
    assert registry.list_descriptors() == (second, first)
    assert registry.resolve_request(_request("first")) == first

    with pytest.raises(DelegableAgentAlreadyRegisteredError):
        registry.register_agent(first)


def test_registry_is_namespaced_closed_world() -> None:
    registry = AgentDelegationRegistry()
    registry.register_agent(_descriptor("worker", namespace="team-a"))

    with pytest.raises(DelegableAgentNotFoundError):
        registry.resolve_request(_request("worker", namespace="team-b"))
    with pytest.raises(DelegableAgentNotFoundError):
        registry.resolve_request(_request("missing", namespace="team-a"))


def test_registry_rejects_unapproved_parent_and_nested_depth() -> None:
    registry = AgentDelegationRegistry()
    registry.register_agent(_descriptor("worker"))

    with pytest.raises(DelegableAgentNotFoundError):
        registry.resolve_request(_request("worker", parent="other"))

    lineage = DelegationLineage(
        (
            DelegationLineageEntry(AgentId("root"), AgentRunId()),
            DelegationLineageEntry(
                AgentId("parent"),
                AgentRunId(),
                via_delegation_id=DelegationId(),
            ),
        )
    )
    with pytest.raises(DelegableAgentNotFoundError):
        registry.resolve_request(_request("worker", lineage=lineage))


def test_registry_can_explicitly_allow_bounded_nested_delegation() -> None:
    registry = AgentDelegationRegistry()
    descriptor = _descriptor(
        "worker",
        parents=("planner",),
        nested=True,
        max_depth=2,
    )
    registry.register_agent(descriptor)
    lineage = DelegationLineage(
        (
            DelegationLineageEntry(AgentId("root"), AgentRunId()),
            DelegationLineageEntry(
                AgentId("planner"),
                AgentRunId(),
                DelegationId(),
            ),
        )
    )

    assert registry.resolve_request(_request("worker", lineage=lineage)) == descriptor


def test_registry_close_is_terminal() -> None:
    registry = AgentDelegationRegistry()
    registry.close()

    assert registry.closed
    with pytest.raises(AgentDelegationRegistryClosedError):
        registry.list_descriptors()
    with pytest.raises(AgentDelegationRegistryClosedError):
        registry.register_agent(_descriptor("closed"))
