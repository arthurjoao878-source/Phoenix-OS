from __future__ import annotations

from typing import cast

import pytest

from phoenix_os.agent.composition import create_agent_runtime_stack
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.fake import DeterministicFinalTurn, DeterministicModelTurnAdapter
from phoenix_os.agent.service import AgentService
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent import durable_live_revalidation as live_module
from phoenix_os.integrated_agent.contracts import IntegratedDataProvenance
from phoenix_os.integrated_agent.durable_live_revalidation import (
    IntegratedDurableRecoveryLiveProbes,
)
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext


def _service() -> AgentService:
    return create_agent_runtime_stack(
        configuration=AgentServiceConfiguration(
            agent_id=AgentId("resume-agent"),
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
        ),
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        tool_resolvers=(),
        tool_adapters=(),
        policy=PolicyEngine(),
    ).service


def _cancelled(_run_id: AgentRunId) -> bool:
    return False


def _context_current(_provenance: IntegratedDataProvenance) -> bool:
    return True


def test_live_probe_owner_requires_explicit_callable_probes() -> None:
    probes = IntegratedDurableRecoveryLiveProbes(
        cancellation_probe=_cancelled,
        context_freshness_probe=_context_current,
    )
    assert probes.cancellation_probe is _cancelled
    assert probes.context_freshness_probe is _context_current

    with pytest.raises(TypeError, match="cancellation_probe must be callable"):
        IntegratedDurableRecoveryLiveProbes(
            cancellation_probe=cast(object, None),  # type: ignore[arg-type]
            context_freshness_probe=_context_current,
        )

    with pytest.raises(TypeError, match="context_freshness_probe must be callable"):
        IntegratedDurableRecoveryLiveProbes(
            cancellation_probe=_cancelled,
            context_freshness_probe=cast(object, None),  # type: ignore[arg-type]
        )


def test_factory_reuses_public_agent_service_owners_and_exact_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service()
    context = SecurityContext(
        principal="service:rfc0039-resume",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )
    probes = IntegratedDurableRecoveryLiveProbes(
        cancellation_probe=_cancelled,
        context_freshness_probe=_context_current,
    )

    captured: dict[str, object] = {}
    sentinel = object()

    def capture(**kwargs: object) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(
        live_module,
        "AgentLoopIntegratedDurableRecoveryLiveRevalidator",
        capture,
    )

    created = live_module.compose_agent_service_integrated_durable_recovery_live_revalidator(
        service=service,
        context=context,
        probes=probes,
    )

    assert created is sentinel
    assert captured["loop"] is service.runtime
    assert captured["configuration"] is service.configuration
    assert captured["context"] is context
    assert captured["cancellation_probe"] is _cancelled
    assert captured["context_freshness_probe"] is _context_current
    assert captured["composition"] is None


def test_factory_rejects_non_service_owner() -> None:
    probes = IntegratedDurableRecoveryLiveProbes(
        cancellation_probe=_cancelled,
        context_freshness_probe=_context_current,
    )
    context = SecurityContext(
        principal="service:rfc0039-resume",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )

    with pytest.raises(TypeError, match="service must be AgentService"):
        live_module.compose_agent_service_integrated_durable_recovery_live_revalidator(
            service=object(),  # type: ignore[arg-type]
            context=context,
            probes=probes,
        )
