from __future__ import annotations

from typing import Any

import pytest

from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.execution_interceptors import ChainedAgentExecutionInterceptor
from phoenix_os.agent.loop import AgentExecutionInterceptor
from phoenix_os.agent.tools import ToolFinalAdmissionGrant


class _RecordingInterceptor:
    def __init__(
        self,
        name: str,
        calls: list[tuple[str, str, tuple[object, ...]]],
        *,
        grant: ToolFinalAdmissionGrant | None = None,
        fail_method: str | None = None,
    ) -> None:
        self._name = name
        self._calls = calls
        self._grant = grant
        self._fail_method = fail_method

    def _record(self, method: str, *args: object) -> None:
        self._calls.append((self._name, method, args))
        if self._fail_method == method:
            raise RuntimeError(f"{self._name}:{method}:failed")

    async def before_model_turn(self, *args: Any) -> None:
        self._record("before_model_turn", *args)

    async def before_tool_authorization(self, *args: Any) -> None:
        self._record("before_tool_authorization", *args)

    async def before_tool_invocation(self, *args: Any) -> None:
        self._record("before_tool_invocation", *args)

    async def final_tool_admission(self, *args: Any) -> ToolFinalAdmissionGrant | None:
        self._record("final_tool_admission", *args)
        return self._grant

    async def after_tool_result(self, *args: Any) -> None:
        self._record("after_tool_result", *args)

    async def before_final_output(self, *args: Any) -> None:
        self._record("before_final_output", *args)


def _chain(
    *interceptors: AgentExecutionInterceptor,
) -> ChainedAgentExecutionInterceptor:
    return ChainedAgentExecutionInterceptor(tuple(interceptors))


@pytest.mark.asyncio
async def test_chain_is_protocol_compatible_and_forwards_all_non_grant_boundaries_in_order() -> (
    None
):
    calls: list[tuple[str, str, tuple[object, ...]]] = []
    first = _RecordingInterceptor("first", calls)
    second = _RecordingInterceptor("second", calls)
    chain = _chain(first, second)
    sentinels = tuple(object() for _ in range(6))

    assert isinstance(chain, AgentExecutionInterceptor)
    assert chain.interceptors == (first, second)

    await chain.before_model_turn(*sentinels[:3])  # type: ignore[arg-type]
    await chain.before_tool_authorization(*sentinels[:4])  # type: ignore[arg-type]
    await chain.before_tool_invocation(*sentinels[:4])  # type: ignore[arg-type]
    await chain.after_tool_result(*sentinels[:6])  # type: ignore[arg-type]
    await chain.before_final_output(*sentinels[:4])  # type: ignore[arg-type]

    assert [(name, method) for name, method, _args in calls] == [
        ("first", "before_model_turn"),
        ("second", "before_model_turn"),
        ("first", "before_tool_authorization"),
        ("second", "before_tool_authorization"),
        ("first", "before_tool_invocation"),
        ("second", "before_tool_invocation"),
        ("first", "after_tool_result"),
        ("second", "after_tool_result"),
        ("first", "before_final_output"),
        ("second", "before_final_output"),
    ]
    for _name, method, args in calls:
        expected = {
            "before_model_turn": sentinels[:3],
            "before_tool_authorization": sentinels[:4],
            "before_tool_invocation": sentinels[:4],
            "after_tool_result": sentinels[:6],
            "before_final_output": sentinels[:4],
        }[method]
        assert args == expected


@pytest.mark.asyncio
async def test_final_admission_returns_the_single_grant_and_runs_every_interceptor() -> None:
    calls: list[tuple[str, str, tuple[object, ...]]] = []
    grant = ToolFinalAdmissionGrant(provenance_attributes={"source": "integrated"})
    chain = _chain(
        _RecordingInterceptor("first", calls),
        _RecordingInterceptor("authority", calls, grant=grant),
        _RecordingInterceptor("observer", calls),
    )
    args = tuple(object() for _ in range(5))

    selected = await chain.final_tool_admission(*args)  # type: ignore[arg-type]

    assert selected is grant
    assert [(name, method) for name, method, _args in calls] == [
        ("first", "final_tool_admission"),
        ("authority", "final_tool_admission"),
        ("observer", "final_tool_admission"),
    ]
    assert all(recorded == args for _name, _method, recorded in calls)


@pytest.mark.asyncio
async def test_final_admission_rejects_ambiguous_multiple_grants_and_stops_closed() -> None:
    calls: list[tuple[str, str, tuple[object, ...]]] = []
    first_grant = ToolFinalAdmissionGrant(provenance_attributes={"one": "1"})
    second_grant = ToolFinalAdmissionGrant(provenance_attributes={"two": "2"})
    chain = _chain(
        _RecordingInterceptor("first", calls, grant=first_grant),
        _RecordingInterceptor("second", calls, grant=second_grant),
        _RecordingInterceptor("never", calls),
    )

    with pytest.raises(AgentStateConflictError):
        await chain.final_tool_admission(*tuple(object() for _ in range(5)))  # type: ignore[arg-type]

    assert [name for name, _method, _args in calls] == ["first", "second"]


@pytest.mark.asyncio
async def test_chain_propagates_failure_and_stops_before_later_interceptors() -> None:
    calls: list[tuple[str, str, tuple[object, ...]]] = []
    chain = _chain(
        _RecordingInterceptor("first", calls),
        _RecordingInterceptor("broken", calls, fail_method="after_tool_result"),
        _RecordingInterceptor("never", calls),
    )

    with pytest.raises(RuntimeError, match="broken:after_tool_result:failed"):
        await chain.after_tool_result(*tuple(object() for _ in range(6)))  # type: ignore[arg-type]

    assert [name for name, _method, _args in calls] == ["first", "broken"]


def test_chain_rejects_empty_non_tuple_and_non_interceptor_members() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        ChainedAgentExecutionInterceptor(())
    with pytest.raises(TypeError, match="must be a tuple"):
        ChainedAgentExecutionInterceptor([])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must implement"):
        ChainedAgentExecutionInterceptor((object(),))  # type: ignore[arg-type]
