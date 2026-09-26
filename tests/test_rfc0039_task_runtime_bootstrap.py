from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast

import pytest

from phoenix_os.control_plane import task_runtime_bootstrap as bootstrap
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorProfileConfiguration,
    OperatorWorkspaceConfiguration,
)
from phoenix_os.control_plane.task_cli import TaskRunSummary
from phoenix_os.policy import PolicyEngine


class _FakeRuntime:
    def __init__(self, services: dict[str, object]) -> None:
        self._services = services
        self.started = False
        self.stopped = False

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    def service(self, name: str) -> object:
        return self._services[name]


class _FakeAccess:
    def __init__(self) -> None:
        self.issued: list[object] = []
        self.authenticated: list[str] = []
        self.logged_out: list[str] = []

    async def issue(self, evidence: object) -> object:
        self.issued.append(evidence)
        return SimpleNamespace(token=SimpleNamespace(value="temporary-session-token"))

    async def authenticate(self, token: str) -> object:
        self.authenticated.append(token)
        return SimpleNamespace(principal="session-authentication")

    async def logout(self, token: str) -> bool:
        self.logged_out.append(token)
        return True


class _FakeAuthenticator:
    seen: ClassVar[list[tuple[object, str]]] = []

    def __init__(self, registry: object) -> None:
        self._registry = registry

    async def authenticate(self, authorization: str) -> object:
        type(self).seen.append((self._registry, authorization))
        return SimpleNamespace(operator_id="existing-operator")


class _FakeOwner:
    pass


class _FakeAdministration:
    calls: ClassVar[list[tuple[str, object, dict[str, object]]]] = []
    policies: ClassVar[list[PolicyEngine]] = []

    def __init__(
        self,
        *,
        owner: object,
        policy: PolicyEngine,
        lease_owner_id: object,
        authority_freshness: object,
    ) -> None:
        del owner, lease_owner_id, authority_freshness
        type(self).policies.append(policy)

    async def run(self, authentication: object, **kwargs: object) -> object:
        type(self).calls.append(("run", authentication, kwargs))
        return _summary("running")

    async def status(self, authentication: object, **kwargs: object) -> object:
        type(self).calls.append(("status", authentication, kwargs))
        return _summary("running")

    async def cancel(self, authentication: object, **kwargs: object) -> object:
        type(self).calls.append(("cancel", authentication, kwargs))
        return _summary("cancelled")

    async def resume(self, authentication: object, **kwargs: object) -> object:
        type(self).calls.append(("resume", authentication, kwargs))
        return _summary("running")


def _summary(state: str) -> object:
    return SimpleNamespace(
        schema_version=1,
        task_id="task-1",
        run_id="11111111-1111-1111-1111-111111111111",
        run_state=state,
    )


def _configuration() -> OperatorConfiguration:
    return OperatorConfiguration(
        source=Path("operator.toml"),
        runtime=None,
        inference=None,
        models=(),
        workspaces=(),
        profiles=(),
    )


def _workspace() -> OperatorWorkspaceConfiguration:
    return OperatorWorkspaceConfiguration(
        workspace_name="project",
        kind="development-checkout",
        root="C:/project",
        read_prefixes=(),
        patch_prefixes=(),
    )


@pytest.fixture(autouse=True)
def _reset_fakes() -> None:
    _FakeAuthenticator.seen.clear()
    _FakeAdministration.calls.clear()
    _FakeAdministration.policies.clear()


@pytest.fixture
def _surface(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    policy = PolicyEngine()
    access = _FakeAccess()
    registry = object()
    sessions = object()
    owner = _FakeOwner()
    runtime = _FakeRuntime(
        {
            "control_plane.operator-registry": registry,
            "control_plane.operator-access": access,
            "control_plane.operator-sessions": sessions,
            "control_plane.task-runtime": owner,
        }
    )
    profile = OperatorProfileConfiguration(
        profile_name="dev",
        model_name="dev",
        workspace_name="project",
        context_paths=(),
        allow_workspace_patch=False,
    )

    async def compose(
        _configuration: OperatorConfiguration,
        _profile: OperatorProfileConfiguration,
    ) -> bootstrap._RuntimeSurface:
        assert _profile is profile
        return bootstrap._RuntimeSurface(
            runtime=cast(Any, runtime),
            policy=policy,
            profile=profile,
        )

    async def existing_profile(
        _configuration: OperatorConfiguration,
        _run_id: object,
    ) -> OperatorProfileConfiguration:
        return profile

    monkeypatch.setattr(bootstrap, "_compose_runtime", compose)
    monkeypatch.setattr(bootstrap, "_profile_for_existing_run", existing_profile)
    monkeypatch.setattr(bootstrap, "_read_operator_credential", lambda: "existing-secret")
    monkeypatch.setattr(bootstrap, "ControlPlaneOperatorAuthenticator", _FakeAuthenticator)
    monkeypatch.setattr(bootstrap, "ControlPlaneDurableSessionAccessService", _FakeAccess)
    monkeypatch.setattr(bootstrap, "ServerOwnedDurableIntegratedTaskRuntime", _FakeOwner)
    monkeypatch.setattr(
        bootstrap,
        "ControlPlaneDurableAuthorityFreshnessValidator",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        bootstrap,
        "ServerOwnedControlPlaneTaskHttpAdministration",
        _FakeAdministration,
    )
    return SimpleNamespace(
        policy=policy,
        access=access,
        registry=registry,
        runtime=runtime,
        profile=profile,
    )


def test_bootstrap_uses_existing_operator_credential_only_for_authentication(
    _surface: SimpleNamespace,
) -> None:
    bridge = bootstrap.StandaloneTaskRuntimeBridge()
    workspace = _workspace()
    result = bridge.run(
        configuration=_configuration(),
        profile=_surface.profile,
        workspace=workspace,
        task_text="inspect repository",
    )

    assert isinstance(result, TaskRunSummary)
    assert _FakeAuthenticator.seen == [(_surface.registry, "Bearer existing-secret")]
    assert len(_surface.access.issued) == 1
    assert _surface.access.authenticated == ["temporary-session-token"]
    assert _surface.access.logged_out == ["temporary-session-token"]
    assert _surface.runtime.started
    assert _surface.runtime.stopped


def test_bootstrap_reuses_exact_shared_policy_for_task_administration(
    _surface: SimpleNamespace,
) -> None:
    bridge = bootstrap.StandaloneTaskRuntimeBridge()
    bridge.status(
        configuration=_configuration(),
        run_id="11111111-1111-1111-1111-111111111111",
    )
    assert _FakeAdministration.policies == [_surface.policy]
    assert _FakeAdministration.calls[0][0] == "status"


def test_bootstrap_cancel_uses_durable_session_and_logs_out(
    _surface: SimpleNamespace,
) -> None:
    bridge = bootstrap.StandaloneTaskRuntimeBridge()
    result = bridge.cancel(
        configuration=_configuration(),
        run_id="11111111-1111-1111-1111-111111111111",
    )
    assert isinstance(result, TaskRunSummary)
    assert result.status == "cancelled"
    assert _FakeAdministration.calls[0][0] == "cancel"
    assert _surface.access.logged_out == ["temporary-session-token"]


def test_bootstrap_resume_forwards_exact_resupply_object(
    _surface: SimpleNamespace,
) -> None:
    bridge = bootstrap.StandaloneTaskRuntimeBridge()
    resupply = object()
    result = bridge.resume(
        configuration=_configuration(),
        run_id="11111111-1111-1111-1111-111111111111",
        context_resupply=resupply,  # type: ignore[arg-type]
    )
    assert isinstance(result, TaskRunSummary)
    action, _authentication, kwargs = _FakeAdministration.calls[0]
    assert action == "resume"
    assert kwargs["context_resupply"] is resupply


def test_bootstrap_requires_resume_context_resupply(
    _surface: SimpleNamespace,
) -> None:
    bridge = bootstrap.StandaloneTaskRuntimeBridge()
    with pytest.raises(ValueError, match="resume context resupply is required"):
        bridge.resume(
            configuration=_configuration(),
            run_id="11111111-1111-1111-1111-111111111111",
        )


def test_bootstrap_never_configures_cli_credential_as_bootstrap_operator_token() -> None:
    source = inspect.getsource(bootstrap._compose_runtime)
    assert "control_plane_operator_registry=operator_registry" in source
    assert "control_plane_operator_token=" not in source
    assert "SecurityContext(" not in inspect.getsource(bootstrap)
