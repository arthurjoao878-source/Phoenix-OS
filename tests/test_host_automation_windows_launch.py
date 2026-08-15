import asyncio
import sys
import time
from datetime import UTC, datetime, timedelta

import pytest

import phoenix_os.host_automation.windows as windows_module
import phoenix_os.host_automation.windows_effects as effects_module
from phoenix_os.host_automation import (
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostApplicationNotConfiguredError,
    HostAutomationAdapterError,
    HostAutomationIndeterminateEffectError,
    HostAutomationLimits,
    HostAutomationTimeoutError,
    HostId,
    HostProcessListRequest,
    WindowsHostAutomationAdapter,
)
from phoenix_os.host_automation.windows_effects import WindowsApplicationProfile

_NOW = datetime(2026, 8, 15, 5, 40, tzinfo=UTC)
_HOST = HostId("desktop")
_APP = HostApplicationId("editor")


class _FakeDiscoveryBackend:
    def __init__(
        self,
        snapshots: tuple[windows_module._NativeProcessSnapshot, ...] = (
            windows_module._NativeProcessSnapshot(()),
        ),
    ) -> None:
        self._snapshots = snapshots
        self.calls = 0

    def enumerate_processes(
        self,
        *,
        maximum_records: int,
        maximum_label_characters: int,
    ) -> windows_module._NativeProcessSnapshot:
        del maximum_label_characters
        index = min(self.calls, len(self._snapshots) - 1)
        self.calls += 1
        snapshot = self._snapshots[index]
        records = snapshot.records[:maximum_records]
        return windows_module._NativeProcessSnapshot(
            records=records,
            truncated=snapshot.truncated or len(snapshot.records) > maximum_records,
        )

    def enumerate_windows(
        self,
        *,
        maximum_records: int,
        maximum_title_characters: int,
    ) -> windows_module._NativeWindowSnapshot:
        del maximum_records, maximum_title_characters
        return windows_module._NativeWindowSnapshot(())


class _SuccessfulEffectsBackend:
    def __init__(self, *, pid: int = 4242, creation_time: int = 9001) -> None:
        self.pid = pid
        self.creation_time = creation_time
        self.calls = 0
        self.profiles: list[WindowsApplicationProfile] = []

    def launch_application(
        self,
        profile: WindowsApplicationProfile,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> effects_module._WindowsLaunchedProcess:
        self.calls += 1
        self.profiles.append(profile)
        assert attempt.begin_effect() is True
        return effects_module._WindowsLaunchedProcess(
            pid=self.pid,
            creation_time=self.creation_time,
            label="editor.exe",
        )


class _FailingEffectsBackend:
    def __init__(self) -> None:
        self.calls = 0

    def launch_application(
        self,
        profile: WindowsApplicationProfile,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> effects_module._WindowsLaunchedProcess:
        del profile
        self.calls += 1
        assert attempt.begin_effect() is True
        raise OSError("native path=C:\\secret\\editor.exe pid=4242")


class _IndeterminateEffectsBackend:
    def __init__(self) -> None:
        self.calls = 0

    def launch_application(
        self,
        profile: WindowsApplicationProfile,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> effects_module._WindowsLaunchedProcess:
        del profile
        self.calls += 1
        assert attempt.begin_effect() is True
        raise effects_module._WindowsEffectIndeterminateError()


class _SlowBeforeAdmissionEffectsBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.started = False
        self.prevented = False

    def launch_application(
        self,
        profile: WindowsApplicationProfile,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> effects_module._WindowsLaunchedProcess:
        del profile
        self.calls += 1
        time.sleep(0.03)
        if not attempt.begin_effect():
            self.prevented = True
            raise effects_module._WindowsEffectPreventedError()
        self.started = True
        return effects_module._WindowsLaunchedProcess(
            pid=4242,
            creation_time=9001,
            label="editor.exe",
        )


class _SlowAfterAdmissionEffectsBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.started = False

    def launch_application(
        self,
        profile: WindowsApplicationProfile,
        *,
        attempt: effects_module._WindowsEffectAttempt,
    ) -> effects_module._WindowsLaunchedProcess:
        del profile
        self.calls += 1
        assert attempt.begin_effect() is True
        self.started = True
        time.sleep(0.03)
        return effects_module._WindowsLaunchedProcess(
            pid=4242,
            creation_time=9001,
            label="editor.exe",
        )


def _profile() -> WindowsApplicationProfile:
    return WindowsApplicationProfile(
        application_id=_APP,
        executable=r"C:\Program Files\Phoenix\editor.exe",
        working_directory=r"C:\Program Files\Phoenix",
    )


def _adapter(
    monkeypatch: pytest.MonkeyPatch,
    effects_backend: object,
    *,
    discovery_backend: _FakeDiscoveryBackend | None = None,
    limits: HostAutomationLimits | None = None,
    profiles: tuple[WindowsApplicationProfile, ...] | None = None,
) -> WindowsHostAutomationAdapter:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsDiscoveryBackend",
        lambda: discovery_backend or _FakeDiscoveryBackend(),
    )
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsEffectsBackend",
        lambda: effects_backend,
    )
    return WindowsHostAutomationAdapter(
        host_id=_HOST,
        limits=limits or HostAutomationLimits(),
        application_profiles=profiles if profiles is not None else (_profile(),),
    )


def test_windows_application_profile_is_exact_local_executable_configuration() -> None:
    profile = _profile()

    assert profile.application_id == _APP
    assert profile.executable == r"C:\Program Files\Phoenix\editor.exe"
    assert profile.working_directory == r"C:\Program Files\Phoenix"

    for value in (
        "editor.exe",
        r"\\server\share\editor.exe",
        r"\\?\C:\Apps\editor.exe",
        r"C:\Apps\editor.cmd",
        r"C:\Apps\editor.exe --unsafe",
        'C:\\Apps\\"editor.exe"',
    ):
        with pytest.raises(ValueError):
            WindowsApplicationProfile(application_id=_APP, executable=value)

    with pytest.raises(ValueError):
        WindowsApplicationProfile(
            application_id=_APP,
            executable=r"C:\Apps\editor.exe",
            working_directory="relative",
        )


def test_windows_application_profiles_reject_duplicate_server_owned_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        windows_module,
        "_CtypesWindowsDiscoveryBackend",
        _FakeDiscoveryBackend,
    )
    profile = _profile()

    with pytest.raises(ValueError, match="duplicate application id"):
        WindowsHostAutomationAdapter(
            host_id=_HOST,
            application_profiles=(profile, profile),
        )


@pytest.mark.asyncio
async def test_windows_launch_resolves_only_configured_profile_and_exposes_opaque_process_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SuccessfulEffectsBackend()
    adapter = _adapter(monkeypatch, effects)
    request = HostApplicationLaunchRequest(
        host_id=_HOST,
        application_id=_APP,
        created_at=_NOW,
    )

    result = await adapter.launch_application(request)

    assert effects.calls == 1
    assert effects.profiles == [_profile()]
    assert result.application_id == _APP
    assert result.host_epoch == adapter.host_epoch
    assert str(result.process_id) != "4242"


@pytest.mark.asyncio
async def test_launched_process_binding_survives_matching_read_only_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = windows_module._NativeProcessRecord(
        pid=4242,
        creation_time=9001,
        label=r"C:\Program Files\Phoenix\editor.exe",
    )
    discovery = _FakeDiscoveryBackend((windows_module._NativeProcessSnapshot((record,)),))
    adapter = _adapter(
        monkeypatch,
        _SuccessfulEffectsBackend(),
        discovery_backend=discovery,
    )

    launch = await adapter.launch_application(
        HostApplicationLaunchRequest(
            host_id=_HOST,
            application_id=_APP,
            created_at=_NOW,
        )
    )
    listed = await adapter.list_processes(HostProcessListRequest(host_id=_HOST, created_at=_NOW))

    assert listed.processes[0].process_id == launch.process_id
    assert listed.processes[0].application_id == _APP
    assert listed.processes[0].label == "editor.exe"


@pytest.mark.asyncio
async def test_unconfigured_windows_launch_fails_before_native_effect_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SuccessfulEffectsBackend()
    adapter = _adapter(monkeypatch, effects)

    with pytest.raises(HostApplicationNotConfiguredError):
        await adapter.launch_application(
            HostApplicationLaunchRequest(
                host_id=_HOST,
                application_id=HostApplicationId("not-configured"),
                created_at=_NOW,
            )
        )

    assert effects.calls == 0


@pytest.mark.asyncio
async def test_windows_launch_native_failure_is_safe_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _FailingEffectsBackend()
    adapter = _adapter(monkeypatch, effects)

    with pytest.raises(HostAutomationAdapterError) as captured:
        await adapter.launch_application(
            HostApplicationLaunchRequest(
                host_id=_HOST,
                application_id=_APP,
                created_at=_NOW,
            )
        )

    assert effects.calls == 1
    assert str(captured.value) == "host automation adapter failed"
    assert "secret" not in str(captured.value)
    assert "4242" not in str(captured.value)


@pytest.mark.asyncio
async def test_windows_launch_indeterminate_native_outcome_is_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _IndeterminateEffectsBackend()
    adapter = _adapter(monkeypatch, effects)

    with pytest.raises(HostAutomationIndeterminateEffectError):
        await adapter.launch_application(
            HostApplicationLaunchRequest(
                host_id=_HOST,
                application_id=_APP,
                created_at=_NOW,
            )
        )

    assert effects.calls == 1


@pytest.mark.asyncio
async def test_windows_launch_timeout_before_effect_admission_prevents_late_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SlowBeforeAdmissionEffectsBackend()
    limits = HostAutomationLimits(operation_timeout=timedelta(milliseconds=1))
    adapter = _adapter(monkeypatch, effects, limits=limits)

    with pytest.raises(HostAutomationTimeoutError):
        await adapter.launch_application(
            HostApplicationLaunchRequest(
                host_id=_HOST,
                application_id=_APP,
                created_at=_NOW,
            )
        )

    await asyncio.sleep(0.04)
    assert effects.calls == 1
    assert effects.prevented is True
    assert effects.started is False


@pytest.mark.asyncio
async def test_windows_launch_timeout_after_effect_admission_is_indeterminate_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _SlowAfterAdmissionEffectsBackend()
    limits = HostAutomationLimits(operation_timeout=timedelta(milliseconds=1))
    adapter = _adapter(monkeypatch, effects, limits=limits)

    with pytest.raises(HostAutomationIndeterminateEffectError):
        await adapter.launch_application(
            HostApplicationLaunchRequest(
                host_id=_HOST,
                application_id=_APP,
                created_at=_NOW,
            )
        )

    await asyncio.sleep(0.04)
    assert effects.calls == 1
    assert effects.started is True
