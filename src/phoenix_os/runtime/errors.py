"""Phoenix Runtime lifecycle exceptions."""

from __future__ import annotations

from phoenix_os.runtime.contracts import ComponentFailure, RuntimePhase


class PhoenixRuntimeError(RuntimeError):
    """Base class for runtime lifecycle failures."""


class RuntimeStateError(PhoenixRuntimeError):
    """Raised when an operation is invalid for the current runtime state."""


class RuntimeNotRunningError(RuntimeStateError):
    """Raised when request handling is attempted outside RUNNING state."""


class RuntimeServiceNotFoundError(PhoenixRuntimeError):
    """Raised when a composed service name is unknown."""


class RuntimeStartError(PhoenixRuntimeError):
    """Raised after startup failure and best-effort rollback."""

    def __init__(
        self,
        failure: ComponentFailure,
        rollback_failures: tuple[ComponentFailure, ...],
    ) -> None:
        self.failure = failure
        self.rollback_failures = rollback_failures
        super().__init__(f"runtime startup failed in component {failure.component!r}")


class RuntimeStopError(PhoenixRuntimeError):
    """Raised after all possible shutdown hooks have been attempted."""

    def __init__(self, failures: tuple[ComponentFailure, ...]) -> None:
        self.failures = failures
        super().__init__(f"runtime shutdown failed in {len(failures)} component(s)")


class RuntimeDeadlineExceededError(PhoenixRuntimeError):
    """Raised when a lifecycle deadline expires."""

    def __init__(
        self,
        phase: RuntimePhase,
        rollback_failures: tuple[ComponentFailure, ...] = (),
    ) -> None:
        self.phase = phase
        self.rollback_failures = rollback_failures
        super().__init__(f"runtime {phase.value} deadline exceeded")
