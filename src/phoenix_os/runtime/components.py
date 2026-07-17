"""Reference lifecycle components and hook adapters."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

from phoenix_os.runtime.contracts import RuntimeContext

type LifecycleHook = Callable[[RuntimeContext], Awaitable[None] | None]


async def _run_hook(hook: LifecycleHook, context: RuntimeContext) -> None:
    result = hook(context)
    if inspect.isawaitable(result):
        await result


class HookComponent:
    """Adapt synchronous or asynchronous lifecycle hooks to a component."""

    def __init__(
        self,
        *,
        start: LifecycleHook | None = None,
        stop: LifecycleHook | None = None,
    ) -> None:
        if start is not None and not callable(start):
            raise TypeError("start hook must be callable")
        if stop is not None and not callable(stop):
            raise TypeError("stop hook must be callable")
        self._start = start
        self._stop = stop

    async def start(self, context: RuntimeContext) -> None:
        if self._start is not None:
            await _run_hook(self._start, context)

    async def stop(self, context: RuntimeContext) -> None:
        if self._stop is not None:
            await _run_hook(self._stop, context)
