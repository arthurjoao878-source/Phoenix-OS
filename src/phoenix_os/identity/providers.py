"""Provider adapters for Phoenix authentication."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

from phoenix_os.identity.contracts import AuthenticationRequest, Identity

type AuthenticationHook = Callable[[AuthenticationRequest], Identity | Awaitable[Identity]]


class CallableAuthenticationProvider:
    """Adapt a synchronous or asynchronous callable to AuthenticationProvider."""

    def __init__(self, hook: AuthenticationHook) -> None:
        if not callable(hook):
            raise TypeError("authentication hook must be callable")
        self._hook = hook

    async def authenticate(self, request: AuthenticationRequest) -> Identity:
        result = self._hook(request)
        identity = await result if inspect.isawaitable(result) else result
        if not isinstance(identity, Identity):
            raise TypeError("authentication provider must return Identity")
        return identity
