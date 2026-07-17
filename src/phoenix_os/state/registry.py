"""Named state-store registry and lifecycle ownership."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Iterable
from dataclasses import dataclass

from phoenix_os.state.contracts import StateStore
from phoenix_os.state.errors import (
    DuplicateStateStoreError,
    StateStoreClosedError,
    StateStoreNotFoundError,
)


def _normalize_store_name(name: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        raise ValueError("state store name must not be blank")
    return normalized


@dataclass(frozen=True, slots=True)
class StateStoreRegistration:
    """One named state store registered in deterministic order."""

    name: str
    store: StateStore

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_store_name(self.name))


class StateStoreRegistry:
    """Resolve named stores and own their deterministic lifecycle."""

    def __init__(
        self,
        registrations: Iterable[StateStoreRegistration] = (),
        *,
        default: str | None = None,
    ) -> None:
        self._stores: dict[str, StateStore] = {}
        self._order: list[str] = []
        self._closed = False
        self._started = False
        self._lock = asyncio.Lock()
        for registration in registrations:
            if registration.name in self._stores:
                raise DuplicateStateStoreError(
                    f"duplicate state store registration: {registration.name}"
                )
            self._stores[registration.name] = registration.store
            self._order.append(registration.name)
        if default is None:
            self._default = self._order[0] if len(self._order) == 1 else None
        else:
            normalized_default = _normalize_store_name(default)
            if normalized_default not in self._stores:
                raise StateStoreNotFoundError(
                    f"default state store not found: {normalized_default}"
                )
            self._default = normalized_default

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def default_name(self) -> str | None:
        return self._default

    async def register(
        self,
        name: str,
        store: StateStore,
        *,
        make_default: bool = False,
    ) -> StateStoreRegistration:
        normalized = _normalize_store_name(name)
        async with self._lock:
            self._ensure_open()
            if self._started:
                raise StateStoreClosedError("cannot register stores after registry startup")
            if normalized in self._stores:
                raise DuplicateStateStoreError(f"duplicate state store registration: {normalized}")
            self._stores[normalized] = store
            self._order.append(normalized)
            if make_default or (self._default is None and len(self._stores) == 1):
                self._default = normalized
            return StateStoreRegistration(normalized, store)

    async def remove(self, name: str) -> bool:
        normalized = _normalize_store_name(name)
        async with self._lock:
            self._ensure_open()
            if self._started:
                raise StateStoreClosedError("cannot remove stores after registry startup")
            removed = self._stores.pop(normalized, None)
            if removed is None:
                return False
            self._order.remove(normalized)
            if self._default == normalized:
                self._default = self._order[0] if len(self._order) == 1 else None
            return True

    def store(self, name: str | None = None) -> StateStore:
        self._ensure_open()
        selected = self._default if name is None else _normalize_store_name(name)
        if selected is None:
            raise StateStoreNotFoundError("no default state store is configured")
        try:
            return self._stores[selected]
        except KeyError as exception:
            raise StateStoreNotFoundError(f"state store not found: {selected}") from exception

    def names(self) -> tuple[str, ...]:
        self._ensure_open()
        return tuple(self._order)

    async def start(self, context: object) -> None:
        async with self._lock:
            self._ensure_open()
            if self._started:
                return
            started: list[StateStore] = []
            try:
                for name in self._order:
                    store = self._stores[name]
                    result = store.start(context)
                    if inspect.isawaitable(result):
                        await result
                    started.append(store)
            except BaseException:
                for store in reversed(started):
                    try:
                        await store.stop(context)
                    except BaseException:
                        pass
                raise
            self._started = True

    async def stop(self, context: object) -> None:
        async with self._lock:
            if self._closed:
                return
            failure: BaseException | None = None
            for name in reversed(self._order):
                try:
                    await self._stores[name].stop(context)
                except asyncio.CancelledError:
                    raise
                except BaseException as exception:
                    if failure is None:
                        failure = exception
            self._started = False
            self._closed = True
            if failure is not None:
                raise failure

    async def close(self) -> None:
        await self.stop(object())

    def _ensure_open(self) -> None:
        if self._closed:
            raise StateStoreClosedError("state store registry is closed")
