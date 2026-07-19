"""Bounded in-memory reference registry for local control-plane operators."""

from __future__ import annotations

import asyncio
from collections import Counter
from uuid import UUID

from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorAlreadyExistsError,
    ControlPlaneOperatorCapacityError,
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorNotFoundError,
    ControlPlaneOperatorRegistryClosedError,
)
from phoenix_os.control_plane.operator_contracts import (
    DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_REQUEST,
    MAX_CONTROL_PLANE_OPERATOR_CAPACITY,
    ControlPlaneOperatorPage,
    ControlPlaneOperatorPageInfo,
    ControlPlaneOperatorPageRequest,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistrySnapshot,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    _normalize_digest,
    _normalize_username,
)


class InMemoryControlPlaneOperatorRegistry:
    """Process-local registry with unique identities and optimistic replacement."""

    def __init__(self, *, capacity: int = 256) -> None:
        if capacity <= 0 or capacity > MAX_CONTROL_PLANE_OPERATOR_CAPACITY:
            raise ValueError(
                f"operator registry capacity must be between 1 and "
                f"{MAX_CONTROL_PLANE_OPERATOR_CAPACITY}"
            )
        self._capacity = capacity
        self._records: dict[UUID, ControlPlaneOperatorRecord] = {}
        self._username_index: dict[str, UUID] = {}
        self._token_index: dict[str, UUID] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: ControlPlaneOperatorRecord) -> None:
        async with self._lock:
            self._require_open()
            if len(self._records) >= self._capacity:
                raise ControlPlaneOperatorCapacityError(
                    "control-plane operator registry capacity has been exhausted"
                )
            if record.id in self._records:
                raise ControlPlaneOperatorAlreadyExistsError(
                    "control-plane operator id already exists"
                )
            if record.username in self._username_index:
                raise ControlPlaneOperatorAlreadyExistsError(
                    "control-plane operator username already exists"
                )
            if record.token_digest in self._token_index:
                raise ControlPlaneOperatorAlreadyExistsError(
                    "control-plane operator token digest already exists"
                )
            self._records[record.id] = record
            self._username_index[record.username] = record.id
            self._token_index[record.token_digest] = record.id

    async def get(self, operator_id: UUID) -> ControlPlaneOperatorRecord | None:
        async with self._lock:
            self._require_open()
            return self._records.get(operator_id)

    async def get_by_username(self, username: str) -> ControlPlaneOperatorRecord | None:
        normalized = _normalize_username(username)
        async with self._lock:
            self._require_open()
            operator_id = self._username_index.get(normalized)
            return None if operator_id is None else self._records[operator_id]

    async def get_by_token_digest(
        self,
        token_digest: str,
    ) -> ControlPlaneOperatorRecord | None:
        normalized = _normalize_digest(token_digest)
        async with self._lock:
            self._require_open()
            operator_id = self._token_index.get(normalized)
            return None if operator_id is None else self._records[operator_id]

    async def list_page(
        self,
        request: ControlPlaneOperatorPageRequest = DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_REQUEST,
    ) -> ControlPlaneOperatorPage:
        async with self._lock:
            self._require_open()
            ordered = tuple(
                sorted(
                    self._records.values(),
                    key=lambda item: (item.username, item.id.hex),
                )
            )
            items = ordered[request.offset : request.offset + request.limit]
            return ControlPlaneOperatorPage(
                items=items,
                page=ControlPlaneOperatorPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )

    async def replace(
        self,
        record: ControlPlaneOperatorRecord,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorRecord:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        async with self._lock:
            self._require_open()
            current = self._records.get(record.id)
            if current is None:
                raise ControlPlaneOperatorNotFoundError("control-plane operator was not found")
            if current.revision != expected_revision:
                raise ControlPlaneOperatorConflictError("control-plane operator revision conflict")
            if record.revision != expected_revision + 1:
                raise ControlPlaneOperatorConflictError(
                    "replacement operator revision must increment exactly once"
                )
            if record.created_at != current.created_at:
                raise ControlPlaneOperatorConflictError(
                    "replacement operator cannot change created_at"
                )
            if record.updated_at < current.updated_at:
                raise ControlPlaneOperatorConflictError(
                    "replacement operator updated_at cannot move backwards"
                )
            if record.schema_version != current.schema_version:
                raise ControlPlaneOperatorConflictError(
                    "replacement operator cannot change schema version"
                )

            username_owner = self._username_index.get(record.username)
            if username_owner is not None and username_owner != record.id:
                raise ControlPlaneOperatorAlreadyExistsError(
                    "control-plane operator username already exists"
                )
            token_owner = self._token_index.get(record.token_digest)
            if token_owner is not None and token_owner != record.id:
                raise ControlPlaneOperatorAlreadyExistsError(
                    "control-plane operator token digest already exists"
                )

            if current.username != record.username:
                del self._username_index[current.username]
                self._username_index[record.username] = record.id
            if current.token_digest != record.token_digest:
                del self._token_index[current.token_digest]
                self._token_index[record.token_digest] = record.id
            self._records[record.id] = record
            return record

    async def snapshot(self) -> ControlPlaneOperatorRegistrySnapshot:
        async with self._lock:
            statuses = Counter(record.status for record in self._records.values())
            roles = Counter(record.role for record in self._records.values())
            return ControlPlaneOperatorRegistrySnapshot(
                closed=self._closed,
                operators=len(self._records),
                active=statuses[ControlPlaneOperatorStatus.ACTIVE],
                disabled=statuses[ControlPlaneOperatorStatus.DISABLED],
                revoked=statuses[ControlPlaneOperatorStatus.REVOKED],
                viewers=roles[ControlPlaneOperatorRole.VIEWER],
                operators_role=roles[ControlPlaneOperatorRole.OPERATOR],
                maintainers=roles[ControlPlaneOperatorRole.MAINTAINER],
                capacity=self._capacity,
            )

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()
            self._username_index.clear()
            self._token_index.clear()
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneOperatorRegistryClosedError(
                "control-plane operator registry is closed"
            )
