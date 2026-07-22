"""Bounded in-memory repository for service accounts and API tokens."""

from __future__ import annotations

import asyncio
from collections import Counter
from uuid import UUID

from phoenix_os.control_plane.errors import (
    ControlPlaneApiTokenAlreadyExistsError,
    ControlPlaneApiTokenCapacityError,
    ControlPlaneApiTokenConflictError,
    ControlPlaneApiTokenNotFoundError,
    ControlPlaneServiceAccountAlreadyExistsError,
    ControlPlaneServiceAccountCapacityError,
    ControlPlaneServiceAccountConflictError,
    ControlPlaneServiceAccountNotFoundError,
    ControlPlaneServiceAccountRepositoryClosedError,
)
from phoenix_os.control_plane.service_account_contracts import (
    DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST,
    MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT,
    MAX_CONTROL_PLANE_SERVICE_ACCOUNT_CAPACITY,
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenPage,
    ControlPlaneApiTokenRotation,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountPage,
    ControlPlaneServiceAccountPageInfo,
    ControlPlaneServiceAccountPageRequest,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountRegistrySnapshot,
    ControlPlaneServiceAccountStatus,
    _normalize_digest,
    _normalize_name,
)


class InMemoryControlPlaneServiceAccountRepository:
    """Process-local repository with bounded unique indexes."""

    def __init__(
        self,
        *,
        account_capacity: int = 256,
        max_tokens_per_account: int = 8,
    ) -> None:
        if account_capacity <= 0 or account_capacity > MAX_CONTROL_PLANE_SERVICE_ACCOUNT_CAPACITY:
            raise ValueError(
                "service-account capacity must be between 1 and "
                f"{MAX_CONTROL_PLANE_SERVICE_ACCOUNT_CAPACITY}"
            )

        if (
            max_tokens_per_account <= 0
            or max_tokens_per_account > MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT
        ):
            raise ValueError(
                "API-token capacity must be between 1 and "
                f"{MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT}"
            )

        self._account_capacity = account_capacity
        self._max_tokens_per_account = max_tokens_per_account

        self._accounts: dict[
            UUID,
            ControlPlaneServiceAccountRecord,
        ] = {}
        self._account_name_index: dict[str, UUID] = {}

        self._tokens: dict[
            UUID,
            ControlPlaneApiTokenMetadata,
        ] = {}
        self._token_digest_index: dict[str, UUID] = {}
        self._token_ids_by_account: dict[
            UUID,
            set[UUID],
        ] = {}

        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add_account(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> None:
        async with self._lock:
            self._require_open()

            if len(self._accounts) >= self._account_capacity:
                raise ControlPlaneServiceAccountCapacityError(
                    "service-account repository capacity has been exhausted"
                )

            if record.id in self._accounts:
                raise ControlPlaneServiceAccountAlreadyExistsError(
                    "service-account id already exists"
                )

            if record.name in self._account_name_index:
                raise ControlPlaneServiceAccountAlreadyExistsError(
                    "service-account name already exists"
                )

            self._accounts[record.id] = record
            self._account_name_index[record.name] = record.id
            self._token_ids_by_account[record.id] = set()

    async def get_account(
        self,
        service_account_id: UUID,
    ) -> ControlPlaneServiceAccountRecord | None:
        async with self._lock:
            self._require_open()
            return self._accounts.get(service_account_id)

    async def get_account_by_name(
        self,
        name: str,
    ) -> ControlPlaneServiceAccountRecord | None:
        normalized = _normalize_name(name)

        async with self._lock:
            self._require_open()

            account_id = self._account_name_index.get(normalized)

            if account_id is None:
                return None

            return self._accounts[account_id]

    async def list_accounts(
        self,
        request: ControlPlaneServiceAccountPageRequest = (
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST
        ),
    ) -> ControlPlaneServiceAccountPage:
        async with self._lock:
            self._require_open()

            ordered = tuple(
                sorted(
                    self._accounts.values(),
                    key=lambda item: (
                        item.name,
                        item.id.hex,
                    ),
                )
            )

            items = ordered[request.offset : request.offset + request.limit]

            return ControlPlaneServiceAccountPage(
                items=items,
                page=ControlPlaneServiceAccountPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )

    async def replace_account(
        self,
        record: ControlPlaneServiceAccountRecord,
        *,
        expected_revision: int,
    ) -> ControlPlaneServiceAccountRecord:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        async with self._lock:
            self._require_open()

            current = self._accounts.get(record.id)

            if current is None:
                raise ControlPlaneServiceAccountNotFoundError("service account was not found")

            self._validate_account_replacement(
                current,
                record,
                expected_revision=expected_revision,
            )

            name_owner = self._account_name_index.get(record.name)

            if name_owner is not None and name_owner != record.id:
                raise ControlPlaneServiceAccountAlreadyExistsError(
                    "service-account name already exists"
                )

            if current.name != record.name:
                del self._account_name_index[current.name]
                self._account_name_index[record.name] = record.id

            self._accounts[record.id] = record
            return record

    async def add_token(
        self,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> None:
        async with self._lock:
            self._require_open()

            if metadata.service_account_id not in self._accounts:
                raise ControlPlaneServiceAccountNotFoundError("service account was not found")

            if metadata.id in self._tokens:
                raise ControlPlaneApiTokenAlreadyExistsError("API-token id already exists")

            if metadata.token_digest in self._token_digest_index:
                raise ControlPlaneApiTokenAlreadyExistsError("API-token digest already exists")

            account_tokens = self._token_ids_by_account[metadata.service_account_id]

            if len(account_tokens) >= self._max_tokens_per_account:
                raise ControlPlaneApiTokenCapacityError(
                    "service account API-token capacity has been exhausted"
                )

            self._tokens[metadata.id] = metadata
            self._token_digest_index[metadata.token_digest] = metadata.id
            account_tokens.add(metadata.id)

    async def get_token(
        self,
        token_id: UUID,
    ) -> ControlPlaneApiTokenMetadata | None:
        async with self._lock:
            self._require_open()
            return self._tokens.get(token_id)

    async def get_token_by_digest(
        self,
        token_digest: str,
    ) -> ControlPlaneApiTokenMetadata | None:
        normalized = _normalize_digest(
            token_digest,
            label="API token digest",
        )

        async with self._lock:
            self._require_open()

            token_id = self._token_digest_index.get(normalized)

            if token_id is None:
                return None

            return self._tokens[token_id]

    async def list_tokens(
        self,
        service_account_id: UUID,
        request: ControlPlaneServiceAccountPageRequest = (
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST
        ),
    ) -> ControlPlaneApiTokenPage:
        async with self._lock:
            self._require_open()

            if service_account_id not in self._accounts:
                raise ControlPlaneServiceAccountNotFoundError("service account was not found")

            token_ids = self._token_ids_by_account[service_account_id]

            ordered = tuple(
                sorted(
                    (self._tokens[token_id] for token_id in token_ids),
                    key=lambda item: (
                        item.issued_at,
                        item.id.hex,
                    ),
                )
            )

            items = ordered[request.offset : request.offset + request.limit]

            return ControlPlaneApiTokenPage(
                items=items,
                page=ControlPlaneServiceAccountPageInfo.from_slice(
                    request,
                    returned=len(items),
                    total=len(ordered),
                ),
            )

    async def replace_token(
        self,
        metadata: ControlPlaneApiTokenMetadata,
        *,
        expected_revision: int,
    ) -> ControlPlaneApiTokenMetadata:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        async with self._lock:
            self._require_open()

            current = self._tokens.get(metadata.id)

            if current is None:
                raise ControlPlaneApiTokenNotFoundError("API-token metadata was not found")

            self._validate_token_replacement(
                current,
                metadata,
                expected_revision=expected_revision,
            )

            self._tokens[metadata.id] = metadata
            return metadata

    async def delete_terminal_token(
        self,
        token_id: UUID,
        *,
        expected_revision: int,
    ) -> None:
        """Delete one standalone terminal API-token record."""

        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        async with self._lock:
            self._require_open()

            current = self._tokens.get(token_id)

            if current is None:
                raise ControlPlaneApiTokenNotFoundError("API-token metadata was not found")

            if current.revision != expected_revision:
                raise ControlPlaneApiTokenConflictError("API-token revision conflict")

            if current.status is ControlPlaneApiTokenStatus.ACTIVE:
                raise ControlPlaneApiTokenConflictError("active API token cannot be deleted")

            referenced = any(
                metadata.rotated_from == current.id for metadata in self._tokens.values()
            )

            if current.rotated_from is not None or referenced:
                raise ControlPlaneApiTokenConflictError("lineage-bound API token cannot be deleted")

            del self._tokens[current.id]
            del self._token_digest_index[current.token_digest]
            self._token_ids_by_account[current.service_account_id].remove(current.id)

    async def rotate_token(
        self,
        predecessor: ControlPlaneApiTokenMetadata,
        successor: ControlPlaneApiTokenMetadata,
        *,
        expected_revision: int,
    ) -> ControlPlaneApiTokenRotation:
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        async with self._lock:
            self._require_open()

            current = self._tokens.get(predecessor.id)

            if current is None:
                raise ControlPlaneApiTokenNotFoundError("API-token metadata was not found")

            self._validate_token_replacement(
                current,
                predecessor,
                expected_revision=expected_revision,
            )

            rotation = ControlPlaneApiTokenRotation(
                predecessor=predecessor,
                successor=successor,
            )

            rotation_time = successor.issued_at

            if (
                current.status is not ControlPlaneApiTokenStatus.ACTIVE
                or not current.authenticatable_at(rotation_time)
            ):
                raise ControlPlaneApiTokenConflictError(
                    "only an active unexpired API token can be rotated"
                )

            if any(token.rotated_from == current.id for token in self._tokens.values()):
                raise ControlPlaneApiTokenConflictError(
                    "API token already has a rotation successor"
                )

            if successor.id in self._tokens:
                raise (
                    ControlPlaneApiTokenAlreadyExistsError("API-token successor id already exists")
                )

            if successor.token_digest in self._token_digest_index:
                raise (
                    ControlPlaneApiTokenAlreadyExistsError(
                        "API-token successor digest already exists"
                    )
                )

            account_tokens = self._token_ids_by_account[current.service_account_id]

            if len(account_tokens) >= self._max_tokens_per_account:
                raise ControlPlaneApiTokenCapacityError(
                    "service account API-token capacity has been exhausted"
                )

            self._tokens[predecessor.id] = predecessor
            self._tokens[successor.id] = successor

            self._token_digest_index[successor.token_digest] = successor.id

            account_tokens.add(successor.id)

            return rotation

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountRegistrySnapshot:
        async with self._lock:
            account_statuses = Counter(record.status for record in self._accounts.values())
            token_statuses = Counter(metadata.status for metadata in self._tokens.values())

            return ControlPlaneServiceAccountRegistrySnapshot(
                closed=self._closed,
                accounts=len(self._accounts),
                active_accounts=account_statuses[ControlPlaneServiceAccountStatus.ACTIVE],
                disabled_accounts=account_statuses[ControlPlaneServiceAccountStatus.DISABLED],
                revoked_accounts=account_statuses[ControlPlaneServiceAccountStatus.REVOKED],
                tokens=len(self._tokens),
                active_tokens=token_statuses[ControlPlaneApiTokenStatus.ACTIVE],
                revoked_tokens=token_statuses[ControlPlaneApiTokenStatus.REVOKED],
                expired_tokens=token_statuses[ControlPlaneApiTokenStatus.EXPIRED],
                account_capacity=self._account_capacity,
                max_tokens_per_account=(self._max_tokens_per_account),
            )

    async def close(self) -> None:
        async with self._lock:
            self._accounts.clear()
            self._account_name_index.clear()
            self._tokens.clear()
            self._token_digest_index.clear()
            self._token_ids_by_account.clear()
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneServiceAccountRepositoryClosedError(
                "service-account repository is closed"
            )

    @staticmethod
    def _validate_account_replacement(
        current: ControlPlaneServiceAccountRecord,
        replacement: ControlPlaneServiceAccountRecord,
        *,
        expected_revision: int,
    ) -> None:
        if current.revision != expected_revision:
            raise ControlPlaneServiceAccountConflictError("service-account revision conflict")

        if replacement.revision != expected_revision + 1:
            raise ControlPlaneServiceAccountConflictError(
                "replacement service-account revision must increment exactly once"
            )

        if replacement.created_at != current.created_at:
            raise ControlPlaneServiceAccountConflictError(
                "replacement service account cannot change created_at"
            )

        if replacement.updated_at < current.updated_at:
            raise ControlPlaneServiceAccountConflictError(
                "replacement service-account updated_at cannot move backwards"
            )

        if replacement.schema_version != current.schema_version:
            raise ControlPlaneServiceAccountConflictError(
                "replacement service account cannot change schema version"
            )

    @staticmethod
    def _validate_token_replacement(
        current: ControlPlaneApiTokenMetadata,
        replacement: ControlPlaneApiTokenMetadata,
        *,
        expected_revision: int,
    ) -> None:
        if current.revision != expected_revision:
            raise ControlPlaneApiTokenConflictError("API-token revision conflict")

        if replacement.revision != expected_revision + 1:
            raise ControlPlaneApiTokenConflictError(
                "replacement API-token revision must increment exactly once"
            )

        if replacement.updated_at < current.updated_at:
            raise ControlPlaneApiTokenConflictError(
                "replacement API-token updated_at cannot move backwards"
            )

        immutable_fields = (
            replacement.id == current.id,
            (replacement.service_account_id == current.service_account_id),
            replacement.label == current.label,
            (replacement.token_digest == current.token_digest),
            replacement.scopes == current.scopes,
            replacement.resources == current.resources,
            (replacement.restriction == current.restriction),
            replacement.issued_at == current.issued_at,
            (
                replacement.expires_at == current.expires_at
                or (
                    current.status is ControlPlaneApiTokenStatus.ACTIVE
                    and replacement.status is ControlPlaneApiTokenStatus.ACTIVE
                    and replacement.expires_at < current.expires_at
                    and replacement.expires_at > replacement.updated_at
                )
            ),
            (replacement.rotated_from == current.rotated_from),
            (replacement.token_version == current.token_version),
            (replacement.schema_version == current.schema_version),
        )

        if not all(immutable_fields):
            raise ControlPlaneApiTokenConflictError(
                "replacement cannot change immutable API-token metadata"
            )
