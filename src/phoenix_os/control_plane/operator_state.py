"""Durable local-operator registry backed by the Phoenix State Store."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import cast
from uuid import UUID

from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorAlreadyExistsError,
    ControlPlaneOperatorCapacityError,
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorCorruptionError,
    ControlPlaneOperatorNotFoundError,
    ControlPlaneOperatorPersistenceError,
    ControlPlaneOperatorRegistryClosedError,
    ControlPlaneOperatorSchemaError,
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
from phoenix_os.policy import PrincipalType
from phoenix_os.state import (
    ABSENT_VERSION,
    PhoenixStateError,
    StateConflictError,
    StateKey,
    StateOperationContext,
    StateRecord,
    StateStore,
)

_SCHEMA_VERSION = 1
_RECORD_KIND = "phoenix.control-plane.operator.record"
_USERNAME_INDEX_KIND = "phoenix.control-plane.operator.username-index"
_TOKEN_INDEX_KIND = "phoenix.control-plane.operator.token-index"
_RECORD_PREFIX = "operator_"
_USERNAME_PREFIX = "username_"
_TOKEN_PREFIX = "token_"
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "username",
        "display_name",
        "role",
        "token_digest",
        "created_at",
        "updated_at",
        "additional_permissions",
        "status",
        "disabled_at",
        "revoked_at",
        "token_version",
        "revision",
    }
)
_RECORD_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record", "record_digest"})
_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "operator_id",
        "username",
        "token_digest",
        "token_version",
        "revision",
        "record_digest",
    }
)


def canonical_control_plane_operator_record_bytes(record: ControlPlaneOperatorRecord) -> bytes:
    """Return deterministic schema-v1 JSON bytes for one credential-safe record."""

    return _canonical_json_bytes(_record_document(record))


def control_plane_operator_record_digest(record: ControlPlaneOperatorRecord) -> str:
    """Return the SHA-256 digest used to detect persisted record corruption."""

    return hashlib.sha256(canonical_control_plane_operator_record_bytes(record)).hexdigest()


class StateControlPlaneOperatorRegistry:
    """Persist operators and unique identity indexes through atomic State Store writes."""

    def __init__(
        self,
        store: StateStore,
        *,
        capacity: int = 256,
        namespace: str = "control-plane-operators",
        context: StateOperationContext | None = None,
    ) -> None:
        if capacity <= 0 or capacity > MAX_CONTROL_PLANE_OPERATOR_CAPACITY:
            raise ValueError(
                f"operator registry capacity must be between 1 and "
                f"{MAX_CONTROL_PLANE_OPERATOR_CAPACITY}"
            )
        probe = StateKey(namespace, f"{_RECORD_PREFIX}{'0' * 32}", dict)
        self._store = store
        self._capacity = capacity
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.control-plane.operator-registry",
                "principal_type": PrincipalType.SYSTEM.value,
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: ControlPlaneOperatorRecord) -> None:
        self._ensure_open()
        record_key = self._record_key(record.id)
        username_key = self._username_key(record.username)
        token_key = self._token_key(record.token_digest)
        try:
            async with self._store.transaction(context=self._context) as transaction:
                records = await transaction.list(namespace=self._namespace, prefix=_RECORD_PREFIX)
                username_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_USERNAME_PREFIX,
                )
                token_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_TOKEN_PREFIX,
                )
                _validate_persisted_collection(records, username_indexes, token_indexes)
                if len(records) >= self._capacity:
                    raise ControlPlaneOperatorCapacityError(
                        "control-plane operator registry capacity has been exhausted"
                    )
                if await transaction.get(record_key) is not None:
                    raise ControlPlaneOperatorAlreadyExistsError(
                        "control-plane operator id already exists"
                    )
                if await transaction.get(username_key) is not None:
                    raise ControlPlaneOperatorAlreadyExistsError(
                        "control-plane operator username already exists"
                    )
                if await transaction.get(token_key) is not None:
                    raise ControlPlaneOperatorAlreadyExistsError(
                        "control-plane operator token digest already exists"
                    )
                await transaction.put(
                    record_key,
                    _record_envelope(record),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    username_key,
                    _index_document(record, kind=_USERNAME_INDEX_KIND),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    token_key,
                    _index_document(record, kind=_TOKEN_INDEX_KIND),
                    expected_version=ABSENT_VERSION,
                )
        except (
            ControlPlaneOperatorAlreadyExistsError,
            ControlPlaneOperatorCapacityError,
            ControlPlaneOperatorCorruptionError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneOperatorAlreadyExistsError(
                "control-plane operator identity already exists"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneOperatorPersistenceError(
                "control-plane operator persistence operation failed"
            ) from exception

    async def get(self, operator_id: UUID) -> ControlPlaneOperatorRecord | None:
        self._ensure_open()
        try:
            stored_record = await self._store.get(
                self._record_key(operator_id),
                context=self._context,
            )
            if stored_record is None:
                return None
            record = _decode_record_state(stored_record)
            if record.id != operator_id:
                raise ControlPlaneOperatorCorruptionError(
                    "persisted operator identity does not match its state key"
                )
            return await self._read_and_verify_indexes(record)
        except ControlPlaneOperatorCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise ControlPlaneOperatorPersistenceError(
                "control-plane operator persistence operation failed"
            ) from exception

    async def get_by_username(self, username: str) -> ControlPlaneOperatorRecord | None:
        self._ensure_open()
        normalized = _normalize_username(username)
        try:
            stored_index = await self._store.get(
                self._username_key(normalized),
                context=self._context,
            )
            if stored_index is None:
                return None
            index = _decode_index_state(stored_index, expected_kind=_USERNAME_INDEX_KIND)
            if index.username != normalized:
                raise ControlPlaneOperatorCorruptionError(
                    "persisted operator username index does not match its state key"
                )
            stored_record = await self._store.get(
                self._record_key(index.operator_id),
                context=self._context,
            )
            if stored_record is None:
                raise ControlPlaneOperatorCorruptionError(
                    "persisted operator username index references a missing record"
                )
            record = _decode_record_state(stored_record)
            _verify_index_record(index, record)
            return await self._read_and_verify_indexes(record)
        except ControlPlaneOperatorCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise ControlPlaneOperatorPersistenceError(
                "control-plane operator persistence operation failed"
            ) from exception

    async def get_by_token_digest(
        self,
        token_digest: str,
    ) -> ControlPlaneOperatorRecord | None:
        self._ensure_open()
        normalized = _normalize_digest(token_digest)
        try:
            stored_index = await self._store.get(
                self._token_key(normalized),
                context=self._context,
            )
            if stored_index is None:
                return None
            index = _decode_index_state(stored_index, expected_kind=_TOKEN_INDEX_KIND)
            if not hmac.compare_digest(index.token_digest, normalized):
                raise ControlPlaneOperatorCorruptionError(
                    "persisted operator token index does not match its state key"
                )
            stored_record = await self._store.get(
                self._record_key(index.operator_id),
                context=self._context,
            )
            if stored_record is None:
                raise ControlPlaneOperatorCorruptionError(
                    "persisted operator token index references a missing record"
                )
            record = _decode_record_state(stored_record)
            _verify_index_record(index, record)
            return await self._read_and_verify_indexes(record)
        except ControlPlaneOperatorCorruptionError:
            raise
        except PhoenixStateError as exception:
            raise ControlPlaneOperatorPersistenceError(
                "control-plane operator persistence operation failed"
            ) from exception

    async def list_page(
        self,
        request: ControlPlaneOperatorPageRequest = DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_REQUEST,
    ) -> ControlPlaneOperatorPage:
        records = await self._load_records()
        ordered = tuple(sorted(records, key=lambda item: (item.username, item.id.hex)))
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
        self._ensure_open()
        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")
        record_key = self._record_key(record.id)
        try:
            async with self._store.transaction(context=self._context) as transaction:
                records = await transaction.list(namespace=self._namespace, prefix=_RECORD_PREFIX)
                username_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_USERNAME_PREFIX,
                )
                token_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_TOKEN_PREFIX,
                )
                _validate_persisted_collection(records, username_indexes, token_indexes)
                stored_current = await transaction.get(record_key)
                if stored_current is None:
                    raise ControlPlaneOperatorNotFoundError("control-plane operator was not found")
                current = _decode_record_state(stored_current)
                _validate_replacement(current, record, expected_revision=expected_revision)

                old_username_key = self._username_key(current.username)
                old_token_key = self._token_key(current.token_digest)
                stored_old_username = await transaction.get(old_username_key)
                stored_old_token = await transaction.get(old_token_key)
                if stored_old_username is None or stored_old_token is None:
                    raise ControlPlaneOperatorCorruptionError(
                        "persisted operator record has incomplete indexes"
                    )
                _verify_index_record(
                    _decode_index_state(
                        stored_old_username,
                        expected_kind=_USERNAME_INDEX_KIND,
                    ),
                    current,
                )
                _verify_index_record(
                    _decode_index_state(stored_old_token, expected_kind=_TOKEN_INDEX_KIND),
                    current,
                )

                new_username_key = self._username_key(record.username)
                new_token_key = self._token_key(record.token_digest)
                stored_new_username = await transaction.get(new_username_key)
                stored_new_token = await transaction.get(new_token_key)
                if new_username_key != old_username_key and stored_new_username is not None:
                    raise ControlPlaneOperatorAlreadyExistsError(
                        "control-plane operator username already exists"
                    )
                if new_token_key != old_token_key and stored_new_token is not None:
                    raise ControlPlaneOperatorAlreadyExistsError(
                        "control-plane operator token digest already exists"
                    )

                await transaction.put(
                    record_key,
                    _record_envelope(record),
                    expected_version=stored_current.version,
                )
                if new_username_key == old_username_key:
                    await transaction.put(
                        old_username_key,
                        _index_document(record, kind=_USERNAME_INDEX_KIND),
                        expected_version=stored_old_username.version,
                    )
                else:
                    await transaction.delete(
                        old_username_key,
                        expected_version=stored_old_username.version,
                    )
                    await transaction.put(
                        new_username_key,
                        _index_document(record, kind=_USERNAME_INDEX_KIND),
                        expected_version=ABSENT_VERSION,
                    )
                if new_token_key == old_token_key:
                    await transaction.put(
                        old_token_key,
                        _index_document(record, kind=_TOKEN_INDEX_KIND),
                        expected_version=stored_old_token.version,
                    )
                else:
                    await transaction.delete(
                        old_token_key,
                        expected_version=stored_old_token.version,
                    )
                    await transaction.put(
                        new_token_key,
                        _index_document(record, kind=_TOKEN_INDEX_KIND),
                        expected_version=ABSENT_VERSION,
                    )
                return record
        except (
            ControlPlaneOperatorAlreadyExistsError,
            ControlPlaneOperatorConflictError,
            ControlPlaneOperatorCorruptionError,
            ControlPlaneOperatorNotFoundError,
        ):
            raise
        except StateConflictError as exception:
            raise ControlPlaneOperatorConflictError(
                "control-plane operator state changed concurrently"
            ) from exception
        except PhoenixStateError as exception:
            raise ControlPlaneOperatorPersistenceError(
                "control-plane operator persistence operation failed"
            ) from exception

    async def snapshot(self) -> ControlPlaneOperatorRegistrySnapshot:
        records = await self._load_records(require_open=False)
        statuses = Counter(record.status for record in records)
        roles = Counter(record.role for record in records)
        return ControlPlaneOperatorRegistrySnapshot(
            closed=self._closed,
            operators=len(records),
            active=statuses[ControlPlaneOperatorStatus.ACTIVE],
            disabled=statuses[ControlPlaneOperatorStatus.DISABLED],
            revoked=statuses[ControlPlaneOperatorStatus.REVOKED],
            viewers=roles[ControlPlaneOperatorRole.VIEWER],
            operators_role=roles[ControlPlaneOperatorRole.OPERATOR],
            maintainers=roles[ControlPlaneOperatorRole.MAINTAINER],
            capacity=self._capacity,
        )

    async def close(self) -> None:
        # The registry borrows the State Store; Runtime owns the store lifecycle.
        self._closed = True

    async def _read_and_verify_indexes(
        self,
        record: ControlPlaneOperatorRecord,
    ) -> ControlPlaneOperatorRecord:
        stored_username = await self._store.get(
            self._username_key(record.username),
            context=self._context,
        )
        stored_token = await self._store.get(
            self._token_key(record.token_digest),
            context=self._context,
        )
        if stored_username is None or stored_token is None:
            raise ControlPlaneOperatorCorruptionError(
                "persisted operator record has incomplete indexes"
            )
        username_index = _decode_index_state(
            stored_username,
            expected_kind=_USERNAME_INDEX_KIND,
        )
        token_index = _decode_index_state(stored_token, expected_kind=_TOKEN_INDEX_KIND)
        if stored_username.key.name != f"{_USERNAME_PREFIX}{record.username}":
            raise ControlPlaneOperatorCorruptionError(
                "persisted operator username index does not match its state key"
            )
        if stored_token.key.name != f"{_TOKEN_PREFIX}{record.token_digest}":
            raise ControlPlaneOperatorCorruptionError(
                "persisted operator token index does not match its state key"
            )
        _verify_index_record(username_index, record)
        _verify_index_record(token_index, record)
        return record

    async def _load_records(
        self,
        *,
        require_open: bool = True,
    ) -> tuple[ControlPlaneOperatorRecord, ...]:
        if require_open:
            self._ensure_open()
        try:
            records = await self._store.list(
                namespace=self._namespace,
                prefix=_RECORD_PREFIX,
                context=self._context,
            )
            username_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_USERNAME_PREFIX,
                context=self._context,
            )
            token_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_TOKEN_PREFIX,
                context=self._context,
            )
        except PhoenixStateError as exception:
            raise ControlPlaneOperatorPersistenceError(
                "control-plane operator persistence operation failed"
            ) from exception
        decoded = _validate_persisted_collection(records, username_indexes, token_indexes)
        if len(decoded) > self._capacity:
            raise ControlPlaneOperatorCorruptionError(
                "persisted operator entries exceed configured registry capacity"
            )
        return decoded

    def _record_key(self, operator_id: UUID) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"{_RECORD_PREFIX}{operator_id.hex}", dict)

    def _username_key(self, username: str) -> StateKey[dict[str, object]]:
        normalized = _normalize_username(username)
        return StateKey(self._namespace, f"{_USERNAME_PREFIX}{normalized}", dict)

    def _token_key(self, token_digest: str) -> StateKey[dict[str, object]]:
        normalized = _normalize_digest(token_digest)
        return StateKey(self._namespace, f"{_TOKEN_PREFIX}{normalized}", dict)

    def _ensure_open(self) -> None:
        if self._closed:
            raise ControlPlaneOperatorRegistryClosedError(
                "control-plane operator registry is closed"
            )


class _DecodedIndex:
    __slots__ = (
        "kind",
        "operator_id",
        "record_digest",
        "revision",
        "token_digest",
        "token_version",
        "username",
    )

    def __init__(
        self,
        *,
        kind: str,
        operator_id: UUID,
        username: str,
        token_digest: str,
        token_version: int,
        revision: int,
        record_digest: str,
    ) -> None:
        self.kind = kind
        self.operator_id = operator_id
        self.username = username
        self.token_digest = token_digest
        self.token_version = token_version
        self.revision = revision
        self.record_digest = record_digest


def _validate_replacement(
    current: ControlPlaneOperatorRecord,
    replacement: ControlPlaneOperatorRecord,
    *,
    expected_revision: int,
) -> None:
    if current.revision != expected_revision:
        raise ControlPlaneOperatorConflictError("control-plane operator revision conflict")
    if replacement.revision != expected_revision + 1:
        raise ControlPlaneOperatorConflictError(
            "replacement operator revision must increment exactly once"
        )
    if replacement.created_at != current.created_at:
        raise ControlPlaneOperatorConflictError("replacement operator cannot change created_at")
    if replacement.updated_at < current.updated_at:
        raise ControlPlaneOperatorConflictError(
            "replacement operator updated_at cannot move backwards"
        )
    if replacement.schema_version != current.schema_version:
        raise ControlPlaneOperatorConflictError("replacement operator cannot change schema version")


def _validate_persisted_collection(
    stored_records: tuple[StateRecord[object], ...],
    stored_username_indexes: tuple[StateRecord[object], ...],
    stored_token_indexes: tuple[StateRecord[object], ...],
) -> tuple[ControlPlaneOperatorRecord, ...]:
    records = tuple(_decode_record_state(item) for item in stored_records)
    username_indexes = tuple(
        _decode_index_state(item, expected_kind=_USERNAME_INDEX_KIND)
        for item in stored_username_indexes
    )
    token_indexes = tuple(
        _decode_index_state(item, expected_kind=_TOKEN_INDEX_KIND) for item in stored_token_indexes
    )
    ids = tuple(record.id for record in records)
    usernames = tuple(record.username for record in records)
    digests = tuple(record.token_digest for record in records)
    if (
        len(ids) != len(set(ids))
        or len(usernames) != len(set(usernames))
        or len(digests) != len(set(digests))
    ):
        raise ControlPlaneOperatorCorruptionError(
            "persisted operator registry contains duplicate identities"
        )
    if len(records) != len(username_indexes) or len(records) != len(token_indexes):
        raise ControlPlaneOperatorCorruptionError(
            "persisted operator records and indexes are incomplete"
        )
    if (
        len({index.username for index in username_indexes}) != len(username_indexes)
        or len({index.token_digest for index in token_indexes}) != len(token_indexes)
        or len({index.operator_id for index in username_indexes}) != len(username_indexes)
        or len({index.operator_id for index in token_indexes}) != len(token_indexes)
    ):
        raise ControlPlaneOperatorCorruptionError(
            "persisted operator registry contains duplicate indexes"
        )

    username_by_name = {index.username: index for index in username_indexes}
    token_by_digest = {index.token_digest: index for index in token_indexes}
    for stored_record, record in zip(stored_records, records, strict=True):
        if stored_record.key.name != f"{_RECORD_PREFIX}{record.id.hex}":
            raise ControlPlaneOperatorCorruptionError(
                "persisted operator identity does not match its state key"
            )
        username_index = username_by_name.get(record.username)
        token_index = token_by_digest.get(record.token_digest)
        if username_index is None or token_index is None:
            raise ControlPlaneOperatorCorruptionError(
                "persisted operator record has incomplete indexes"
            )
        _verify_index_record(username_index, record)
        _verify_index_record(token_index, record)
    for stored, index in zip(stored_username_indexes, username_indexes, strict=True):
        if stored.key.name != f"{_USERNAME_PREFIX}{index.username}":
            raise ControlPlaneOperatorCorruptionError(
                "persisted operator username index does not match its state key"
            )
    for stored, index in zip(stored_token_indexes, token_indexes, strict=True):
        if stored.key.name != f"{_TOKEN_PREFIX}{index.token_digest}":
            raise ControlPlaneOperatorCorruptionError(
                "persisted operator token index does not match its state key"
            )
    return records


def _record_document(record: ControlPlaneOperatorRecord) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "id": str(record.id),
        "username": record.username,
        "display_name": record.display_name,
        "role": record.role.value,
        "token_digest": record.token_digest,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "additional_permissions": sorted(record.additional_permissions),
        "status": record.status.value,
        "disabled_at": None if record.disabled_at is None else record.disabled_at.isoformat(),
        "revoked_at": None if record.revoked_at is None else record.revoked_at.isoformat(),
        "token_version": record.token_version,
        "revision": record.revision,
    }


def _record_envelope(record: ControlPlaneOperatorRecord) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _RECORD_KIND,
        "record": _record_document(record),
        "record_digest": control_plane_operator_record_digest(record),
    }


def _index_document(record: ControlPlaneOperatorRecord, *, kind: str) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": kind,
        "operator_id": str(record.id),
        "username": record.username,
        "token_digest": record.token_digest,
        "token_version": record.token_version,
        "revision": record.revision,
        "record_digest": control_plane_operator_record_digest(record),
    }


def _decode_record_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
) -> ControlPlaneOperatorRecord:
    value = _mapping(stored.value, label="record envelope")
    _require_exact_fields(value, _RECORD_ENVELOPE_FIELDS, label="record envelope")
    _require_schema(value)
    if _string(value, "kind") != _RECORD_KIND:
        raise ControlPlaneOperatorCorruptionError("persisted operator record kind is invalid")
    document = _mapping(value.get("record"), label="record")
    _require_exact_fields(document, _RECORD_FIELDS, label="record")
    expected_digest = _normalize_digest(_string(value, "record_digest"))
    actual_digest = hashlib.sha256(_canonical_json_bytes(document)).hexdigest()
    if not hmac.compare_digest(expected_digest, actual_digest):
        raise ControlPlaneOperatorCorruptionError("persisted operator record digest does not match")
    try:
        schema_version = _integer(document, "schema_version")
        if schema_version != _SCHEMA_VERSION:
            raise ControlPlaneOperatorSchemaError("persisted operator record schema is unsupported")
        permissions = _string_sequence(document, "additional_permissions")
        if permissions != tuple(sorted(set(permissions))):
            raise ValueError("persisted operator permissions are not canonical")
        return ControlPlaneOperatorRecord(
            id=UUID(_string(document, "id")),
            username=_string(document, "username"),
            display_name=_string(document, "display_name"),
            role=ControlPlaneOperatorRole(_string(document, "role")),
            token_digest=_string(document, "token_digest"),
            created_at=_datetime(document, "created_at"),
            updated_at=_datetime(document, "updated_at"),
            additional_permissions=frozenset(permissions),
            status=ControlPlaneOperatorStatus(_string(document, "status")),
            disabled_at=_optional_datetime(document, "disabled_at"),
            revoked_at=_optional_datetime(document, "revoked_at"),
            token_version=_integer(document, "token_version"),
            revision=_integer(document, "revision"),
            schema_version=schema_version,
        )
    except ControlPlaneOperatorSchemaError:
        raise
    except (TypeError, ValueError) as exception:
        raise ControlPlaneOperatorCorruptionError(
            "persisted operator record is invalid"
        ) from exception


def _decode_index_state(
    stored: StateRecord[dict[str, object]] | StateRecord[object],
    *,
    expected_kind: str,
) -> _DecodedIndex:
    value = _mapping(stored.value, label="index")
    _require_exact_fields(value, _INDEX_FIELDS, label="index")
    _require_schema(value)
    kind = _string(value, "kind")
    if kind != expected_kind:
        raise ControlPlaneOperatorCorruptionError("persisted operator index kind is invalid")
    try:
        return _DecodedIndex(
            kind=kind,
            operator_id=UUID(_string(value, "operator_id")),
            username=_normalize_username(_string(value, "username")),
            token_digest=_normalize_digest(_string(value, "token_digest")),
            token_version=_positive_integer(value, "token_version"),
            revision=_positive_integer(value, "revision"),
            record_digest=_normalize_digest(_string(value, "record_digest")),
        )
    except (TypeError, ValueError) as exception:
        raise ControlPlaneOperatorCorruptionError(
            "persisted operator index is invalid"
        ) from exception


def _verify_index_record(index: _DecodedIndex, record: ControlPlaneOperatorRecord) -> None:
    digest = control_plane_operator_record_digest(record)
    if (
        index.operator_id != record.id
        or index.username != record.username
        or not hmac.compare_digest(index.token_digest, record.token_digest)
        or index.token_version != record.token_version
        or index.revision != record.revision
        or not hmac.compare_digest(index.record_digest, digest)
    ):
        raise ControlPlaneOperatorCorruptionError(
            "persisted operator index and record do not match"
        )


def _require_schema(value: Mapping[str, object]) -> None:
    try:
        schema_version = _integer(value, "schema_version")
    except ValueError as exception:
        raise ControlPlaneOperatorCorruptionError(
            "persisted operator schema field is invalid"
        ) from exception
    if schema_version != _SCHEMA_VERSION:
        raise ControlPlaneOperatorSchemaError("persisted operator schema is unsupported")


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise ControlPlaneOperatorCorruptionError(f"persisted operator {label} fields are invalid")


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ControlPlaneOperatorCorruptionError(f"persisted operator {label} is invalid")
    return cast(Mapping[str, object], value)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted operator field: {key}")
    return result


def _integer(value: Mapping[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise ValueError(f"invalid persisted operator field: {key}")
    return result


def _positive_integer(value: Mapping[str, object], key: str) -> int:
    result = _integer(value, key)
    if result <= 0:
        raise ValueError(f"invalid persisted operator field: {key}")
    return result


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    return datetime.fromisoformat(_string(value, key))


def _optional_datetime(value: Mapping[str, object], key: str) -> datetime | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted operator field: {key}")
    return datetime.fromisoformat(result)


def _string_sequence(value: Mapping[str, object], key: str) -> tuple[str, ...]:
    result = value.get(key)
    if not isinstance(result, Sequence) or isinstance(result, (str, bytes, bytearray)):
        raise ValueError(f"invalid persisted operator field: {key}")
    if not all(isinstance(item, str) for item in result):
        raise ValueError(f"invalid persisted operator field: {key}")
    return tuple(cast(Sequence[str], result))


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
