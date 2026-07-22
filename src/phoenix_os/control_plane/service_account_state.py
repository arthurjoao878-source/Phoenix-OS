"""Durable service-account encoding and State Store persistence."""

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
    ControlPlaneApiTokenAlreadyExistsError,
    ControlPlaneApiTokenCapacityError,
    ControlPlaneApiTokenConflictError,
    ControlPlaneApiTokenNotFoundError,
    ControlPlaneServiceAccountAlreadyExistsError,
    ControlPlaneServiceAccountCapacityError,
    ControlPlaneServiceAccountConflictError,
    ControlPlaneServiceAccountCorruptionError,
    ControlPlaneServiceAccountNotFoundError,
    ControlPlaneServiceAccountPersistenceError,
    ControlPlaneServiceAccountRepositoryClosedError,
    ControlPlaneServiceAccountSchemaError,
)
from phoenix_os.control_plane.service_account_contracts import (
    DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST,
    MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT,
    MAX_CONTROL_PLANE_SERVICE_ACCOUNT_CAPACITY,
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenPage,
    ControlPlaneApiTokenRestriction,
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

_API_TOKEN_RECORD_KIND = "phoenix.control-plane.service-account.api-token.record"
_API_TOKEN_DIGEST_INDEX_KIND = "phoenix.control-plane.service-account.api-token.digest-index"
_API_TOKEN_RECORD_PREFIX = "token_record_"
_API_TOKEN_DIGEST_PREFIX = "token_digest_"
_API_TOKEN_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "service_account_id",
        "label",
        "token_digest",
        "scopes",
        "resources",
        "restriction",
        "issued_at",
        "expires_at",
        "updated_at",
        "status",
        "revoked_at",
        "rotated_from",
        "token_version",
        "revision",
    }
)
_API_TOKEN_RECORD_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "record",
        "record_digest",
    }
)
_API_TOKEN_RESTRICTION_FIELDS = frozenset(
    {
        "allowed_client_networks",
        "mutual_tls_certificate_sha256",
    }
)
_API_TOKEN_DIGEST_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "token_id",
        "service_account_id",
        "token_digest",
        "token_version",
        "revision",
        "record_digest",
    }
)


def canonical_control_plane_service_account_record_bytes(
    record: ControlPlaneServiceAccountRecord,
) -> bytes:
    """Return deterministic schema-v1 JSON bytes for one account."""

    return _canonical_json_bytes(_service_account_document(record))


def control_plane_service_account_record_digest(
    record: ControlPlaneServiceAccountRecord,
) -> str:
    """Return the integrity digest for one service account."""

    return hashlib.sha256(canonical_control_plane_service_account_record_bytes(record)).hexdigest()


def canonical_control_plane_api_token_record_bytes(
    metadata: ControlPlaneApiTokenMetadata,
) -> bytes:
    """Return deterministic credential-safe bytes for one token."""

    return _canonical_json_bytes(_api_token_document(metadata))


def control_plane_api_token_record_digest(
    metadata: ControlPlaneApiTokenMetadata,
) -> str:
    """Return the integrity digest for API-token metadata."""

    return hashlib.sha256(canonical_control_plane_api_token_record_bytes(metadata)).hexdigest()


def _service_account_document(
    record: ControlPlaneServiceAccountRecord,
) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "id": str(record.id),
        "name": record.name,
        "display_name": record.display_name,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "status": record.status.value,
        "disabled_at": (None if record.disabled_at is None else record.disabled_at.isoformat()),
        "revoked_at": (None if record.revoked_at is None else record.revoked_at.isoformat()),
        "revision": record.revision,
    }


def _api_token_document(
    metadata: ControlPlaneApiTokenMetadata,
) -> dict[str, object]:
    return {
        "schema_version": metadata.schema_version,
        "id": str(metadata.id),
        "service_account_id": str(metadata.service_account_id),
        "label": metadata.label,
        "token_digest": metadata.token_digest,
        "scopes": sorted(metadata.scopes),
        "resources": sorted(metadata.resources),
        "restriction": _restriction_document(metadata.restriction),
        "issued_at": metadata.issued_at.isoformat(),
        "expires_at": metadata.expires_at.isoformat(),
        "updated_at": metadata.updated_at.isoformat(),
        "status": metadata.status.value,
        "revoked_at": (None if metadata.revoked_at is None else metadata.revoked_at.isoformat()),
        "rotated_from": (None if metadata.rotated_from is None else str(metadata.rotated_from)),
        "token_version": metadata.token_version,
        "revision": metadata.revision,
    }


def _restriction_document(
    restriction: ControlPlaneApiTokenRestriction,
) -> dict[str, object]:
    return {
        "allowed_client_networks": list(restriction.allowed_client_networks),
        "mutual_tls_certificate_sha256": (restriction.mutual_tls_certificate_sha256),
    }


def _canonical_json_bytes(
    value: Mapping[str, object],
) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


_SCHEMA_VERSION = 1
_ACCOUNT_RECORD_KIND = "phoenix.control-plane.service-account.record"
_ACCOUNT_NAME_INDEX_KIND = "phoenix.control-plane.service-account.name-index"
_ACCOUNT_RECORD_PREFIX = "record_"
_ACCOUNT_NAME_PREFIX = "name_"
_ACCOUNT_NAME_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "service_account_id",
        "name",
        "revision",
        "record_digest",
    }
)
_ACCOUNT_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "name",
        "display_name",
        "created_at",
        "updated_at",
        "status",
        "disabled_at",
        "revoked_at",
        "revision",
    }
)
_ACCOUNT_RECORD_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "record",
        "record_digest",
    }
)


def _account_record_envelope(
    record: ControlPlaneServiceAccountRecord,
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _ACCOUNT_RECORD_KIND,
        "record": _service_account_document(record),
        "record_digest": (control_plane_service_account_record_digest(record)),
    }


def _decode_account_record_state(
    stored: (StateRecord[dict[str, object]] | StateRecord[object]),
) -> ControlPlaneServiceAccountRecord:
    value = _mapping(
        stored.value,
        label="record envelope",
    )

    _require_exact_fields(
        value,
        _ACCOUNT_RECORD_ENVELOPE_FIELDS,
        label="record envelope",
    )
    _require_schema(value)

    if _string(value, "kind") != _ACCOUNT_RECORD_KIND:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account record kind is invalid"
        )

    document = _mapping(
        value.get("record"),
        label="record",
    )

    _require_exact_fields(
        document,
        _ACCOUNT_RECORD_FIELDS,
        label="record",
    )

    expected_digest = _normalize_sha256(_string(value, "record_digest"))
    actual_digest = hashlib.sha256(_canonical_json_bytes(document)).hexdigest()

    if not hmac.compare_digest(
        expected_digest,
        actual_digest,
    ):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account record digest does not match"
        )

    try:
        schema_version = _integer(
            document,
            "schema_version",
        )

        if schema_version != _SCHEMA_VERSION:
            raise ControlPlaneServiceAccountSchemaError(
                "persisted service-account record schema is unsupported"
            )

        return ControlPlaneServiceAccountRecord(
            id=UUID(_string(document, "id")),
            name=_string(document, "name"),
            display_name=_string(
                document,
                "display_name",
            ),
            created_at=_datetime(
                document,
                "created_at",
            ),
            updated_at=_datetime(
                document,
                "updated_at",
            ),
            status=ControlPlaneServiceAccountStatus(_string(document, "status")),
            disabled_at=_optional_datetime(
                document,
                "disabled_at",
            ),
            revoked_at=_optional_datetime(
                document,
                "revoked_at",
            ),
            revision=_integer(
                document,
                "revision",
            ),
            schema_version=schema_version,
        )

    except ControlPlaneServiceAccountSchemaError:
        raise

    except (TypeError, ValueError) as exception:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account record is invalid"
        ) from exception


def _require_schema(
    value: Mapping[str, object],
) -> None:
    try:
        schema_version = _integer(
            value,
            "schema_version",
        )
    except ValueError as exception:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account schema field is invalid"
        ) from exception

    if schema_version != _SCHEMA_VERSION:
        raise ControlPlaneServiceAccountSchemaError(
            "persisted service-account schema is unsupported"
        )


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise ControlPlaneServiceAccountCorruptionError(
            f"persisted service-account {label} fields are invalid"
        )


def _mapping(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ControlPlaneServiceAccountCorruptionError(
            f"persisted service-account {label} is invalid"
        )

    return cast(Mapping[str, object], value)


def _string(
    value: Mapping[str, object],
    key: str,
) -> str:
    result = value.get(key)

    if not isinstance(result, str):
        raise ValueError(f"invalid persisted service-account field: {key}")

    return result


def _integer(
    value: Mapping[str, object],
    key: str,
) -> int:
    result = value.get(key)

    if not isinstance(result, int) or isinstance(result, bool):
        raise ValueError(f"invalid persisted service-account field: {key}")

    return result


def _datetime(
    value: Mapping[str, object],
    key: str,
) -> datetime:
    return datetime.fromisoformat(_string(value, key))


def _optional_datetime(
    value: Mapping[str, object],
    key: str,
) -> datetime | None:
    result = value.get(key)

    if result is None:
        return None

    if not isinstance(result, str):
        raise ValueError(f"invalid persisted service-account field: {key}")

    return datetime.fromisoformat(result)


def _normalize_sha256(value: str) -> str:
    normalized = value.strip().lower()

    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("invalid persisted SHA-256 digest")

    return normalized


class StateControlPlaneServiceAccountRepository:
    """Persist service accounts through atomic State Store writes."""

    def __init__(
        self,
        store: StateStore,
        *,
        account_capacity: int = 256,
        max_tokens_per_account: int = 8,
        namespace: str = "control-plane-service-accounts",
        context: StateOperationContext | None = None,
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

        probe = StateKey(
            namespace,
            f"{_ACCOUNT_RECORD_PREFIX}{'0' * 32}",
            dict,
        )

        self._store = store
        self._account_capacity = account_capacity
        self._max_tokens_per_account = max_tokens_per_account
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": ("phoenix.control-plane.service-account-repository"),
                "principal_type": PrincipalType.SYSTEM.value,
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add_account(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> None:
        self._ensure_open()

        record_key = self._account_record_key(record.id)
        name_key = self._account_name_key(record.name)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_RECORD_PREFIX,
                )
                stored_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_NAME_PREFIX,
                )

                _validate_persisted_account_collection(
                    stored_records,
                    stored_indexes,
                )

                if len(stored_records) >= self._account_capacity:
                    raise (
                        ControlPlaneServiceAccountCapacityError(
                            "service-account repository capacity has been exhausted"
                        )
                    )

                if await transaction.get(record_key) is not None:
                    raise (
                        ControlPlaneServiceAccountAlreadyExistsError(
                            "service-account id already exists"
                        )
                    )

                if await transaction.get(name_key) is not None:
                    raise (
                        ControlPlaneServiceAccountAlreadyExistsError(
                            "service-account name already exists"
                        )
                    )

                await transaction.put(
                    record_key,
                    _account_record_envelope(record),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    name_key,
                    _account_name_index_document(record),
                    expected_version=ABSENT_VERSION,
                )

        except (
            ControlPlaneServiceAccountAlreadyExistsError,
            ControlPlaneServiceAccountCapacityError,
            ControlPlaneServiceAccountCorruptionError,
        ):
            raise

        except StateConflictError as exception:
            raise (
                ControlPlaneServiceAccountAlreadyExistsError(
                    "service-account identity already exists"
                )
            ) from exception

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "service-account persistence operation failed"
            ) from exception

    async def get_account(
        self,
        service_account_id: UUID,
    ) -> ControlPlaneServiceAccountRecord | None:
        self._ensure_open()

        try:
            stored = await self._store.get(
                self._account_record_key(service_account_id),
                context=self._context,
            )

            if stored is None:
                return None

            record = _decode_account_record_state(stored)

            if record.id != service_account_id:
                raise ControlPlaneServiceAccountCorruptionError(
                    "persisted service-account identity does not match its state key"
                )

            return await self._read_and_verify_name_index(record)

        except ControlPlaneServiceAccountCorruptionError:
            raise

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "service-account persistence operation failed"
            ) from exception

    async def get_account_by_name(
        self,
        name: str,
    ) -> ControlPlaneServiceAccountRecord | None:
        self._ensure_open()
        normalized = _normalize_name(name)

        try:
            stored_index = await self._store.get(
                self._account_name_key(normalized),
                context=self._context,
            )

            if stored_index is None:
                return None

            index = _decode_account_name_index_state(stored_index)

            if index.name != normalized:
                raise ControlPlaneServiceAccountCorruptionError(
                    "persisted service-account name index does not match its state key"
                )

            stored_record = await self._store.get(
                self._account_record_key(index.service_account_id),
                context=self._context,
            )

            if stored_record is None:
                raise ControlPlaneServiceAccountCorruptionError(
                    "persisted service-account name index references a missing record"
                )

            record = _decode_account_record_state(stored_record)
            _verify_account_name_index(
                index,
                record,
            )

            return await self._read_and_verify_name_index(record)

        except ControlPlaneServiceAccountCorruptionError:
            raise

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "service-account persistence operation failed"
            ) from exception

    async def list_accounts(
        self,
        request: ControlPlaneServiceAccountPageRequest = (
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST
        ),
    ) -> ControlPlaneServiceAccountPage:
        records = await self._load_accounts()

        ordered = tuple(
            sorted(
                records,
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
        self._ensure_open()

        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        record_key = self._account_record_key(record.id)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_RECORD_PREFIX,
                )
                stored_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_NAME_PREFIX,
                )

                _validate_persisted_account_collection(
                    stored_records,
                    stored_indexes,
                )

                stored_current = await transaction.get(record_key)

                if stored_current is None:
                    raise ControlPlaneServiceAccountNotFoundError("service account was not found")

                current = _decode_account_record_state(stored_current)

                _validate_account_replacement(
                    current,
                    record,
                    expected_revision=expected_revision,
                )

                old_name_key = self._account_name_key(current.name)
                stored_old_name = await transaction.get(old_name_key)

                if stored_old_name is None:
                    raise ControlPlaneServiceAccountCorruptionError(
                        "persisted service-account record has an incomplete name index"
                    )

                _verify_account_name_index(
                    _decode_account_name_index_state(stored_old_name),
                    current,
                )

                new_name_key = self._account_name_key(record.name)
                stored_new_name = await transaction.get(new_name_key)

                if new_name_key != old_name_key and stored_new_name is not None:
                    raise (
                        ControlPlaneServiceAccountAlreadyExistsError(
                            "service-account name already exists"
                        )
                    )

                await transaction.put(
                    record_key,
                    _account_record_envelope(record),
                    expected_version=stored_current.version,
                )

                if new_name_key == old_name_key:
                    await transaction.put(
                        old_name_key,
                        _account_name_index_document(record),
                        expected_version=(stored_old_name.version),
                    )
                else:
                    await transaction.delete(
                        old_name_key,
                        expected_version=(stored_old_name.version),
                    )
                    await transaction.put(
                        new_name_key,
                        _account_name_index_document(record),
                        expected_version=ABSENT_VERSION,
                    )

                return record

        except (
            ControlPlaneServiceAccountAlreadyExistsError,
            ControlPlaneServiceAccountConflictError,
            ControlPlaneServiceAccountCorruptionError,
            ControlPlaneServiceAccountNotFoundError,
        ):
            raise

        except StateConflictError as exception:
            raise ControlPlaneServiceAccountConflictError(
                "service-account state changed concurrently"
            ) from exception

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "service-account persistence operation failed"
            ) from exception

    async def add_token(
        self,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> None:
        self._ensure_open()

        record_key = self._api_token_record_key(metadata.id)
        digest_key = self._api_token_digest_key(metadata.token_digest)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                account_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_RECORD_PREFIX,
                )
                account_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_NAME_PREFIX,
                )
                accounts = _validate_persisted_account_collection(
                    account_records,
                    account_indexes,
                )
                account_ids = frozenset(account.id for account in accounts)

                if metadata.service_account_id not in account_ids:
                    raise (ControlPlaneServiceAccountNotFoundError("service account was not found"))

                token_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_API_TOKEN_RECORD_PREFIX,
                )
                token_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_API_TOKEN_DIGEST_PREFIX,
                )
                tokens = _validate_persisted_token_collection(
                    token_records,
                    token_indexes,
                    account_ids=account_ids,
                )

                account_token_count = sum(
                    token.service_account_id == metadata.service_account_id for token in tokens
                )

                if account_token_count >= self._max_tokens_per_account:
                    raise ControlPlaneApiTokenCapacityError(
                        "service account API-token capacity has been exhausted"
                    )

                if await transaction.get(record_key) is not None:
                    raise (ControlPlaneApiTokenAlreadyExistsError("API-token id already exists"))

                if await transaction.get(digest_key) is not None:
                    raise (
                        ControlPlaneApiTokenAlreadyExistsError("API-token digest already exists")
                    )

                await transaction.put(
                    record_key,
                    _api_token_record_envelope(metadata),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    digest_key,
                    _api_token_digest_index_document(metadata),
                    expected_version=ABSENT_VERSION,
                )

        except (
            ControlPlaneApiTokenAlreadyExistsError,
            ControlPlaneApiTokenCapacityError,
            ControlPlaneServiceAccountCorruptionError,
            ControlPlaneServiceAccountNotFoundError,
        ):
            raise

        except StateConflictError as exception:
            raise ControlPlaneApiTokenAlreadyExistsError(
                "API-token identity already exists"
            ) from exception

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "API-token persistence operation failed"
            ) from exception

    async def get_token(
        self,
        token_id: UUID,
    ) -> ControlPlaneApiTokenMetadata | None:
        self._ensure_open()

        try:
            stored_record = await self._store.get(
                self._api_token_record_key(token_id),
                context=self._context,
            )

            if stored_record is None:
                return None

            metadata = _decode_api_token_record_state(stored_record)

            if metadata.id != token_id:
                raise ControlPlaneServiceAccountCorruptionError(
                    "persisted API-token identity does not match its state key"
                )

            await self._read_and_verify_token_parent(metadata)

            return await self._read_and_verify_token_index(metadata)

        except ControlPlaneServiceAccountCorruptionError:
            raise

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "API-token persistence operation failed"
            ) from exception

    async def get_token_by_digest(
        self,
        token_digest: str,
    ) -> ControlPlaneApiTokenMetadata | None:
        self._ensure_open()
        normalized = _normalize_digest(
            token_digest,
            label="API token digest",
        )

        try:
            stored_index = await self._store.get(
                self._api_token_digest_key(normalized),
                context=self._context,
            )

            if stored_index is None:
                return None

            index = _decode_api_token_digest_index_state(stored_index)

            if not hmac.compare_digest(
                index.token_digest,
                normalized,
            ):
                raise ControlPlaneServiceAccountCorruptionError(
                    "persisted API-token digest index does not match its state key"
                )

            if not _api_token_digest_key_matches(
                stored_index.key.name,
                normalized,
            ):
                raise ControlPlaneServiceAccountCorruptionError(
                    "persisted API-token digest index does not match its state key"
                )

            stored_record = await self._store.get(
                self._api_token_record_key(index.token_id),
                context=self._context,
            )

            if stored_record is None:
                raise ControlPlaneServiceAccountCorruptionError(
                    "persisted API-token digest index references a missing record"
                )

            metadata = _decode_api_token_record_state(stored_record)

            _verify_api_token_digest_index(
                index,
                metadata,
            )
            await self._read_and_verify_token_parent(metadata)

            return await self._read_and_verify_token_index(metadata)

        except ControlPlaneServiceAccountCorruptionError:
            raise

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "API-token persistence operation failed"
            ) from exception

    async def list_tokens(
        self,
        service_account_id: UUID,
        request: ControlPlaneServiceAccountPageRequest = (
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST
        ),
    ) -> ControlPlaneApiTokenPage:
        accounts = await self._load_accounts()
        account_ids = frozenset(account.id for account in accounts)

        if service_account_id not in account_ids:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        tokens = await self._load_tokens(account_ids=account_ids)
        ordered = tuple(
            sorted(
                (token for token in tokens if (token.service_account_id == service_account_id)),
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
        self._ensure_open()

        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        record_key = self._api_token_record_key(metadata.id)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                account_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_RECORD_PREFIX,
                )
                account_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_NAME_PREFIX,
                )
                accounts = _validate_persisted_account_collection(
                    account_records,
                    account_indexes,
                )
                account_ids = frozenset(account.id for account in accounts)

                token_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_API_TOKEN_RECORD_PREFIX,
                )
                token_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_API_TOKEN_DIGEST_PREFIX,
                )
                _validate_persisted_token_collection(
                    token_records,
                    token_indexes,
                    account_ids=account_ids,
                )

                stored_current = await transaction.get(record_key)

                if stored_current is None:
                    raise ControlPlaneApiTokenNotFoundError("API-token metadata was not found")

                current = _decode_api_token_record_state(stored_current)

                _validate_token_replacement(
                    current,
                    metadata,
                    expected_revision=expected_revision,
                )

                if metadata.service_account_id not in account_ids:
                    raise (ControlPlaneServiceAccountNotFoundError("service account was not found"))

                digest_key = self._api_token_digest_key(current.token_digest)
                stored_digest_index = await transaction.get(digest_key)

                if stored_digest_index is None:
                    raise ControlPlaneServiceAccountCorruptionError(
                        "persisted API-token record has an incomplete digest index"
                    )

                _verify_api_token_digest_index(
                    _decode_api_token_digest_index_state(stored_digest_index),
                    current,
                )

                await transaction.put(
                    record_key,
                    _api_token_record_envelope(metadata),
                    expected_version=stored_current.version,
                )
                await transaction.put(
                    digest_key,
                    _api_token_digest_index_document(metadata),
                    expected_version=(stored_digest_index.version),
                )

                return metadata

        except (
            ControlPlaneApiTokenConflictError,
            ControlPlaneApiTokenNotFoundError,
            ControlPlaneServiceAccountCorruptionError,
            ControlPlaneServiceAccountNotFoundError,
        ):
            raise

        except StateConflictError as exception:
            raise ControlPlaneApiTokenConflictError(
                "API-token state changed concurrently"
            ) from exception

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "API-token persistence operation failed"
            ) from exception

    async def delete_terminal_token(
        self,
        token_id: UUID,
        *,
        expected_revision: int,
    ) -> None:
        """Atomically delete one standalone terminal token."""

        self._ensure_open()

        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        record_key = self._api_token_record_key(token_id)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                account_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_RECORD_PREFIX,
                )
                account_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_NAME_PREFIX,
                )
                accounts = _validate_persisted_account_collection(
                    account_records,
                    account_indexes,
                )
                account_ids = frozenset(account.id for account in accounts)

                token_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_API_TOKEN_RECORD_PREFIX,
                )
                token_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_API_TOKEN_DIGEST_PREFIX,
                )
                tokens = _validate_persisted_token_collection(
                    token_records,
                    token_indexes,
                    account_ids=account_ids,
                )

                stored_current = await transaction.get(record_key)

                if stored_current is None:
                    raise ControlPlaneApiTokenNotFoundError("API-token metadata was not found")

                current = _decode_api_token_record_state(stored_current)

                if current.revision != expected_revision:
                    raise ControlPlaneApiTokenConflictError("API-token revision conflict")

                if current.status is ControlPlaneApiTokenStatus.ACTIVE:
                    raise ControlPlaneApiTokenConflictError("active API token cannot be deleted")

                referenced = any(metadata.rotated_from == current.id for metadata in tokens)

                if current.rotated_from is not None or referenced:
                    raise ControlPlaneApiTokenConflictError(
                        "lineage-bound API token cannot be deleted"
                    )

                digest_key = self._api_token_digest_key(current.token_digest)
                stored_digest = await transaction.get(digest_key)

                if stored_digest is None:
                    raise (
                        ControlPlaneServiceAccountCorruptionError(
                            "persisted API-token record has an incomplete digest index"
                        )
                    )

                _verify_api_token_digest_index(
                    _decode_api_token_digest_index_state(stored_digest),
                    current,
                )

                await transaction.delete(
                    record_key,
                    expected_version=stored_current.version,
                )
                await transaction.delete(
                    digest_key,
                    expected_version=stored_digest.version,
                )

        except (
            ControlPlaneApiTokenConflictError,
            ControlPlaneApiTokenNotFoundError,
            ControlPlaneServiceAccountCorruptionError,
        ):
            raise

        except StateConflictError as exception:
            raise ControlPlaneApiTokenConflictError(
                "API-token state changed concurrently"
            ) from exception

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "API-token persistence operation failed"
            ) from exception

    async def rotate_token(
        self,
        predecessor: ControlPlaneApiTokenMetadata,
        successor: ControlPlaneApiTokenMetadata,
        *,
        expected_revision: int,
    ) -> ControlPlaneApiTokenRotation:
        self._ensure_open()

        if expected_revision <= 0:
            raise ValueError("expected_revision must be positive")

        rotation = ControlPlaneApiTokenRotation(
            predecessor=predecessor,
            successor=successor,
        )

        predecessor_key = self._api_token_record_key(predecessor.id)
        predecessor_digest_key = self._api_token_digest_key(predecessor.token_digest)
        successor_key = self._api_token_record_key(successor.id)
        successor_digest_key = self._api_token_digest_key(successor.token_digest)

        try:
            async with self._store.transaction(context=self._context) as transaction:
                account_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_RECORD_PREFIX,
                )
                account_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_ACCOUNT_NAME_PREFIX,
                )

                accounts = _validate_persisted_account_collection(
                    account_records,
                    account_indexes,
                )
                account_ids = frozenset(account.id for account in accounts)

                token_records = await transaction.list(
                    namespace=self._namespace,
                    prefix=_API_TOKEN_RECORD_PREFIX,
                )
                token_indexes = await transaction.list(
                    namespace=self._namespace,
                    prefix=_API_TOKEN_DIGEST_PREFIX,
                )

                tokens = _validate_persisted_token_collection(
                    token_records,
                    token_indexes,
                    account_ids=account_ids,
                )

                current = next(
                    (token for token in tokens if token.id == predecessor.id),
                    None,
                )

                if current is None:
                    raise (ControlPlaneApiTokenNotFoundError("API-token metadata was not found"))

                _validate_token_replacement(
                    current,
                    predecessor,
                    expected_revision=(expected_revision),
                )

                rotation_time = successor.issued_at

                if (
                    current.status is not ControlPlaneApiTokenStatus.ACTIVE
                    or not current.authenticatable_at(rotation_time)
                ):
                    raise (
                        ControlPlaneApiTokenConflictError(
                            "only an active unexpired API token can be rotated"
                        )
                    )

                if any(token.rotated_from == current.id for token in tokens):
                    raise (
                        ControlPlaneApiTokenConflictError(
                            "API token already has a rotation successor"
                        )
                    )

                account_token_count = sum(
                    token.service_account_id == current.service_account_id for token in tokens
                )

                if account_token_count >= self._max_tokens_per_account:
                    raise ControlPlaneApiTokenCapacityError(
                        "service account API-token capacity has been exhausted"
                    )

                stored_predecessor = await transaction.get(predecessor_key)
                stored_predecessor_index = await transaction.get(predecessor_digest_key)

                if stored_predecessor is None or stored_predecessor_index is None:
                    raise (
                        ControlPlaneServiceAccountCorruptionError(
                            "persisted API-token predecessor is incomplete"
                        )
                    )

                _verify_api_token_digest_index(
                    _decode_api_token_digest_index_state(stored_predecessor_index),
                    current,
                )

                if await transaction.get(successor_key) is not None:
                    raise (
                        ControlPlaneApiTokenAlreadyExistsError(
                            "API-token successor id already exists"
                        )
                    )

                if await transaction.get(successor_digest_key) is not None:
                    raise (
                        ControlPlaneApiTokenAlreadyExistsError(
                            "API-token successor digest already exists"
                        )
                    )

                await transaction.put(
                    predecessor_key,
                    _api_token_record_envelope(predecessor),
                    expected_version=(stored_predecessor.version),
                )
                await transaction.put(
                    predecessor_digest_key,
                    _api_token_digest_index_document(predecessor),
                    expected_version=(stored_predecessor_index.version),
                )
                await transaction.put(
                    successor_key,
                    _api_token_record_envelope(successor),
                    expected_version=ABSENT_VERSION,
                )
                await transaction.put(
                    successor_digest_key,
                    _api_token_digest_index_document(successor),
                    expected_version=ABSENT_VERSION,
                )

                return rotation

        except (
            ControlPlaneApiTokenAlreadyExistsError,
            ControlPlaneApiTokenCapacityError,
            ControlPlaneApiTokenConflictError,
            ControlPlaneApiTokenNotFoundError,
            ControlPlaneServiceAccountCorruptionError,
            ControlPlaneServiceAccountNotFoundError,
        ):
            raise

        except StateConflictError as exception:
            raise ControlPlaneApiTokenConflictError(
                "API-token rotation changed concurrently"
            ) from exception

        except PhoenixStateError as exception:
            raise (
                ControlPlaneServiceAccountPersistenceError("API-token rotation persistence failed")
            ) from exception

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountRegistrySnapshot:
        accounts = await self._load_accounts(require_open=False)
        account_ids = frozenset(account.id for account in accounts)
        tokens = await self._load_tokens(
            account_ids=account_ids,
            require_open=False,
        )

        account_statuses = Counter(account.status for account in accounts)
        token_statuses = Counter(token.status for token in tokens)

        return ControlPlaneServiceAccountRegistrySnapshot(
            closed=self._closed,
            accounts=len(accounts),
            active_accounts=account_statuses[ControlPlaneServiceAccountStatus.ACTIVE],
            disabled_accounts=account_statuses[ControlPlaneServiceAccountStatus.DISABLED],
            revoked_accounts=account_statuses[ControlPlaneServiceAccountStatus.REVOKED],
            tokens=len(tokens),
            active_tokens=token_statuses[ControlPlaneApiTokenStatus.ACTIVE],
            revoked_tokens=token_statuses[ControlPlaneApiTokenStatus.REVOKED],
            expired_tokens=token_statuses[ControlPlaneApiTokenStatus.EXPIRED],
            account_capacity=self._account_capacity,
            max_tokens_per_account=(self._max_tokens_per_account),
        )

    async def close(self) -> None:
        # Runtime owns the borrowed State Store lifecycle.
        self._closed = True

    async def _read_and_verify_name_index(
        self,
        record: ControlPlaneServiceAccountRecord,
    ) -> ControlPlaneServiceAccountRecord:
        stored_index = await self._store.get(
            self._account_name_key(record.name),
            context=self._context,
        )

        if stored_index is None:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted service-account record has an incomplete name index"
            )

        if stored_index.key.name != (f"{_ACCOUNT_NAME_PREFIX}{record.name}"):
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted service-account name index does not match its state key"
            )

        _verify_account_name_index(
            _decode_account_name_index_state(stored_index),
            record,
        )

        return record

    async def _load_accounts(
        self,
        *,
        require_open: bool = True,
    ) -> tuple[
        ControlPlaneServiceAccountRecord,
        ...,
    ]:
        if require_open:
            self._ensure_open()

        try:
            stored_records = await self._store.list(
                namespace=self._namespace,
                prefix=_ACCOUNT_RECORD_PREFIX,
                context=self._context,
            )
            stored_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_ACCOUNT_NAME_PREFIX,
                context=self._context,
            )

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "service-account persistence operation failed"
            ) from exception

        records = _validate_persisted_account_collection(
            stored_records,
            stored_indexes,
        )

        if len(records) > self._account_capacity:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted service-account entries exceed configured repository capacity"
            )

        return records

    def _account_record_key(
        self,
        service_account_id: UUID,
    ) -> StateKey[dict[str, object]]:
        return StateKey(
            self._namespace,
            (f"{_ACCOUNT_RECORD_PREFIX}{service_account_id.hex}"),
            dict,
        )

    def _account_name_key(
        self,
        name: str,
    ) -> StateKey[dict[str, object]]:
        normalized = _normalize_name(name)

        return StateKey(
            self._namespace,
            f"{_ACCOUNT_NAME_PREFIX}{normalized}",
            dict,
        )

    async def _read_and_verify_token_index(
        self,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> ControlPlaneApiTokenMetadata:
        stored_index = await self._store.get(
            self._api_token_digest_key(metadata.token_digest),
            context=self._context,
        )

        if stored_index is None:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API-token record has an incomplete digest index"
            )

        if not _api_token_digest_key_matches(
            stored_index.key.name,
            metadata.token_digest,
        ):
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API-token digest index does not match its state key"
            )

        _verify_api_token_digest_index(
            _decode_api_token_digest_index_state(stored_index),
            metadata,
        )

        return metadata

    async def _read_and_verify_token_parent(
        self,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> ControlPlaneServiceAccountRecord:
        stored_account = await self._store.get(
            self._account_record_key(metadata.service_account_id),
            context=self._context,
        )

        if stored_account is None:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API token references a missing service account"
            )

        account = _decode_account_record_state(stored_account)

        if account.id != metadata.service_account_id:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API-token parent identity does not match its state key"
            )

        return await self._read_and_verify_name_index(account)

    async def _load_tokens(
        self,
        *,
        account_ids: frozenset[UUID],
        require_open: bool = True,
    ) -> tuple[
        ControlPlaneApiTokenMetadata,
        ...,
    ]:
        if require_open:
            self._ensure_open()

        try:
            stored_records = await self._store.list(
                namespace=self._namespace,
                prefix=_API_TOKEN_RECORD_PREFIX,
                context=self._context,
            )
            stored_indexes = await self._store.list(
                namespace=self._namespace,
                prefix=_API_TOKEN_DIGEST_PREFIX,
                context=self._context,
            )

        except PhoenixStateError as exception:
            raise ControlPlaneServiceAccountPersistenceError(
                "API-token persistence operation failed"
            ) from exception

        tokens = _validate_persisted_token_collection(
            stored_records,
            stored_indexes,
            account_ids=account_ids,
        )
        counts = Counter(token.service_account_id for token in tokens)

        if any(count > self._max_tokens_per_account for count in counts.values()):
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API-token entries exceed configured per-account capacity"
            )

        return tokens

    def _api_token_record_key(
        self,
        token_id: UUID,
    ) -> StateKey[dict[str, object]]:
        return StateKey(
            self._namespace,
            f"{_API_TOKEN_RECORD_PREFIX}{token_id.hex}",
            dict,
        )

    def _api_token_digest_key(
        self,
        token_digest: str,
    ) -> StateKey[dict[str, object]]:
        normalized = _normalize_digest(
            token_digest,
            label="API token digest",
        )

        return StateKey(
            self._namespace,
            f"{_API_TOKEN_DIGEST_PREFIX}{normalized}",
            dict,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise (
                ControlPlaneServiceAccountRepositoryClosedError(
                    "service-account repository is closed"
                )
            )


class _DecodedAccountNameIndex:
    __slots__ = (
        "kind",
        "name",
        "record_digest",
        "revision",
        "service_account_id",
    )

    def __init__(
        self,
        *,
        kind: str,
        service_account_id: UUID,
        name: str,
        revision: int,
        record_digest: str,
    ) -> None:
        self.kind = kind
        self.service_account_id = service_account_id
        self.name = name
        self.revision = revision
        self.record_digest = record_digest


def _account_name_index_document(
    record: ControlPlaneServiceAccountRecord,
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _ACCOUNT_NAME_INDEX_KIND,
        "service_account_id": str(record.id),
        "name": record.name,
        "revision": record.revision,
        "record_digest": (control_plane_service_account_record_digest(record)),
    }


def _decode_account_name_index_state(
    stored: (StateRecord[dict[str, object]] | StateRecord[object]),
) -> _DecodedAccountNameIndex:
    value = _mapping(
        stored.value,
        label="name index",
    )

    _require_exact_fields(
        value,
        _ACCOUNT_NAME_INDEX_FIELDS,
        label="name index",
    )
    _require_schema(value)

    kind = _string(value, "kind")

    if kind != _ACCOUNT_NAME_INDEX_KIND:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account name index kind is invalid"
        )

    try:
        return _DecodedAccountNameIndex(
            kind=kind,
            service_account_id=UUID(
                _string(
                    value,
                    "service_account_id",
                )
            ),
            name=_normalize_name(_string(value, "name")),
            revision=_positive_integer(
                value,
                "revision",
            ),
            record_digest=_normalize_sha256(
                _string(
                    value,
                    "record_digest",
                )
            ),
        )

    except (TypeError, ValueError) as exception:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account name index is invalid"
        ) from exception


def _verify_account_name_index(
    index: _DecodedAccountNameIndex,
    record: ControlPlaneServiceAccountRecord,
) -> None:
    digest = control_plane_service_account_record_digest(record)

    if (
        index.service_account_id != record.id
        or index.name != record.name
        or index.revision != record.revision
        or not hmac.compare_digest(
            index.record_digest,
            digest,
        )
    ):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account name index and record do not match"
        )


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


def _validate_persisted_account_collection(
    stored_records: tuple[
        StateRecord[object],
        ...,
    ],
    stored_indexes: tuple[
        StateRecord[object],
        ...,
    ],
) -> tuple[
    ControlPlaneServiceAccountRecord,
    ...,
]:
    records = tuple(_decode_account_record_state(item) for item in stored_records)
    indexes = tuple(_decode_account_name_index_state(item) for item in stored_indexes)

    # Validate physical record keys before identity uniqueness.
    for stored_record, record in zip(
        stored_records,
        records,
        strict=True,
    ):
        expected_key = f"{_ACCOUNT_RECORD_PREFIX}{record.id.hex}"

        if stored_record.key.name != expected_key:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted service-account identity does not match its state key"
            )

    ids = tuple(record.id for record in records)
    names = tuple(record.name for record in records)

    if len(ids) != len(set(ids)) or len(names) != len(set(names)):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account repository contains duplicate identities"
        )

    if len(records) != len(indexes):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account records and name indexes are incomplete"
        )

    index_names = tuple(index.name for index in indexes)
    index_ids = tuple(index.service_account_id for index in indexes)

    if len(index_names) != len(set(index_names)) or len(index_ids) != len(set(index_ids)):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted service-account repository contains duplicate name indexes"
        )

    index_by_name = {index.name: index for index in indexes}

    for stored_record, record in zip(
        stored_records,
        records,
        strict=True,
    ):
        expected_key = f"{_ACCOUNT_RECORD_PREFIX}{record.id.hex}"

        if stored_record.key.name != expected_key:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted service-account identity does not match its state key"
            )

        index = index_by_name.get(record.name)

        if index is None:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted service-account record has an incomplete name index"
            )

        _verify_account_name_index(
            index,
            record,
        )

    for stored_index, index in zip(
        stored_indexes,
        indexes,
        strict=True,
    ):
        expected_key = f"{_ACCOUNT_NAME_PREFIX}{index.name}"

        if stored_index.key.name != expected_key:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted service-account name index does not match its state key"
            )

    return records


def _positive_integer(
    value: Mapping[str, object],
    key: str,
) -> int:
    result = _integer(value, key)

    if result <= 0:
        raise ValueError(f"invalid persisted service-account field: {key}")

    return result


class _DecodedApiTokenDigestIndex:
    __slots__ = (
        "kind",
        "record_digest",
        "revision",
        "service_account_id",
        "token_digest",
        "token_id",
        "token_version",
    )

    def __init__(
        self,
        *,
        kind: str,
        token_id: UUID,
        service_account_id: UUID,
        token_digest: str,
        token_version: int,
        revision: int,
        record_digest: str,
    ) -> None:
        self.kind = kind
        self.token_id = token_id
        self.service_account_id = service_account_id
        self.token_digest = token_digest
        self.token_version = token_version
        self.revision = revision
        self.record_digest = record_digest


def _api_token_record_envelope(
    metadata: ControlPlaneApiTokenMetadata,
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _API_TOKEN_RECORD_KIND,
        "record": _api_token_document(metadata),
        "record_digest": (control_plane_api_token_record_digest(metadata)),
    }


def _api_token_digest_index_document(
    metadata: ControlPlaneApiTokenMetadata,
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _API_TOKEN_DIGEST_INDEX_KIND,
        "token_id": str(metadata.id),
        "service_account_id": str(metadata.service_account_id),
        "token_digest": metadata.token_digest,
        "token_version": metadata.token_version,
        "revision": metadata.revision,
        "record_digest": (control_plane_api_token_record_digest(metadata)),
    }


def _decode_api_token_record_state(
    stored: (StateRecord[dict[str, object]] | StateRecord[object]),
) -> ControlPlaneApiTokenMetadata:
    value = _mapping(
        stored.value,
        label="API-token record envelope",
    )

    _require_exact_fields(
        value,
        _API_TOKEN_RECORD_ENVELOPE_FIELDS,
        label="API-token record envelope",
    )
    _require_schema(value)

    if _string(value, "kind") != _API_TOKEN_RECORD_KIND:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token record kind is invalid"
        )

    document = _mapping(
        value.get("record"),
        label="API-token record",
    )

    _require_exact_fields(
        document,
        _API_TOKEN_RECORD_FIELDS,
        label="API-token record",
    )

    expected_digest = _normalize_sha256(_string(value, "record_digest"))
    actual_digest = hashlib.sha256(_canonical_json_bytes(document)).hexdigest()

    if not hmac.compare_digest(
        expected_digest,
        actual_digest,
    ):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token record digest does not match"
        )

    restriction_document = _mapping(
        document.get("restriction"),
        label="API-token restriction",
    )

    _require_exact_fields(
        restriction_document,
        _API_TOKEN_RESTRICTION_FIELDS,
        label="API-token restriction",
    )

    try:
        schema_version = _integer(
            document,
            "schema_version",
        )

        if schema_version != _SCHEMA_VERSION:
            raise ControlPlaneServiceAccountSchemaError(
                "persisted API-token record schema is unsupported"
            )

        scopes = _string_sequence(
            document,
            "scopes",
        )
        resources = _string_sequence(
            document,
            "resources",
        )
        networks = _string_sequence(
            restriction_document,
            "allowed_client_networks",
        )

        if scopes != tuple(sorted(set(scopes))):
            raise ValueError("persisted API-token scopes are not canonical")

        if resources != tuple(sorted(set(resources))):
            raise ValueError("persisted API-token resources are not canonical")

        if networks != tuple(sorted(set(networks))):
            raise ValueError("persisted API-token networks are not canonical")

        certificate_digest = _optional_string(
            restriction_document,
            "mutual_tls_certificate_sha256",
        )

        restriction = ControlPlaneApiTokenRestriction(
            allowed_client_networks=networks,
            mutual_tls_certificate_sha256=(certificate_digest),
        )

        if restriction.allowed_client_networks != networks:
            raise ValueError("persisted API-token networks are not canonical")

        if restriction.mutual_tls_certificate_sha256 != certificate_digest:
            raise ValueError("persisted API-token mTLS identity is not canonical")

        token_digest = _string(
            document,
            "token_digest",
        )
        normalized_token_digest = _normalize_sha256(token_digest)

        if token_digest != normalized_token_digest:
            raise ValueError("persisted API-token digest is not canonical")

        return ControlPlaneApiTokenMetadata(
            id=UUID(_string(document, "id")),
            service_account_id=UUID(
                _string(
                    document,
                    "service_account_id",
                )
            ),
            label=_string(document, "label"),
            token_digest=normalized_token_digest,
            scopes=frozenset(scopes),
            resources=frozenset(resources),
            restriction=restriction,
            issued_at=_datetime(
                document,
                "issued_at",
            ),
            expires_at=_datetime(
                document,
                "expires_at",
            ),
            updated_at=_datetime(
                document,
                "updated_at",
            ),
            status=ControlPlaneApiTokenStatus(_string(document, "status")),
            revoked_at=_optional_datetime(
                document,
                "revoked_at",
            ),
            rotated_from=_optional_uuid(
                document,
                "rotated_from",
            ),
            token_version=_positive_integer(
                document,
                "token_version",
            ),
            revision=_positive_integer(
                document,
                "revision",
            ),
            schema_version=schema_version,
        )

    except ControlPlaneServiceAccountSchemaError:
        raise

    except (TypeError, ValueError) as exception:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token record is invalid"
        ) from exception


def _decode_api_token_digest_index_state(
    stored: (StateRecord[dict[str, object]] | StateRecord[object]),
) -> _DecodedApiTokenDigestIndex:
    value = _mapping(
        stored.value,
        label="API-token digest index",
    )

    _require_exact_fields(
        value,
        _API_TOKEN_DIGEST_INDEX_FIELDS,
        label="API-token digest index",
    )
    _require_schema(value)

    kind = _string(value, "kind")

    if kind != _API_TOKEN_DIGEST_INDEX_KIND:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token digest index kind is invalid"
        )

    try:
        token_digest = _string(
            value,
            "token_digest",
        )
        normalized_token_digest = _normalize_sha256(token_digest)

        if token_digest != normalized_token_digest:
            raise ValueError("persisted API-token digest index is not canonical")

        return _DecodedApiTokenDigestIndex(
            kind=kind,
            token_id=UUID(_string(value, "token_id")),
            service_account_id=UUID(
                _string(
                    value,
                    "service_account_id",
                )
            ),
            token_digest=normalized_token_digest,
            token_version=_positive_integer(
                value,
                "token_version",
            ),
            revision=_positive_integer(
                value,
                "revision",
            ),
            record_digest=_normalize_sha256(
                _string(
                    value,
                    "record_digest",
                )
            ),
        )

    except (TypeError, ValueError) as exception:
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token digest index is invalid"
        ) from exception


def _verify_api_token_digest_index(
    index: _DecodedApiTokenDigestIndex,
    metadata: ControlPlaneApiTokenMetadata,
) -> None:
    digest = control_plane_api_token_record_digest(metadata)

    if (
        index.token_id != metadata.id
        or (index.service_account_id != metadata.service_account_id)
        or not hmac.compare_digest(
            index.token_digest,
            metadata.token_digest,
        )
        or (index.token_version != metadata.token_version)
        or index.revision != metadata.revision
        or not hmac.compare_digest(
            index.record_digest,
            digest,
        )
    ):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token digest index and record do not match"
        )


def _optional_string(
    value: Mapping[str, object],
    key: str,
) -> str | None:
    result = value.get(key)

    if result is None:
        return None

    if not isinstance(result, str):
        raise ValueError(f"invalid persisted service-account field: {key}")

    return result


def _optional_uuid(
    value: Mapping[str, object],
    key: str,
) -> UUID | None:
    result = value.get(key)

    if result is None:
        return None

    if not isinstance(result, str):
        raise ValueError(f"invalid persisted service-account field: {key}")

    return UUID(result)


def _string_sequence(
    value: Mapping[str, object],
    key: str,
) -> tuple[str, ...]:
    result = value.get(key)

    if (
        not isinstance(result, Sequence)
        or isinstance(
            result,
            (str, bytes, bytearray),
        )
        or not all(isinstance(item, str) for item in result)
    ):
        raise ValueError(f"invalid persisted service-account field: {key}")

    return tuple(cast(Sequence[str], result))


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


def _api_token_digest_key_matches(
    key_name: str,
    token_digest: str,
) -> bool:
    if not key_name.startswith(_API_TOKEN_DIGEST_PREFIX):
        return False

    persisted_digest = key_name[len(_API_TOKEN_DIGEST_PREFIX) :]

    return hmac.compare_digest(
        persisted_digest,
        token_digest,
    )


def _validate_persisted_token_collection(
    stored_records: tuple[
        StateRecord[object],
        ...,
    ],
    stored_indexes: tuple[
        StateRecord[object],
        ...,
    ],
    *,
    account_ids: frozenset[UUID],
) -> tuple[
    ControlPlaneApiTokenMetadata,
    ...,
]:
    tokens = tuple(_decode_api_token_record_state(item) for item in stored_records)
    indexes = tuple(_decode_api_token_digest_index_state(item) for item in stored_indexes)

    for stored_record, metadata in zip(
        stored_records,
        tokens,
        strict=True,
    ):
        expected_key = f"{_API_TOKEN_RECORD_PREFIX}{metadata.id.hex}"

        if stored_record.key.name != expected_key:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API-token identity does not match its state key"
            )

    for stored_index, digest_index in zip(
        stored_indexes,
        indexes,
        strict=True,
    ):
        if not _api_token_digest_key_matches(
            stored_index.key.name,
            digest_index.token_digest,
        ):
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API-token digest index does not match its state key"
            )

    token_ids = tuple(metadata.id for metadata in tokens)
    digests = tuple(metadata.token_digest for metadata in tokens)

    if len(token_ids) != len(set(token_ids)) or len(digests) != len(set(digests)):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token repository contains duplicate identities"
        )

    if len(tokens) != len(indexes):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token records and digest indexes are incomplete"
        )

    index_token_ids = tuple(index.token_id for index in indexes)
    index_digests = tuple(index.token_digest for index in indexes)

    if len(index_token_ids) != len(set(index_token_ids)) or len(index_digests) != len(
        set(index_digests)
    ):
        raise ControlPlaneServiceAccountCorruptionError(
            "persisted API-token repository contains duplicate digest indexes"
        )

    indexes_by_digest = {index.token_digest: index for index in indexes}

    for metadata in tokens:
        if metadata.service_account_id not in account_ids:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API token references a missing service account"
            )

        index = indexes_by_digest.get(metadata.token_digest)

        if index is None:
            raise ControlPlaneServiceAccountCorruptionError(
                "persisted API-token record has an incomplete digest index"
            )

        _verify_api_token_digest_index(
            index,
            metadata,
        )

    return tokens
