"""Session repositories for Phoenix authentication."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import cast
from uuid import UUID

from phoenix_os.identity.contracts import Identity, Session, SessionRecord, SessionStatus
from phoenix_os.identity.errors import SessionRepositoryClosedError
from phoenix_os.policy import PrincipalType
from phoenix_os.state import ABSENT_VERSION, StateKey, StateOperationContext, StateStore


class InMemorySessionRepository:
    """Deterministic in-process session repository."""

    def __init__(self) -> None:
        self._records: dict[UUID, SessionRecord] = {}
        self._by_digest: dict[str, UUID] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def save(self, record: SessionRecord) -> None:
        async with self._lock:
            self._ensure_open()
            previous = self._records.get(record.session.id)
            if previous is not None and previous.token_digest != record.token_digest:
                self._by_digest.pop(previous.token_digest, None)
            collision = self._by_digest.get(record.token_digest)
            if collision is not None and collision != record.session.id:
                raise ValueError("session token digest collision")
            self._records[record.session.id] = record
            self._by_digest[record.token_digest] = record.session.id

    async def get(self, session_id: UUID) -> SessionRecord | None:
        async with self._lock:
            self._ensure_open()
            return self._records.get(session_id)

    async def find_by_digest(self, token_digest: str) -> SessionRecord | None:
        async with self._lock:
            self._ensure_open()
            session_id = self._by_digest.get(token_digest.strip().lower())
            return None if session_id is None else self._records.get(session_id)

    async def list_for_subject(self, subject: str) -> tuple[SessionRecord, ...]:
        normalized = subject.strip()
        if not normalized:
            raise ValueError("subject must not be blank")
        async with self._lock:
            self._ensure_open()
            records = [
                record
                for record in self._records.values()
                if record.session.identity.subject == normalized
            ]
        return _sort_records(records)

    async def list_all(self) -> tuple[SessionRecord, ...]:
        async with self._lock:
            self._ensure_open()
            return _sort_records(self._records.values())

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()
            self._by_digest.clear()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise SessionRepositoryClosedError("session repository is closed")


class StateSessionRepository:
    """Persist hashed sessions through the generic Phoenix StateStore contract."""

    def __init__(
        self,
        store: StateStore,
        *,
        namespace: str = "identity_sessions",
        context: StateOperationContext | None = None,
    ) -> None:
        normalized = namespace.strip().lower()
        if not normalized:
            raise ValueError("namespace must not be blank")
        self._store = store
        self._namespace = normalized
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.identity",
                "principal_type": PrincipalType.SYSTEM.value,
                "authenticated": "true",
            }
        )
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def save(self, record: SessionRecord) -> None:
        async with self._lock:
            self._ensure_open()
            key = self._key(record.session.id)
            current = await self._store.get(key, context=self._context)
            expected = ABSENT_VERSION if current is None else current.version
            await self._store.put(
                key,
                _encode_record(record),
                expected_version=expected,
                context=self._context,
            )

    async def get(self, session_id: UUID) -> SessionRecord | None:
        self._ensure_open()
        record = await self._store.get(self._key(session_id), context=self._context)
        return None if record is None else _decode_record(record.value)

    async def find_by_digest(self, token_digest: str) -> SessionRecord | None:
        normalized = token_digest.strip().lower()
        for record in await self.list_all():
            if record.token_digest == normalized:
                return record
        return None

    async def list_for_subject(self, subject: str) -> tuple[SessionRecord, ...]:
        normalized = subject.strip()
        if not normalized:
            raise ValueError("subject must not be blank")
        records = [
            record
            for record in await self.list_all()
            if record.session.identity.subject == normalized
        ]
        return _sort_records(records)

    async def list_all(self) -> tuple[SessionRecord, ...]:
        self._ensure_open()
        raw_records = await self._store.list(namespace=self._namespace, context=self._context)
        decoded = [_decode_record(cast(Mapping[str, object], item.value)) for item in raw_records]
        return _sort_records(decoded)

    async def close(self) -> None:
        # The repository borrows the StateStore; Runtime owns the store lifecycle.
        self._closed = True

    def _key(self, session_id: UUID) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"s_{session_id.hex}", dict)

    def _ensure_open(self) -> None:
        if self._closed:
            raise SessionRepositoryClosedError("session repository is closed")


def _sort_records(records: Iterable[SessionRecord]) -> tuple[SessionRecord, ...]:
    return tuple(
        sorted(
            records,
            key=lambda item: (item.session.issued_at, str(item.session.id)),
        )
    )


def _encode_record(record: SessionRecord) -> dict[str, object]:
    identity = record.session.identity
    session = record.session
    return {
        "token_digest": record.token_digest,
        "session": {
            "id": str(session.id),
            "issued_at": session.issued_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "last_seen_at": session.last_seen_at.isoformat(),
            "idle_expires_at": (
                None if session.idle_expires_at is None else session.idle_expires_at.isoformat()
            ),
            "idle_ttl_seconds": (
                None if session.idle_ttl is None else session.idle_ttl.total_seconds()
            ),
            "status": session.status.value,
            "revoked_at": None if session.revoked_at is None else session.revoked_at.isoformat(),
            "revocation_reason": session.revocation_reason,
            "metadata": dict(session.metadata),
        },
        "identity": {
            "subject": identity.subject,
            "principal_type": identity.principal_type.value,
            "provider": identity.provider,
            "display_name": identity.display_name,
            "roles": sorted(identity.roles),
            "permissions": sorted(identity.permissions),
            "scopes": sorted(identity.scopes),
            "attributes": dict(identity.attributes),
            "authenticated_at": identity.authenticated_at.isoformat(),
        },
    }


def _decode_record(value: Mapping[str, object]) -> SessionRecord:
    session_data = _mapping(value, "session")
    identity_data = _mapping(value, "identity")
    identity = Identity(
        subject=_string(identity_data, "subject"),
        principal_type=PrincipalType(_string(identity_data, "principal_type")),
        provider=_string(identity_data, "provider"),
        display_name=_optional_string(identity_data, "display_name"),
        roles=frozenset(_string_list(identity_data, "roles")),
        permissions=frozenset(_string_list(identity_data, "permissions")),
        scopes=frozenset(_string_list(identity_data, "scopes")),
        attributes=_string_mapping(identity_data, "attributes"),
        authenticated_at=_datetime(identity_data, "authenticated_at"),
    )
    session = Session(
        id=UUID(_string(session_data, "id")),
        identity=identity,
        issued_at=_datetime(session_data, "issued_at"),
        expires_at=_datetime(session_data, "expires_at"),
        last_seen_at=_datetime(session_data, "last_seen_at"),
        idle_expires_at=_optional_datetime(session_data, "idle_expires_at"),
        idle_ttl=_optional_seconds(session_data, "idle_ttl_seconds"),
        status=SessionStatus(_string(session_data, "status")),
        revoked_at=_optional_datetime(session_data, "revoked_at"),
        revocation_reason=_optional_string(session_data, "revocation_reason"),
        metadata=_string_mapping(session_data, "metadata"),
    )
    return SessionRecord(session=session, token_digest=_string(value, "token_digest"))


def _mapping(value: Mapping[str, object], key: str) -> Mapping[str, object]:
    result = value.get(key)
    if not isinstance(result, Mapping):
        raise ValueError(f"invalid persisted session field: {key}")
    return cast(Mapping[str, object], result)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted session field: {key}")
    return result


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted session field: {key}")
    return result


def _string_list(value: Mapping[str, object], key: str) -> tuple[str, ...]:
    result = value.get(key)
    if not isinstance(result, list) or not all(isinstance(item, str) for item in result):
        raise ValueError(f"invalid persisted session field: {key}")
    return tuple(cast(list[str], result))


def _string_mapping(value: Mapping[str, object], key: str) -> Mapping[str, str]:
    result = value.get(key)
    if not isinstance(result, Mapping):
        raise ValueError(f"invalid persisted session field: {key}")
    if not all(isinstance(item, str) for item in result.keys()) or not all(
        isinstance(item, str) for item in result.values()
    ):
        raise ValueError(f"invalid persisted session field: {key}")
    return cast(Mapping[str, str], result)


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    return datetime.fromisoformat(_string(value, key))


def _optional_datetime(value: Mapping[str, object], key: str) -> datetime | None:
    raw = _optional_string(value, key)
    return None if raw is None else datetime.fromisoformat(raw)


def _optional_seconds(value: Mapping[str, object], key: str) -> timedelta | None:
    raw = value.get(key)
    if raw is None:
        return None
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        raise ValueError(f"invalid persisted session field: {key}")
    return timedelta(seconds=float(raw))
