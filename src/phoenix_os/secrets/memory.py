"""Deterministic in-memory secret store for tests and ephemeral deployments."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime

from phoenix_os.configuration import SecretValue
from phoenix_os.secrets.contracts import (
    KeyRef,
    SecretMetadata,
    SecretRef,
    SecretStatus,
    SecretStoreSnapshot,
    StoredSecret,
)
from phoenix_os.secrets.errors import SecretStoreClosedError, SecretVersionError


class InMemorySecretStore:
    """Process-local store that never serializes secret material.

    This backend is intentionally not encrypted at rest and is suitable only for tests,
    development, or ephemeral processes. Production encryption belongs in an external
    SecretStore implementation.
    """

    def __init__(self) -> None:
        self._records: dict[str, dict[int, StoredSecret]] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def put(
        self,
        ref: SecretRef,
        value: SecretValue,
        *,
        created_by: str,
        attributes: Mapping[str, str] | None = None,
        protection_key: KeyRef | None = None,
    ) -> StoredSecret:
        self._ensure_open()
        if ref.version is not None:
            raise SecretVersionError("put requires an unversioned SecretRef")
        if not isinstance(value, SecretValue):
            raise TypeError("secret value must be SecretValue")
        async with self._lock:
            self._ensure_open()
            versions = self._records.setdefault(ref.canonical, {})
            version = max(versions, default=0) + 1
            previous = version - 1 if version > 1 else None
            exact = ref.at(version)
            metadata = SecretMetadata(
                ref=exact,
                created_by=created_by,
                rotated_from=previous,
                protection_key=protection_key,
                attributes={} if attributes is None else attributes,
            )
            stored = StoredSecret(metadata, value)
            versions[version] = stored
            return stored

    async def get(self, ref: SecretRef) -> StoredSecret | None:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            versions = self._records.get(ref.canonical)
            if not versions:
                return None
            version = ref.version
            if version is None:
                active = [
                    item
                    for item in versions.values()
                    if item.metadata.status is SecretStatus.ACTIVE
                ]
                if not active:
                    return None
                return max(active, key=lambda item: item.metadata.ref.version or 0)
            return versions.get(version)

    async def list(self, *, namespace: str | None = None) -> tuple[SecretMetadata, ...]:
        self._ensure_open()
        normalized = None if namespace is None else SecretRef("placeholder", namespace).namespace
        async with self._lock:
            self._ensure_open()
            metadata = [
                stored.metadata
                for versions in self._records.values()
                for stored in versions.values()
                if normalized is None or stored.metadata.ref.namespace == normalized
            ]
        return tuple(
            sorted(
                metadata,
                key=lambda item: (
                    item.ref.namespace,
                    item.ref.name,
                    item.ref.version or 0,
                ),
            )
        )

    async def revoke(
        self,
        ref: SecretRef,
        *,
        reason: str,
        revoked_at: datetime,
    ) -> SecretMetadata | None:
        self._ensure_open()
        if revoked_at.tzinfo is None:
            raise ValueError("revoked_at must be timezone-aware")
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise ValueError("revocation reason must not be blank")
        async with self._lock:
            self._ensure_open()
            versions = self._records.get(ref.canonical)
            if not versions:
                return None
            version = ref.version
            if version is None:
                active_versions = [
                    number
                    for number, item in versions.items()
                    if item.metadata.status is SecretStatus.ACTIVE
                ]
                if not active_versions:
                    return None
                version = max(active_versions)
            stored = versions.get(version)
            if stored is None or stored.metadata.status is SecretStatus.REVOKED:
                return None
            metadata = replace(
                stored.metadata,
                status=SecretStatus.REVOKED,
                revoked_at=revoked_at,
                revocation_reason=normalized_reason,
            )
            versions[version] = StoredSecret(metadata, stored.value)
            return metadata

    async def snapshot(self) -> SecretStoreSnapshot:
        async with self._lock:
            versions = [stored for group in self._records.values() for stored in group.values()]
            active = sum(item.metadata.status is SecretStatus.ACTIVE for item in versions)
            return SecretStoreSnapshot(
                closed=self._closed,
                names=len(self._records),
                versions=len(versions),
                active_versions=active,
                revoked_versions=len(versions) - active,
            )

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()
            self._closed = True

    async def start(self, context: object) -> None:
        del context
        self._ensure_open()

    async def stop(self, context: object) -> None:
        del context
        await self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise SecretStoreClosedError("secret store is closed")
