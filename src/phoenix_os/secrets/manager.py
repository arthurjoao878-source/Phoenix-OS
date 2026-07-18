"""Identity-aware and policy-enforced Phoenix secrets manager."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from phoenix_os.configuration import SecretValue
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import PolicyEngine, PolicyRequest, SecurityContext
from phoenix_os.policy.errors import PolicyConfirmationRequiredError, PolicyDeniedError
from phoenix_os.secrets.contracts import (
    KeyRef,
    SecretLease,
    SecretLeasePolicy,
    SecretLeaseStatus,
    SecretMetadata,
    SecretRef,
    SecretsSnapshot,
    SecretStatus,
    SecretStore,
)
from phoenix_os.secrets.errors import (
    SecretAccessDeniedError,
    SecretAlreadyExistsError,
    SecretLeaseExpiredError,
    SecretLeaseNotFoundError,
    SecretLeaseRevokedError,
    SecretNotFoundError,
    SecretRevokedError,
    SecretsManagerClosedError,
)
from phoenix_os.secrets.memory import InMemorySecretStore


class SecretsManager:
    """Manage versioned secrets and short-lived material leases."""

    def __init__(
        self,
        store: SecretStore | None = None,
        *,
        policy: PolicyEngine | None = None,
        events: EventBus | None = None,
        observability: ObservabilityHub | None = None,
        lease_policy: SecretLeasePolicy | None = None,
        clock: Callable[[], datetime] | None = None,
        source: str = "phoenix.secrets",
    ) -> None:
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        self._store = store or InMemorySecretStore()
        self._policy = policy
        self._events = events
        self._observability = observability
        self._lease_policy = lease_policy or SecretLeasePolicy()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._source = normalized_source
        self._leases: dict[UUID, SecretLease] = {}
        self._closed = False
        self._issued_leases = 0
        self._revoked_leases = 0
        self._denied_operations = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def store(self) -> SecretStore:
        return self._store

    async def create(
        self,
        ref: SecretRef,
        value: SecretValue,
        context: SecurityContext,
        *,
        attributes: Mapping[str, str] | None = None,
        protection_key: KeyRef | None = None,
    ) -> SecretMetadata:
        """Create version one; use rotate for an existing secret name."""

        self._ensure_open()
        self._require_unversioned(ref)
        await self._authorize("secret.create", ref, context)
        existing = await self._store.list(namespace=ref.namespace)
        if any(item.ref.canonical == ref.canonical for item in existing):
            raise SecretAlreadyExistsError(f"secret already exists: {ref.canonical}")
        async with self._trace("secrets.create", ref, context):
            stored = await self._store.put(
                ref,
                value,
                created_by=context.principal,
                attributes=attributes,
                protection_key=protection_key,
            )
        await self._signal("secrets.created", stored.metadata, context)
        return stored.metadata

    async def rotate(
        self,
        ref: SecretRef,
        value: SecretValue,
        context: SecurityContext,
        *,
        attributes: Mapping[str, str] | None = None,
        protection_key: KeyRef | None = None,
    ) -> SecretMetadata:
        """Create the next immutable version of an existing secret."""

        self._ensure_open()
        self._require_unversioned(ref)
        await self._authorize("secret.rotate", ref, context)
        if await self._store.get(ref) is None:
            raise SecretNotFoundError(f"secret not found: {ref.canonical}")
        async with self._trace("secrets.rotate", ref, context):
            stored = await self._store.put(
                ref,
                value,
                created_by=context.principal,
                attributes=attributes,
                protection_key=protection_key,
            )
        await self._signal("secrets.rotated", stored.metadata, context)
        return stored.metadata

    async def describe(self, ref: SecretRef, context: SecurityContext) -> SecretMetadata:
        self._ensure_open()
        await self._authorize("secret.describe", ref, context)
        stored = await self._store.get(ref)
        if stored is None:
            raise SecretNotFoundError(f"secret not found: {ref}")
        return stored.metadata

    async def list(
        self,
        context: SecurityContext,
        *,
        namespace: str | None = None,
    ) -> tuple[SecretMetadata, ...]:
        self._ensure_open()
        resource = SecretRef("all", namespace or "default")
        await self._authorize("secret.list", resource, context, wildcard=True)
        return await self._store.list(namespace=namespace)

    async def lease(
        self,
        ref: SecretRef,
        context: SecurityContext,
        *,
        ttl: timedelta | None = None,
    ) -> SecretLease:
        """Issue a short-lived lease for one active secret version."""

        self._ensure_open()
        await self._authorize("secret.read", ref, context)
        effective_ttl = self._lease_policy.default_ttl if ttl is None else ttl
        if effective_ttl <= timedelta(0):
            raise ValueError("lease ttl must be positive")
        if effective_ttl > self._lease_policy.max_ttl:
            raise ValueError("lease ttl exceeds configured maximum")
        async with self._trace("secrets.lease", ref, context):
            stored = await self._store.get(ref)
            if stored is None:
                raise SecretNotFoundError(f"secret not found: {ref}")
            if stored.metadata.status is SecretStatus.REVOKED:
                raise SecretRevokedError(f"secret version is revoked: {stored.metadata.ref}")
            now = self._now()
            lease = SecretLease(
                ref=stored.metadata.ref,
                principal=context.principal,
                value=stored.value,
                issued_at=now,
                expires_at=now + effective_ttl,
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )
            async with self._lock:
                self._leases[lease.id] = lease
                self._issued_leases += 1
        await self._signal(
            "secrets.lease.issued",
            stored.metadata,
            context,
            extra={"lease_id": str(lease.id), "expires_at": lease.expires_at.isoformat()},
        )
        return lease

    async def resolve_lease(self, lease_id: UUID, context: SecurityContext) -> SecretLease:
        """Resolve a lease for the same authenticated principal."""

        self._ensure_open()
        if not context.authenticated:
            await self._deny("authenticated identity required")
        async with self._lock:
            lease = self._leases.get(lease_id)
        if lease is None:
            raise SecretLeaseNotFoundError(f"secret lease not found: {lease_id}")
        if lease.principal != context.principal:
            await self._deny("secret lease belongs to another principal")
        if lease.status is SecretLeaseStatus.REVOKED:
            raise SecretLeaseRevokedError(f"secret lease is revoked: {lease_id}")
        if not lease.valid_at(self._now()):
            raise SecretLeaseExpiredError(f"secret lease has expired: {lease_id}")
        return lease

    async def revoke(
        self,
        ref: SecretRef,
        context: SecurityContext,
        *,
        reason: str = "revoked",
    ) -> bool:
        """Revoke one exact version or the latest active version."""

        self._ensure_open()
        await self._authorize("secret.revoke", ref, context)
        metadata = await self._store.revoke(ref, reason=reason, revoked_at=self._now())
        if metadata is None:
            return False
        revoked = await self._revoke_matching_leases(metadata.ref)
        await self._signal(
            "secrets.revoked",
            metadata,
            context,
            extra={"reason": reason.strip(), "revoked_leases": revoked},
        )
        return True

    async def revoke_lease(
        self,
        lease_id: UUID,
        context: SecurityContext,
        *,
        reason: str = "revoked",
    ) -> bool:
        self._ensure_open()
        async with self._lock:
            lease = self._leases.get(lease_id)
        if lease is None:
            return False
        await self._authorize("secret.lease.revoke", lease.ref, context)
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise ValueError("revocation reason must not be blank")
        async with self._lock:
            current = self._leases.get(lease_id)
            if current is None or current.status is SecretLeaseStatus.REVOKED:
                return False
            self._leases[lease_id] = replace(current, status=SecretLeaseStatus.REVOKED)
            self._revoked_leases += 1
        await self._emit(
            "secrets.lease.revoked",
            context,
            {
                "lease_id": str(lease_id),
                "secret": lease.ref.canonical,
                "version": lease.ref.version,
                "reason": normalized_reason,
            },
        )
        return True

    async def purge_expired_leases(self) -> int:
        self._ensure_open()
        now = self._now()
        async with self._lock:
            expired = [
                lease_id for lease_id, lease in self._leases.items() if not lease.valid_at(now)
            ]
            for lease_id in expired:
                del self._leases[lease_id]
            return len(expired)

    async def snapshot(self) -> SecretsSnapshot:
        async with self._lock:
            now = self._now()
            active = sum(lease.valid_at(now) for lease in self._leases.values())
            return SecretsSnapshot(
                closed=self._closed,
                leases=len(self._leases),
                active_leases=active,
                issued_leases=self._issued_leases,
                revoked_leases=self._revoked_leases,
                denied_operations=self._denied_operations,
            )

    async def close(self) -> None:
        async with self._lock:
            self._leases.clear()
            self._closed = True
        await self._store.close()

    async def start(self, context: object) -> None:
        del context
        self._ensure_open()

    async def stop(self, context: object) -> None:
        del context
        await self.close()

    async def _authorize(
        self,
        action: str,
        ref: SecretRef,
        context: SecurityContext,
        *,
        wildcard: bool = False,
    ) -> None:
        if not context.authenticated:
            await self._deny("authenticated identity required")
        resource = f"secret:{ref.namespace}/*" if wildcard else ref.resource
        if self._policy is not None:
            try:
                await self._policy.enforce(
                    PolicyRequest(
                        action=action,
                        resource=resource,
                        context=context,
                        attributes={
                            "namespace": ref.namespace,
                            "secret": ref.name,
                            "version": "latest" if ref.version is None else str(ref.version),
                        },
                    )
                )
                return
            except (PolicyDeniedError, PolicyConfirmationRequiredError) as exception:
                await self._deny(str(exception))
        permissions = context.permissions
        if action not in permissions and "secret.*" not in permissions and "*" not in permissions:
            await self._deny(f"permission required: {action}")

    async def _deny(self, reason: str) -> None:
        async with self._lock:
            self._denied_operations += 1
        raise SecretAccessDeniedError(reason)

    async def _revoke_matching_leases(self, ref: SecretRef) -> int:
        async with self._lock:
            matching = [
                lease_id
                for lease_id, lease in self._leases.items()
                if lease.ref == ref and lease.status is SecretLeaseStatus.ACTIVE
            ]
            for lease_id in matching:
                self._leases[lease_id] = replace(
                    self._leases[lease_id], status=SecretLeaseStatus.REVOKED
                )
            self._revoked_leases += len(matching)
            return len(matching)

    async def _signal(
        self,
        name: str,
        metadata: SecretMetadata,
        context: SecurityContext,
        *,
        extra: Mapping[str, object] | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "secret": metadata.ref.canonical,
            "namespace": metadata.ref.namespace,
            "version": metadata.ref.version,
            "principal": context.principal,
            "status": metadata.status.value,
        }
        if extra is not None:
            payload.update(extra)
        await self._emit(name, context, payload)
        if self._observability is not None:
            await self._observability.metric(
                "secrets.operations",
                1,
                source=self._source,
                kind=MetricKind.COUNTER,
                attributes={"operation": name, "namespace": metadata.ref.namespace},
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )

    async def _emit(
        self,
        name: str,
        context: SecurityContext,
        payload: Mapping[str, object],
    ) -> None:
        if self._events is not None:
            await self._events.emit(
                name,
                source=self._source,
                payload=payload,
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )
        if self._observability is not None:
            await self._observability.log(
                name,
                source=self._source,
                message=name.replace(".", " "),
                severity=Severity.INFO,
                attributes=payload,
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )

    @asynccontextmanager
    async def _trace(
        self,
        name: str,
        ref: SecretRef,
        context: SecurityContext,
    ) -> AsyncIterator[None]:
        if self._observability is None:
            yield
            return
        async with self._observability.span(
            name,
            source=self._source,
            attributes={"secret": ref.canonical, "namespace": ref.namespace},
            correlation_id=context.correlation_id,
        ):
            yield

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return now

    @staticmethod
    def _require_unversioned(ref: SecretRef) -> None:
        if ref.version is not None:
            raise ValueError("operation requires an unversioned SecretRef")

    def _ensure_open(self) -> None:
        if self._closed:
            raise SecretsManagerClosedError("secrets manager is closed")
