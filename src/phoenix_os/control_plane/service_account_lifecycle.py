"""Service-account creation, update, and one-time API-token issuance."""

from __future__ import annotations

import asyncio
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from phoenix_os.control_plane.errors import (
    ControlPlaneApiTokenConflictError,
    ControlPlaneApiTokenNotFoundError,
    ControlPlaneServiceAccountConflictError,
    ControlPlaneServiceAccountLifecycleClosedError,
    ControlPlaneServiceAccountNotFoundError,
)
from phoenix_os.control_plane.service_account_contracts import (
    MAX_CONTROL_PLANE_API_TOKEN_ROTATION_OVERLAP,
    MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT,
    ControlPlaneApiToken,
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenRestriction,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountRepository,
    ControlPlaneServiceAccountStatus,
)

type ControlPlaneServiceAccountClock = Callable[[], datetime]
type ControlPlaneServiceAccountTokenFactory = Callable[[], str]
type ControlPlaneServiceAccountIdFactory = Callable[[], UUID]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_token_factory() -> str:
    return f"phx_sa_{secrets.token_urlsafe(48)}"


def _require_service_account_revision(
    actual: int,
    expected: int | None,
) -> None:
    if expected is None:
        return

    if not isinstance(expected, int) or isinstance(expected, bool) or expected <= 0:
        raise ValueError("expected service-account revision must be a positive integer")

    if actual != expected:
        raise ControlPlaneServiceAccountConflictError("service-account revision conflict")


def _require_api_token_revision(
    actual: int,
    expected: int | None,
) -> None:
    if expected is None:
        return

    if not isinstance(expected, int) or isinstance(expected, bool) or expected <= 0:
        raise ValueError("expected API-token revision must be a positive integer")

    if actual != expected:
        raise ControlPlaneApiTokenConflictError("API-token revision conflict")


@dataclass(frozen=True, slots=True)
class ControlPlaneApiTokenGrant:
    """One-time plaintext token and its credential-safe metadata."""

    metadata: ControlPlaneApiTokenMetadata
    token: ControlPlaneApiToken = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(
            self.metadata,
            ControlPlaneApiTokenMetadata,
        ):
            raise TypeError("API-token grant metadata must be ControlPlaneApiTokenMetadata")

        if not isinstance(
            self.token,
            ControlPlaneApiToken,
        ):
            raise TypeError("API-token grant token must be ControlPlaneApiToken")

        if not hmac.compare_digest(
            self.token.digest,
            self.metadata.token_digest,
        ):
            raise ValueError("API-token grant plaintext does not match its metadata digest")

        if self.schema_version != 1:
            raise ValueError("unsupported API-token grant schema version")


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountLifecycleSnapshot:
    """Credential-free lifecycle operation counters."""

    closed: bool
    accounts_created: int
    accounts_updated: int
    tokens_issued: int

    def __post_init__(self) -> None:
        if (
            min(
                self.accounts_created,
                self.accounts_updated,
                self.tokens_issued,
            )
            < 0
        ):
            raise ValueError("service-account lifecycle counters cannot be negative")


class ControlPlaneServiceAccountLifecycleService:
    """Manage machine identities without retaining plaintext credentials."""

    def __init__(
        self,
        *,
        repository: ControlPlaneServiceAccountRepository,
        clock: ControlPlaneServiceAccountClock = _utc_now,
        token_factory: ControlPlaneServiceAccountTokenFactory = (_default_token_factory),
        account_id_factory: ControlPlaneServiceAccountIdFactory = uuid4,
        token_id_factory: ControlPlaneServiceAccountIdFactory = uuid4,
    ) -> None:
        if not callable(clock):
            raise TypeError("service-account clock must be callable")

        if not callable(token_factory):
            raise TypeError("API-token factory must be callable")

        if not callable(account_id_factory):
            raise TypeError("service-account id factory must be callable")

        if not callable(token_id_factory):
            raise TypeError("API-token id factory must be callable")

        self._repository = repository
        self._clock = clock
        self._token_factory = token_factory
        self._account_id_factory = account_id_factory
        self._token_id_factory = token_id_factory
        self._closed = False
        self._accounts_created = 0
        self._accounts_updated = 0
        self._tokens_issued = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def start(
        self,
        context: object = None,
    ) -> None:
        del context
        self._require_open()

    async def stop(
        self,
        context: object = None,
    ) -> None:
        del context
        await self.close()

    async def create_account(
        self,
        *,
        name: str,
        display_name: str,
    ) -> ControlPlaneServiceAccountRecord:
        self._require_open()
        now = self._now()

        record = ControlPlaneServiceAccountRecord(
            id=self._new_uuid(
                self._account_id_factory,
                label="service-account",
            ),
            name=name,
            display_name=display_name,
            created_at=now,
            updated_at=now,
        )

        await self._repository.add_account(record)
        await self._increment("accounts_created")

        return record

    async def update_account(
        self,
        service_account_id: UUID,
        *,
        expected_revision: int | None = None,
        name: str | None = None,
        display_name: str | None = None,
    ) -> ControlPlaneServiceAccountRecord:
        self._require_open()

        if name is None and display_name is None:
            raise ValueError("service-account update requires at least one field")

        current = await self._repository.get_account(service_account_id)

        if current is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        _require_service_account_revision(
            current.revision,
            expected_revision,
        )

        if current.status is ControlPlaneServiceAccountStatus.REVOKED:
            raise ControlPlaneServiceAccountConflictError(
                "revoked service account cannot be updated"
            )

        now = self._now()

        if now < current.updated_at:
            raise ControlPlaneServiceAccountConflictError("service-account clock moved backwards")

        replacement = replace(
            current,
            name=current.name if name is None else name,
            display_name=(current.display_name if display_name is None else display_name),
            updated_at=now,
            revision=current.revision + 1,
        )

        if replacement.name == current.name and replacement.display_name == current.display_name:
            raise ValueError("service-account update does not change any field")

        result = await self._repository.replace_account(
            replacement,
            expected_revision=current.revision,
        )
        await self._increment("accounts_updated")

        return result

    async def issue_token(
        self,
        service_account_id: UUID,
        *,
        label: str,
        scopes: frozenset[str],
        expires_at: datetime,
        resources: frozenset[str] = frozenset({"*"}),
        restriction: (ControlPlaneApiTokenRestriction | None) = None,
    ) -> ControlPlaneApiTokenGrant:
        """Persist only metadata and return plaintext exactly once."""

        self._require_open()

        account = await self._repository.get_account(service_account_id)

        if account is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        if account.status is not ControlPlaneServiceAccountStatus.ACTIVE:
            raise ControlPlaneServiceAccountConflictError(
                "inactive service account cannot issue API tokens"
            )

        now = self._now()
        token_value = self._token_factory()

        if not isinstance(token_value, str):
            raise TypeError("API-token factory must return str")

        token = ControlPlaneApiToken(token_value)
        metadata = ControlPlaneApiTokenMetadata(
            id=self._new_uuid(
                self._token_id_factory,
                label="API-token",
            ),
            service_account_id=account.id,
            label=label,
            token_digest=token.digest,
            scopes=scopes,
            resources=resources,
            restriction=(ControlPlaneApiTokenRestriction() if restriction is None else restriction),
            issued_at=now,
            expires_at=expires_at,
            updated_at=now,
        )

        await self._repository.add_token(metadata)
        await self._increment("tokens_issued")

        return ControlPlaneApiTokenGrant(
            metadata=metadata,
            token=token,
        )

    async def rotate_token(
        self,
        token_id: UUID,
        *,
        expected_revision: int | None = None,
        expires_at: datetime,
        label: str | None = None,
        scopes: frozenset[str] | None = None,
        resources: frozenset[str] | None = None,
        restriction: (ControlPlaneApiTokenRestriction | None) = None,
        overlap: timedelta = timedelta(0),
    ) -> ControlPlaneApiTokenGrant:
        """Atomically replace one token with bounded overlap."""

        self._require_open()

        if not isinstance(overlap, timedelta):
            raise TypeError("API-token rotation overlap must be timedelta")

        if overlap < timedelta(0):
            raise ValueError("API-token rotation overlap cannot be negative")

        if overlap > MAX_CONTROL_PLANE_API_TOKEN_ROTATION_OVERLAP:
            raise ValueError("API-token rotation overlap exceeds the supported maximum")

        current = await self._repository.get_token(token_id)

        if current is None:
            raise ControlPlaneApiTokenNotFoundError("API-token metadata was not found")

        _require_api_token_revision(
            current.revision,
            expected_revision,
        )

        account = await self._repository.get_account(current.service_account_id)

        if account is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        if account.status is not ControlPlaneServiceAccountStatus.ACTIVE:
            raise ControlPlaneServiceAccountConflictError(
                "inactive service account cannot rotate API tokens"
            )

        now = self._now()

        if not current.authenticatable_at(now):
            raise ControlPlaneApiTokenConflictError(
                "only an active unexpired API token can be rotated"
            )

        token_value = self._token_factory()

        if not isinstance(token_value, str):
            raise TypeError("API-token factory must return str")

        token = ControlPlaneApiToken(token_value)

        successor = ControlPlaneApiTokenMetadata(
            id=self._new_uuid(
                self._token_id_factory,
                label="API-token",
            ),
            service_account_id=current.service_account_id,
            label=current.label if label is None else label,
            token_digest=token.digest,
            scopes=current.scopes if scopes is None else scopes,
            resources=(current.resources if resources is None else resources),
            restriction=(current.restriction if restriction is None else restriction),
            issued_at=now,
            expires_at=expires_at,
            updated_at=now,
            rotated_from=current.id,
            token_version=current.token_version + 1,
        )

        if overlap > timedelta(0):
            predecessor = replace(
                current,
                expires_at=min(
                    current.expires_at,
                    now + overlap,
                ),
                updated_at=now,
                revision=current.revision + 1,
            )
        else:
            predecessor = replace(
                current,
                status=ControlPlaneApiTokenStatus.REVOKED,
                revoked_at=now,
                updated_at=now,
                revision=current.revision + 1,
            )

        rotation = await self._repository.rotate_token(
            predecessor,
            successor,
            expected_revision=current.revision,
        )

        return ControlPlaneApiTokenGrant(
            metadata=rotation.successor,
            token=token,
        )

    async def disable_account(
        self,
        service_account_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> ControlPlaneServiceAccountRecord:
        """Disable one account and invalidate its active tokens."""

        self._require_open()

        current = await self._repository.get_account(service_account_id)

        if current is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        _require_service_account_revision(
            current.revision,
            expected_revision,
        )

        if current.status is ControlPlaneServiceAccountStatus.REVOKED:
            raise ControlPlaneServiceAccountConflictError(
                "revoked service account cannot be disabled"
            )

        if current.status is ControlPlaneServiceAccountStatus.DISABLED:
            await self.revoke_account_tokens(current.id)
            return current

        now = self._now()

        if now < current.updated_at:
            raise ControlPlaneServiceAccountConflictError("service-account clock moved backwards")

        disabled = replace(
            current,
            status=ControlPlaneServiceAccountStatus.DISABLED,
            disabled_at=now,
            revoked_at=None,
            updated_at=now,
            revision=current.revision + 1,
        )

        result = await self._repository.replace_account(
            disabled,
            expected_revision=current.revision,
        )

        await self.revoke_account_tokens(result.id)

        return result

    async def enable_account(
        self,
        service_account_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> ControlPlaneServiceAccountRecord:
        """Re-enable a disabled account only after token invalidation."""

        self._require_open()

        current = await self._repository.get_account(service_account_id)

        if current is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        _require_service_account_revision(
            current.revision,
            expected_revision,
        )

        if current.status is ControlPlaneServiceAccountStatus.REVOKED:
            raise ControlPlaneServiceAccountConflictError(
                "revoked service account cannot be enabled"
            )

        if current.status is ControlPlaneServiceAccountStatus.ACTIVE:
            return current

        await self.reconcile_expired_tokens(current.id)

        page = await self._repository.list_tokens(current.id)

        if any(token.status is ControlPlaneApiTokenStatus.ACTIVE for token in page.items):
            raise ControlPlaneServiceAccountConflictError(
                "disabled service account still has active API tokens"
            )

        latest = await self._repository.get_account(current.id)

        if latest is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        _require_service_account_revision(
            latest.revision,
            expected_revision,
        )

        if latest.status is not ControlPlaneServiceAccountStatus.DISABLED:
            raise ControlPlaneServiceAccountConflictError(
                "service-account state changed concurrently"
            )

        now = self._now()

        if now < latest.updated_at:
            raise ControlPlaneServiceAccountConflictError("service-account clock moved backwards")

        enabled = replace(
            latest,
            status=ControlPlaneServiceAccountStatus.ACTIVE,
            disabled_at=None,
            revoked_at=None,
            updated_at=now,
            revision=latest.revision + 1,
        )

        return await self._repository.replace_account(
            enabled,
            expected_revision=latest.revision,
        )

    async def revoke_account(
        self,
        service_account_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> ControlPlaneServiceAccountRecord:
        """Permanently revoke one account and all active tokens."""

        self._require_open()

        current = await self._repository.get_account(service_account_id)

        if current is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        _require_service_account_revision(
            current.revision,
            expected_revision,
        )

        if current.status is ControlPlaneServiceAccountStatus.REVOKED:
            await self.revoke_account_tokens(current.id)
            return current

        now = self._now()

        if now < current.updated_at:
            raise ControlPlaneServiceAccountConflictError("service-account clock moved backwards")

        revoked = replace(
            current,
            status=ControlPlaneServiceAccountStatus.REVOKED,
            disabled_at=None,
            revoked_at=now,
            updated_at=now,
            revision=current.revision + 1,
        )

        result = await self._repository.replace_account(
            revoked,
            expected_revision=current.revision,
        )

        await self.revoke_account_tokens(result.id)

        return result

    async def revoke_token(
        self,
        token_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> bool:
        """Revoke one active token by UUID."""

        self._require_open()

        current = await self._repository.get_token(token_id)

        if current is None:
            return False

        _require_api_token_revision(
            current.revision,
            expected_revision,
        )

        return await self._revoke_token_at(
            current,
            now=self._now(),
        )

    async def revoke_account_tokens(
        self,
        service_account_id: UUID,
    ) -> int:
        """Revoke every active unexpired token for one account."""

        self._require_open()

        account = await self._repository.get_account(service_account_id)

        if account is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        page = await self._repository.list_tokens(service_account_id)
        now = self._now()
        revoked = 0

        for current in page.items:
            if current.status is not ControlPlaneApiTokenStatus.ACTIVE:
                continue

            if now >= current.expires_at:
                await self._expire_token_at(
                    current,
                    now=now,
                )
                continue

            if await self._revoke_token_at(
                current,
                now=now,
            ):
                revoked += 1

        return revoked

    async def reconcile_expired_tokens(
        self,
        service_account_id: UUID,
    ) -> int:
        """Persist terminal expiry for elapsed active tokens."""

        self._require_open()

        account = await self._repository.get_account(service_account_id)

        if account is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        page = await self._repository.list_tokens(service_account_id)
        now = self._now()
        expired = 0

        for current in page.items:
            if await self._expire_token_at(
                current,
                now=now,
            ):
                expired += 1

        return expired

    async def _revoke_token_at(
        self,
        current: ControlPlaneApiTokenMetadata,
        *,
        now: datetime,
    ) -> bool:
        if current.status is not ControlPlaneApiTokenStatus.ACTIVE:
            return False

        if now < current.updated_at:
            raise ControlPlaneApiTokenConflictError("service-account clock moved backwards")

        if now >= current.expires_at:
            await self._expire_token_at(
                current,
                now=now,
            )
            return False

        replacement = replace(
            current,
            status=ControlPlaneApiTokenStatus.REVOKED,
            revoked_at=now,
            updated_at=now,
            revision=current.revision + 1,
        )

        try:
            await self._repository.replace_token(
                replacement,
                expected_revision=current.revision,
            )

        except ControlPlaneApiTokenConflictError:
            latest = await self._repository.get_token(current.id)

            if latest is not None and latest.status is not ControlPlaneApiTokenStatus.ACTIVE:
                return False

            raise

        return True

    async def _expire_token_at(
        self,
        current: ControlPlaneApiTokenMetadata,
        *,
        now: datetime,
    ) -> bool:
        if current.status is not ControlPlaneApiTokenStatus.ACTIVE or now < current.expires_at:
            return False

        if now < current.updated_at:
            raise ControlPlaneApiTokenConflictError("service-account clock moved backwards")

        replacement = replace(
            current,
            status=ControlPlaneApiTokenStatus.EXPIRED,
            revoked_at=None,
            updated_at=now,
            revision=current.revision + 1,
        )

        try:
            await self._repository.replace_token(
                replacement,
                expected_revision=current.revision,
            )

        except ControlPlaneApiTokenConflictError:
            latest = await self._repository.get_token(current.id)

            if latest is not None and latest.status is not ControlPlaneApiTokenStatus.ACTIVE:
                return False

            raise

        return True

    async def prune_terminal_token_history(
        self,
        service_account_id: UUID,
        *,
        retain: int = 8,
    ) -> int:
        """Remove old standalone terminal token metadata."""

        self._require_open()

        if isinstance(retain, bool) or not isinstance(
            retain,
            int,
        ):
            raise TypeError("terminal token retention must be int")

        if retain < 0 or retain > MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT:
            raise ValueError(
                "terminal token retention must be between zero and the per-account token maximum"
            )

        account = await self._repository.get_account(service_account_id)

        if account is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        await self.reconcile_expired_tokens(service_account_id)

        page = await self._repository.list_tokens(service_account_id)

        referenced_ids = frozenset(
            token.rotated_from for token in page.items if token.rotated_from is not None
        )

        eligible = tuple(
            sorted(
                (
                    token
                    for token in page.items
                    if (
                        token.status is not ControlPlaneApiTokenStatus.ACTIVE
                        and token.rotated_from is None
                        and token.id not in referenced_ids
                    )
                ),
                key=lambda token: (
                    token.updated_at,
                    token.issued_at,
                    token.id.hex,
                ),
                reverse=True,
            )
        )

        removed = 0

        for token in eligible[retain:]:
            await self._repository.delete_terminal_token(
                token.id,
                expected_revision=token.revision,
            )
            removed += 1

        return removed

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountLifecycleSnapshot:
        async with self._lock:
            return ControlPlaneServiceAccountLifecycleSnapshot(
                closed=self._closed,
                accounts_created=(self._accounts_created),
                accounts_updated=(self._accounts_updated),
                tokens_issued=self._tokens_issued,
            )

    async def close(self) -> None:
        """Close only this service; the repository remains borrowed."""

        async with self._lock:
            self._closed = True

    async def _increment(
        self,
        counter: str,
    ) -> None:
        async with self._lock:
            if counter == "accounts_created":
                self._accounts_created += 1
            elif counter == "accounts_updated":
                self._accounts_updated += 1
            elif counter == "tokens_issued":
                self._tokens_issued += 1
            else:
                raise AssertionError(f"unknown service-account lifecycle counter: {counter}")

    def _now(self) -> datetime:
        now = self._clock()

        if not isinstance(now, datetime):
            raise TypeError("service-account clock must return datetime")

        _require_aware(
            now,
            "service-account clock",
        )

        return now

    def _require_open(self) -> None:
        if self._closed:
            raise (
                ControlPlaneServiceAccountLifecycleClosedError(
                    "service-account lifecycle service is closed"
                )
            )

    @staticmethod
    def _new_uuid(
        factory: ControlPlaneServiceAccountIdFactory,
        *,
        label: str,
    ) -> UUID:
        value = factory()

        if not isinstance(value, UUID):
            raise TypeError(f"{label} id factory must return UUID")

        return value


def _require_aware(
    value: datetime,
    label: str,
) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
