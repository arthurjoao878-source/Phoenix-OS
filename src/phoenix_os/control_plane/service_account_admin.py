from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from phoenix_os.control_plane.auth import (
    ControlPlanePrincipal,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneApiTokenNotFoundError,
    ControlPlaneServiceAccountNotFoundError,
)
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_API_TOKENS_ISSUE_PERMISSION,
    CONTROL_PLANE_API_TOKENS_REVOKE_PERMISSION,
    CONTROL_PLANE_API_TOKENS_ROTATE_PERMISSION,
    CONTROL_PLANE_SERVICE_ACCOUNTS_CREATE_PERMISSION,
    CONTROL_PLANE_SERVICE_ACCOUNTS_DISABLE_PERMISSION,
    CONTROL_PLANE_SERVICE_ACCOUNTS_READ_PERMISSION,
    CONTROL_PLANE_SERVICE_ACCOUNTS_REVOKE_PERMISSION,
    CONTROL_PLANE_SERVICE_ACCOUNTS_UPDATE_PERMISSION,
)
from phoenix_os.control_plane.service_account_audit import (
    ControlPlaneServiceAccountAudit,
)
from phoenix_os.control_plane.service_account_contracts import (
    DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST,
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenPage,
    ControlPlaneApiTokenRestriction,
    ControlPlaneApiTokenRotation,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountPage,
    ControlPlaneServiceAccountPageInfo,
    ControlPlaneServiceAccountPageRequest,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountRepository,
    ControlPlaneServiceAccountStatus,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneApiTokenGrant,
    ControlPlaneServiceAccountLifecycleService,
)


class ControlPlaneServiceAccountAdministrationPermissionDeniedError(PermissionError):
    """Human operator lacks an exact administration permission."""

    def __init__(self) -> None:
        super().__init__("service-account administration permission denied")


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountView:
    """Allowlisted administrative service-account metadata."""

    service_account_id: UUID
    name: str
    display_name: str
    status: ControlPlaneServiceAccountStatus
    created_at: datetime
    updated_at: datetime
    disabled_at: datetime | None
    revoked_at: datetime | None
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(
            self.service_account_id,
            UUID,
        ):
            raise TypeError("service-account view id must be UUID")

        if self.revision <= 0:
            raise ValueError("service-account view revision must be positive")

        if self.created_at.tzinfo is None:
            raise ValueError("service-account view created_at must be timezone-aware")

        if self.updated_at.tzinfo is None:
            raise ValueError("service-account view updated_at must be timezone-aware")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account view schema version")

        object.__setattr__(
            self,
            "status",
            ControlPlaneServiceAccountStatus(self.status),
        )

    @classmethod
    def from_record(
        cls,
        record: ControlPlaneServiceAccountRecord,
    ) -> ControlPlaneServiceAccountView:
        if not isinstance(
            record,
            ControlPlaneServiceAccountRecord,
        ):
            raise TypeError("service-account view requires a service-account record")

        return cls(
            service_account_id=record.id,
            name=record.name,
            display_name=record.display_name,
            status=record.status,
            created_at=record.created_at,
            updated_at=record.updated_at,
            disabled_at=record.disabled_at,
            revoked_at=record.revoked_at,
            revision=record.revision,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneApiTokenView:
    """Credential-free API-token administration metadata."""

    token_id: UUID
    service_account_id: UUID
    label: str
    scopes: tuple[str, ...]
    resources: tuple[str, ...]
    allowed_client_networks: tuple[str, ...]
    mutual_tls_certificate_sha256: str | None
    status: ControlPlaneApiTokenStatus
    issued_at: datetime
    expires_at: datetime
    updated_at: datetime
    revoked_at: datetime | None
    rotated_from: UUID | None
    token_version: int
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(
            self.token_id,
            UUID,
        ) or not isinstance(
            self.service_account_id,
            UUID,
        ):
            raise TypeError("API-token view identities must be UUID")

        if self.token_version <= 0 or self.revision <= 0:
            raise ValueError("API-token view versions must be positive")

        if tuple(sorted(self.scopes)) != self.scopes:
            raise ValueError("API-token view scopes must be sorted")

        if tuple(sorted(self.resources)) != self.resources:
            raise ValueError("API-token view resources must be sorted")

        if tuple(sorted(self.allowed_client_networks)) != self.allowed_client_networks:
            raise ValueError("API-token view networks must be sorted")

        if self.schema_version != 1:
            raise ValueError("unsupported API-token view schema version")

        object.__setattr__(
            self,
            "status",
            ControlPlaneApiTokenStatus(self.status),
        )

    @classmethod
    def from_metadata(
        cls,
        metadata: ControlPlaneApiTokenMetadata,
    ) -> ControlPlaneApiTokenView:
        if not isinstance(
            metadata,
            ControlPlaneApiTokenMetadata,
        ):
            raise TypeError("API-token view requires metadata")

        return cls(
            token_id=metadata.id,
            service_account_id=(metadata.service_account_id),
            label=metadata.label,
            scopes=tuple(sorted(metadata.scopes)),
            resources=tuple(sorted(metadata.resources)),
            allowed_client_networks=tuple(sorted(metadata.restriction.allowed_client_networks)),
            mutual_tls_certificate_sha256=(metadata.restriction.mutual_tls_certificate_sha256),
            status=metadata.status,
            issued_at=metadata.issued_at,
            expires_at=metadata.expires_at,
            updated_at=metadata.updated_at,
            revoked_at=metadata.revoked_at,
            rotated_from=metadata.rotated_from,
            token_version=metadata.token_version,
            revision=metadata.revision,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountViewPage:
    """Bounded administrative account page."""

    items: tuple[
        ControlPlaneServiceAccountView,
        ...,
    ]
    page: ControlPlaneServiceAccountPageInfo
    schema_version: int = 1

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("service-account view page count does not match pagination")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account view page schema version")


@dataclass(frozen=True, slots=True)
class ControlPlaneApiTokenViewPage:
    """Bounded administrative API-token page."""

    items: tuple[
        ControlPlaneApiTokenView,
        ...,
    ]
    page: ControlPlaneServiceAccountPageInfo
    schema_version: int = 1

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("API-token view page count does not match pagination")

        if self.schema_version != 1:
            raise ValueError("unsupported API-token view page schema version")


class ControlPlaneServiceAccountAdministration:
    """Apply exact human permissions around lifecycle operations."""

    def __init__(
        self,
        *,
        repository: ControlPlaneServiceAccountRepository,
        lifecycle: (ControlPlaneServiceAccountLifecycleService),
        audit: ControlPlaneServiceAccountAudit,
    ) -> None:
        if not callable(
            getattr(
                repository,
                "list_accounts",
                None,
            )
        ):
            raise TypeError("service-account administration requires a repository")

        if not isinstance(
            lifecycle,
            ControlPlaneServiceAccountLifecycleService,
        ):
            raise TypeError("service-account administration requires a lifecycle service")

        if not isinstance(
            audit,
            ControlPlaneServiceAccountAudit,
        ):
            raise TypeError("service-account administration requires protected audit")

        self._repository = repository
        self._lifecycle = lifecycle
        self._audit = audit

    @property
    def repository(
        self,
    ) -> ControlPlaneServiceAccountRepository:
        return self._repository

    @property
    def lifecycle(
        self,
    ) -> ControlPlaneServiceAccountLifecycleService:
        return self._lifecycle

    @property
    def audit(
        self,
    ) -> ControlPlaneServiceAccountAudit:
        return self._audit

    async def list_accounts(
        self,
        actor: ControlPlanePrincipal,
        request: ControlPlaneServiceAccountPageRequest = (
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST
        ),
    ) -> ControlPlaneServiceAccountViewPage:
        self._require(
            actor,
            CONTROL_PLANE_SERVICE_ACCOUNTS_READ_PERMISSION,
        )

        page = await self._repository.list_accounts(request)

        return _account_page(page)

    async def list_tokens(
        self,
        actor: ControlPlanePrincipal,
        service_account_id: UUID,
        request: ControlPlaneServiceAccountPageRequest = (
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_REQUEST
        ),
    ) -> ControlPlaneApiTokenViewPage:
        self._require(
            actor,
            CONTROL_PLANE_SERVICE_ACCOUNTS_READ_PERMISSION,
        )

        await self._required_account(service_account_id)

        page = await self._repository.list_tokens(
            service_account_id,
            request,
        )

        return _token_page(page)

    async def create_account(
        self,
        actor: ControlPlanePrincipal,
        *,
        name: str,
        display_name: str,
    ) -> ControlPlaneServiceAccountView:
        self._require(
            actor,
            CONTROL_PLANE_SERVICE_ACCOUNTS_CREATE_PERMISSION,
        )

        record = await self._lifecycle.create_account(
            name=name,
            display_name=display_name,
        )

        await self._audit.account_created(record)

        return ControlPlaneServiceAccountView.from_record(record)

    async def update_account(
        self,
        actor: ControlPlanePrincipal,
        service_account_id: UUID,
        *,
        expected_revision: int,
        name: str | None = None,
        display_name: str | None = None,
    ) -> ControlPlaneServiceAccountView:
        self._require(
            actor,
            CONTROL_PLANE_SERVICE_ACCOUNTS_UPDATE_PERMISSION,
        )

        record = await self._lifecycle.update_account(
            service_account_id,
            expected_revision=expected_revision,
            name=name,
            display_name=display_name,
        )

        await self._audit.account_updated(record)

        return ControlPlaneServiceAccountView.from_record(record)

    async def issue_token(
        self,
        actor: ControlPlanePrincipal,
        service_account_id: UUID,
        *,
        label: str,
        scopes: frozenset[str],
        expires_at: datetime,
        resources: frozenset[str] = frozenset(
            {
                "*",
            }
        ),
        restriction: (ControlPlaneApiTokenRestriction | None) = None,
    ) -> ControlPlaneApiTokenGrant:
        self._require(
            actor,
            CONTROL_PLANE_API_TOKENS_ISSUE_PERMISSION,
        )

        grant = await self._lifecycle.issue_token(
            service_account_id,
            label=label,
            scopes=scopes,
            resources=resources,
            restriction=restriction,
            expires_at=expires_at,
        )

        await self._audit.token_issued(grant.metadata)

        return grant

    async def rotate_token(
        self,
        actor: ControlPlanePrincipal,
        token_id: UUID,
        *,
        expected_revision: int,
        expires_at: datetime,
        label: str | None = None,
        scopes: frozenset[str] | None = None,
        resources: frozenset[str] | None = None,
        restriction: (ControlPlaneApiTokenRestriction | None) = None,
        overlap: timedelta = timedelta(0),
    ) -> ControlPlaneApiTokenGrant:
        self._require(
            actor,
            CONTROL_PLANE_API_TOKENS_ROTATE_PERMISSION,
        )

        await self._required_token(token_id)

        grant = await self._lifecycle.rotate_token(
            token_id,
            expected_revision=expected_revision,
            expires_at=expires_at,
            label=label,
            scopes=scopes,
            resources=resources,
            restriction=restriction,
            overlap=overlap,
        )

        predecessor = await self._repository.get_token(token_id)

        if predecessor is None:
            raise RuntimeError("rotated API-token predecessor was not found")

        await self._audit.token_rotated(
            ControlPlaneApiTokenRotation(
                predecessor=predecessor,
                successor=grant.metadata,
            )
        )

        return grant

    async def disable_account(
        self,
        actor: ControlPlanePrincipal,
        service_account_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneServiceAccountView:
        self._require(
            actor,
            CONTROL_PLANE_SERVICE_ACCOUNTS_DISABLE_PERMISSION,
        )

        before = await self._required_account(service_account_id)

        result = await self._lifecycle.disable_account(
            service_account_id,
            expected_revision=expected_revision,
        )

        if result.revision != before.revision:
            await self._audit.account_disabled(result)

        return ControlPlaneServiceAccountView.from_record(result)

    async def enable_account(
        self,
        actor: ControlPlanePrincipal,
        service_account_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneServiceAccountView:
        self._require(
            actor,
            CONTROL_PLANE_SERVICE_ACCOUNTS_DISABLE_PERMISSION,
        )

        before = await self._required_account(service_account_id)

        result = await self._lifecycle.enable_account(
            service_account_id,
            expected_revision=expected_revision,
        )

        if result.revision != before.revision:
            await self._audit.account_enabled(result)

        return ControlPlaneServiceAccountView.from_record(result)

    async def revoke_account(
        self,
        actor: ControlPlanePrincipal,
        service_account_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneServiceAccountView:
        self._require(
            actor,
            CONTROL_PLANE_SERVICE_ACCOUNTS_REVOKE_PERMISSION,
        )

        before = await self._required_account(service_account_id)

        result = await self._lifecycle.revoke_account(
            service_account_id,
            expected_revision=expected_revision,
        )

        if result.revision != before.revision:
            await self._audit.account_revoked(result)

        return ControlPlaneServiceAccountView.from_record(result)

    async def revoke_token(
        self,
        actor: ControlPlanePrincipal,
        token_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneApiTokenView:
        self._require(
            actor,
            CONTROL_PLANE_API_TOKENS_REVOKE_PERMISSION,
        )

        before = await self._required_token(token_id)

        await self._lifecycle.revoke_token(
            token_id,
            expected_revision=expected_revision,
        )

        result = await self._required_token(token_id)

        if result.revision != before.revision:
            if result.status is ControlPlaneApiTokenStatus.REVOKED:
                await self._audit.token_revoked(result)
            elif result.status is ControlPlaneApiTokenStatus.EXPIRED:
                await self._audit.token_expired(result)

        return ControlPlaneApiTokenView.from_metadata(result)

    async def _required_account(
        self,
        service_account_id: UUID,
    ) -> ControlPlaneServiceAccountRecord:
        record = await self._repository.get_account(service_account_id)

        if record is None:
            raise ControlPlaneServiceAccountNotFoundError("service account was not found")

        return record

    async def _required_token(
        self,
        token_id: UUID,
    ) -> ControlPlaneApiTokenMetadata:
        metadata = await self._repository.get_token(token_id)

        if metadata is None:
            raise ControlPlaneApiTokenNotFoundError("API-token metadata was not found")

        return metadata

    @staticmethod
    def _require(
        actor: ControlPlanePrincipal,
        permission: str,
    ) -> None:
        if not isinstance(
            actor,
            ControlPlanePrincipal,
        ):
            raise TypeError("service-account administration requires an operator principal")

        if permission not in actor.permissions:
            raise (ControlPlaneServiceAccountAdministrationPermissionDeniedError())


def service_account_view_to_dict(
    view: ControlPlaneServiceAccountView,
) -> dict[str, object]:
    return {
        "schema_version": view.schema_version,
        "service_account_id": str(view.service_account_id),
        "name": view.name,
        "display_name": view.display_name,
        "status": view.status.value,
        "created_at": view.created_at.isoformat(),
        "updated_at": view.updated_at.isoformat(),
        "disabled_at": _optional_datetime(view.disabled_at),
        "revoked_at": _optional_datetime(view.revoked_at),
        "revision": view.revision,
    }


def api_token_view_to_dict(
    view: ControlPlaneApiTokenView,
) -> dict[str, object]:
    return {
        "schema_version": view.schema_version,
        "token_id": str(view.token_id),
        "service_account_id": str(view.service_account_id),
        "label": view.label,
        "scopes": list(view.scopes),
        "resources": list(view.resources),
        "restriction": {
            "allowed_client_networks": list(view.allowed_client_networks),
            "mutual_tls_certificate_sha256": (view.mutual_tls_certificate_sha256),
        },
        "status": view.status.value,
        "issued_at": view.issued_at.isoformat(),
        "expires_at": view.expires_at.isoformat(),
        "updated_at": view.updated_at.isoformat(),
        "revoked_at": _optional_datetime(view.revoked_at),
        "rotated_from": (None if view.rotated_from is None else str(view.rotated_from)),
        "token_version": view.token_version,
        "revision": view.revision,
    }


def service_account_view_page_to_dict(
    page: ControlPlaneServiceAccountViewPage,
) -> dict[str, object]:
    return {
        "schema_version": page.schema_version,
        "items": [service_account_view_to_dict(item) for item in page.items],
        "page": _page_to_dict(page.page),
    }


def api_token_view_page_to_dict(
    page: ControlPlaneApiTokenViewPage,
) -> dict[str, object]:
    return {
        "schema_version": page.schema_version,
        "items": [api_token_view_to_dict(item) for item in page.items],
        "page": _page_to_dict(page.page),
    }


def api_token_grant_to_dict(
    grant: ControlPlaneApiTokenGrant,
) -> dict[str, object]:
    """Serialize plaintext only for its one-time response."""

    if not isinstance(
        grant,
        ControlPlaneApiTokenGrant,
    ):
        raise TypeError("API-token grant serializer requires a trusted grant")

    return {
        "schema_version": grant.schema_version,
        "token": grant.token.value,
        "metadata": api_token_view_to_dict(ControlPlaneApiTokenView.from_metadata(grant.metadata)),
    }


def _account_page(
    page: ControlPlaneServiceAccountPage,
) -> ControlPlaneServiceAccountViewPage:
    return ControlPlaneServiceAccountViewPage(
        items=tuple(ControlPlaneServiceAccountView.from_record(item) for item in page.items),
        page=page.page,
    )


def _token_page(
    page: ControlPlaneApiTokenPage,
) -> ControlPlaneApiTokenViewPage:
    return ControlPlaneApiTokenViewPage(
        items=tuple(ControlPlaneApiTokenView.from_metadata(item) for item in page.items),
        page=page.page,
    )


def _page_to_dict(
    page: ControlPlaneServiceAccountPageInfo,
) -> dict[str, object]:
    return {
        "offset": page.offset,
        "limit": page.limit,
        "returned": page.returned,
        "total": page.total,
        "next_offset": page.next_offset,
    }


def _optional_datetime(
    value: datetime | None,
) -> str | None:
    return None if value is None else value.isoformat()
