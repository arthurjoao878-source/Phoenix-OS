from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
)

_MAX_ACTION_LENGTH = 128
_MAX_RESOURCE_LENGTH = 256


class ControlPlaneServiceAccountPermissionDeniedError(PermissionError):
    """Generic service-account authorization rejection."""


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountAuthorization:
    """Safe exact scope-and-resource authorization decision."""

    action: str
    resource: str
    allowed: bool
    schema_version: int = 1

    def __post_init__(self) -> None:
        action = _normalize_action(self.action)
        resource = _normalize_resource(self.resource)

        if not isinstance(self.allowed, bool):
            raise TypeError("service-account authorization allowed flag must be bool")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account authorization schema version")

        object.__setattr__(
            self,
            "action",
            action,
        )
        object.__setattr__(
            self,
            "resource",
            resource,
        )


class ControlPlaneServiceAccountAuthorizer:
    """Require an exact action scope and an allowed resource."""

    def decide(
        self,
        authentication: (ControlPlaneServiceAccountAuthentication),
        *,
        action: str,
        resource: str,
    ) -> ControlPlaneServiceAccountAuthorization:
        if not isinstance(
            authentication,
            ControlPlaneServiceAccountAuthentication,
        ):
            raise TypeError(
                "service-account authorization requires service-account authentication evidence"
            )

        normalized_action = _normalize_action(action)
        normalized_resource = _normalize_resource(resource)

        scope_allowed = normalized_action in authentication.scopes
        resource_allowed = _resource_allowed(
            normalized_resource,
            authentication.resources,
        )

        return ControlPlaneServiceAccountAuthorization(
            action=normalized_action,
            resource=normalized_resource,
            allowed=(scope_allowed and resource_allowed),
        )

    def require(
        self,
        authentication: (ControlPlaneServiceAccountAuthentication),
        *,
        action: str,
        resource: str,
    ) -> ControlPlaneServiceAccountAuthorization:
        decision = self.decide(
            authentication,
            action=action,
            resource=resource,
        )

        if not decision.allowed:
            raise (
                ControlPlaneServiceAccountPermissionDeniedError(
                    "service-account authorization denied"
                )
            )

        return decision


def _normalize_action(
    value: str,
) -> str:
    if not isinstance(value, str):
        raise TypeError("service-account action must be str")

    normalized = value.strip().lower()

    if (
        not normalized
        or normalized != value
        or len(normalized) > _MAX_ACTION_LENGTH
        or "*" in normalized
        or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in normalized
        )
    ):
        raise ValueError("service-account action must be canonical and concrete")

    return normalized


def _normalize_resource(
    value: str,
) -> str:
    if not isinstance(value, str):
        raise TypeError("service-account resource must be str")

    normalized = value.strip()

    if (
        not normalized
        or normalized != value
        or len(normalized) > _MAX_RESOURCE_LENGTH
        or "*" in normalized
        or normalized.endswith(":")
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise ValueError("service-account authorization requires one canonical concrete resource")

    return normalized


def _resource_allowed(
    resource: str,
    grants: frozenset[str],
) -> bool:
    for grant in grants:
        if grant == "*":
            return True

        if grant == resource:
            return True

        if grant.endswith(":*") and grant.count("*") == 1:
            prefix = grant[:-1]

            if resource.startswith(prefix) and len(resource) > len(prefix):
                return True

    return False
