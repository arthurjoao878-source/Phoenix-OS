"""Administrative bearer-token authentication for the local control plane."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

_CONTROL_PLANE_READ = "control-plane.read"


@dataclass(frozen=True, slots=True)
class ControlPlanePrincipal:
    """Authenticated administrative identity exposed only inside the transport."""

    name: str
    permissions: frozenset[str] = field(default_factory=lambda: frozenset({_CONTROL_PLANE_READ}))

    def __post_init__(self) -> None:
        normalized = self.name.strip()
        if not normalized:
            raise ValueError("control plane principal name must not be blank")
        permissions = frozenset(permission.strip() for permission in self.permissions)
        if not permissions or "" in permissions:
            raise ValueError("control plane permissions must not be blank")
        if _CONTROL_PLANE_READ not in permissions:
            raise ValueError("control plane principal requires control-plane.read")
        object.__setattr__(self, "name", normalized)
        object.__setattr__(self, "permissions", permissions)


class AdminTokenAuthenticator:
    """Authenticate one administrative bearer token without retaining plaintext."""

    def __init__(
        self,
        token: str,
        *,
        principal: ControlPlanePrincipal | None = None,
    ) -> None:
        if token != token.strip():
            raise ValueError("control plane token must not contain surrounding whitespace")
        if len(token) < 32:
            raise ValueError("control plane token must contain at least 32 characters")
        try:
            encoded = token.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError(
                "control plane token must contain ASCII characters only"
            ) from exception
        self._digest = hashlib.sha256(encoded).digest()
        self._principal = principal or ControlPlanePrincipal("phoenix.dashboard")

    @property
    def principal(self) -> ControlPlanePrincipal:
        return self._principal

    def authenticate(self, authorization: str | None) -> ControlPlanePrincipal | None:
        """Return the principal for an exact Bearer token or None on any mismatch."""

        if authorization is None:
            return None
        parts = authorization.split(" ", 1)
        if len(parts) != 2:
            return None
        scheme, token = parts
        if scheme.lower() != "bearer" or not token or token != token.strip():
            return None
        try:
            candidate = hashlib.sha256(token.encode("ascii")).digest()
        except UnicodeEncodeError:
            return None
        if not secrets.compare_digest(candidate, self._digest):
            return None
        return self._principal
