"""Configuration adapters for safe SecretRef resolution."""

from __future__ import annotations

from datetime import timedelta

from phoenix_os.configuration import ConfigTypeError, Configuration
from phoenix_os.policy import SecurityContext
from phoenix_os.secrets.contracts import SecretLease, SecretRef
from phoenix_os.secrets.manager import SecretsManager


def parse_secret_ref(value: object) -> SecretRef:
    """Decode ``namespace/name`` or ``namespace/name#version`` without resolving material."""

    if not isinstance(value, str):
        raise ConfigTypeError("secret reference must be a string")
    raw = value.strip()
    if not raw:
        raise ConfigTypeError("secret reference must not be blank")
    path, separator, version_text = raw.partition("#")
    namespace, slash, name = path.partition("/")
    if not slash or not namespace or not name:
        raise ConfigTypeError("secret reference must use namespace/name")
    version: int | None = None
    if separator:
        try:
            version = int(version_text)
        except ValueError as exception:
            raise ConfigTypeError("secret reference version must be an integer") from exception
    try:
        return SecretRef(name=name, namespace=namespace, version=version)
    except ValueError as exception:
        raise ConfigTypeError(str(exception)) from exception


class SecretConfigResolver:
    """Resolve a configured SecretRef into a temporary lease on demand."""

    def __init__(self, manager: SecretsManager, context: SecurityContext) -> None:
        self._manager = manager
        self._context = context

    async def lease(
        self,
        configuration: Configuration,
        key: str,
        *,
        ttl: timedelta | None = None,
    ) -> SecretLease:
        ref = configuration.value(key, SecretRef)
        return await self._manager.lease(ref, self._context, ttl=ttl)
