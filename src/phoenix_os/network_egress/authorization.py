"""Fresh exact canonical authorization for controlled network egress."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC
from typing import Protocol, runtime_checkable

from phoenix_os.authority import (
    BUILTIN_AUTHORITY_CATALOG,
    AuthorityFreshnessBinding,
    AuthorityIntent,
)
from phoenix_os.authority.catalog import NETWORK_HTTP_REQUEST_ACTION as NETWORK_HTTP_REQUEST_ACTION
from phoenix_os.network_egress.contracts import NetworkHttpRequest
from phoenix_os.network_egress.profiles import (
    NetworkEgressOperation,
    NetworkEgressProfile,
)
from phoenix_os.policy import PhoenixPolicyError, PolicyEngine, PolicyRequest, SecurityContext


class _Digest(Protocol):
    def update(self, data: bytes) -> None: ...


class NetworkEgressAuthorizationRejectedError(RuntimeError):
    """Network authority failed closed without exposing policy or credential details."""

    def __init__(self) -> None:
        super().__init__("network egress request authorization failed")


@runtime_checkable
class NetworkEgressAuthorizer(Protocol):
    """Authorize one exact current network request intent.

    The returned AuthorityIntent is descriptive data, not a bearer capability.
    Callers must authorize again after later untrusted waits when freshness requires it.
    """

    async def authorize(
        self,
        request: NetworkHttpRequest,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        context: SecurityContext,
    ) -> AuthorityIntent: ...


def network_http_resource(
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
) -> str:
    """Return the exact generation-bound canonical network policy resource."""

    _require_profile_operation(profile, operation)
    return (
        f"network-egress:{profile.profile_id}"
        f"/generation:{profile.generation}"
        f"/operation:{operation.operation_id}"
    )


def network_http_parameter_digest(
    request: NetworkHttpRequest,
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
) -> str:
    """Digest exact effective request parameters without secret material or body bytes."""

    _require_exact_request_binding(request, profile, operation)

    digest = hashlib.sha256()
    _update_field(digest, "profile.id", str(profile.profile_id))
    _update_field(digest, "profile.generation", str(profile.generation))
    _update_field(digest, "profile.mode", profile.mode.value)
    _update_field(digest, "profile.host", profile.host)
    _update_field(digest, "profile.port", str(profile.port))
    _update_field(
        digest,
        "profile.allow_public_networks",
        "true" if profile.allow_public_networks else "false",
    )
    _update_sequence(digest, "profile.allowed_networks", profile.allowed_networks)

    credential = profile.credential
    if credential is None:
        _update_field(digest, "profile.credential", None)
    else:
        _update_field(digest, "profile.credential", "present")
        _update_field(digest, "credential.header_name", credential.header_name)
        _update_field(digest, "credential.secret_namespace", credential.secret_ref.namespace)
        _update_field(digest, "credential.secret_name", credential.secret_ref.name)
        _update_field(
            digest,
            "credential.secret_version",
            str(credential.secret_ref.version),
        )
        _update_field(digest, "credential.value_prefix", credential.value_prefix)

    _update_field(digest, "operation.id", str(operation.operation_id))
    _update_field(digest, "operation.method", operation.method.value)
    _update_field(digest, "operation.request_target", operation.request_target)
    _update_field(digest, "operation.effect", operation.effect.value)
    _update_field(
        digest,
        "operation.max_request_body_bytes",
        str(operation.limits.max_request_body_bytes),
    )
    _update_field(
        digest,
        "operation.max_response_body_bytes",
        str(operation.limits.max_response_body_bytes),
    )
    _update_field(
        digest,
        "operation.max_response_headers",
        str(operation.limits.max_response_headers),
    )
    _update_field(
        digest,
        "operation.max_response_header_bytes",
        str(operation.limits.max_response_header_bytes),
    )
    _update_field(
        digest,
        "operation.max_resolved_addresses",
        str(operation.limits.max_resolved_addresses),
    )
    _update_field(
        digest,
        "operation.connect_timeout_seconds",
        operation.limits.connect_timeout_seconds.hex(),
    )
    _update_field(
        digest,
        "operation.total_timeout_seconds",
        operation.limits.total_timeout_seconds.hex(),
    )
    _update_field(digest, "operation.accept", operation.accept)
    _update_field(digest, "operation.content_type", operation.content_type)
    _update_sequence(
        digest,
        "operation.exposed_response_headers",
        operation.exposed_response_headers,
    )

    _update_field(digest, "request.profile_id", str(request.profile_id))
    _update_field(digest, "request.operation_id", str(request.operation_id))
    _update_field(digest, "request.id", str(request.request_id))
    _update_field(
        digest,
        "request.created_at",
        request.created_at.astimezone(UTC).isoformat(timespec="microseconds"),
    )
    _update_field(digest, "request.body_bytes", str(len(request.body)))
    _update_field(digest, "request.body_digest", request.body_digest)

    return "sha256:" + digest.hexdigest()


def network_http_intent(
    request: NetworkHttpRequest,
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
) -> AuthorityIntent:
    """Resolve an exact catalog-valid network authority intent from trusted inputs."""

    _require_exact_request_binding(request, profile, operation)
    resource = network_http_resource(profile, operation)
    intent = AuthorityIntent(
        action=NETWORK_HTTP_REQUEST_ACTION,
        canonical_resource=resource,
        parameter_digest=network_http_parameter_digest(request, profile, operation),
        freshness_bindings=(
            AuthorityFreshnessBinding(
                "network.profile.generation",
                f"{profile.profile_id}:{profile.generation}",
            ),
        ),
    )
    try:
        BUILTIN_AUTHORITY_CATALOG.validate_intent(intent)
    except Exception as exception:
        raise NetworkEgressAuthorizationRejectedError() from exception
    return intent


class PolicyEngineNetworkEgressAuthorizer:
    """Apply fresh exact policy to one generation-bound network request intent."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize(
        self,
        request: NetworkHttpRequest,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        context: SecurityContext,
    ) -> AuthorityIntent:
        _require_authenticated_context(context)
        intent = network_http_intent(request, profile, operation)

        attributes = {
            "profile_id": str(profile.profile_id),
            "profile_generation": str(profile.generation),
            "operation_id": str(operation.operation_id),
            "operation_effect": operation.effect.value,
            "request_id": str(request.request_id),
            "request_body_bytes": str(len(request.body)),
            "request_body_digest": request.body_digest,
            "intent_parameter_digest": intent.parameter_digest,
        }
        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=NETWORK_HTTP_REQUEST_ACTION,
                    resource=intent.canonical_resource,
                    context=replace(context, confirmed=False),
                    attributes=attributes,
                    created_at=request.created_at,
                )
            )
        except PhoenixPolicyError as exception:
            raise NetworkEgressAuthorizationRejectedError() from exception
        return intent


def _require_profile_operation(
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
) -> None:
    if not isinstance(profile, NetworkEgressProfile):
        raise TypeError("profile must be NetworkEgressProfile")
    if not isinstance(operation, NetworkEgressOperation):
        raise TypeError("operation must be NetworkEgressOperation")
    try:
        configured = profile.require_operation(operation.operation_id)
    except KeyError as exception:
        raise NetworkEgressAuthorizationRejectedError() from exception
    if configured != operation:
        raise NetworkEgressAuthorizationRejectedError()


def _require_exact_request_binding(
    request: NetworkHttpRequest,
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
) -> None:
    if not isinstance(request, NetworkHttpRequest):
        raise TypeError("request must be NetworkHttpRequest")
    _require_profile_operation(profile, operation)
    if request.profile_id != profile.profile_id:
        raise NetworkEgressAuthorizationRejectedError()
    if request.operation_id != operation.operation_id:
        raise NetworkEgressAuthorizationRejectedError()
    if len(request.body) > operation.limits.max_request_body_bytes:
        raise NetworkEgressAuthorizationRejectedError()


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise NetworkEgressAuthorizationRejectedError()


def _update_sequence(
    digest: _Digest,
    label: str,
    values: tuple[str, ...],
) -> None:
    _update_field(digest, f"{label}.count", str(len(values)))
    for index, value in enumerate(values):
        _update_field(digest, f"{label}.{index}", value)


def _update_field(
    digest: _Digest,
    label: str,
    value: str | None,
) -> None:
    label_bytes = label.encode("utf-8")
    digest.update(len(label_bytes).to_bytes(2, "big"))
    digest.update(label_bytes)
    if value is None:
        digest.update(b"\x00")
        return
    data = value.encode("utf-8")
    digest.update(b"\x01")
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)
