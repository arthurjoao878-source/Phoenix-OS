"""Exact deny-by-default authorization for RFC-0039 registered development checkouts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.checkout_workspace import (
    MAX_CHECKOUT_LIST_ENTRIES,
    RegisteredDevelopmentCheckout,
    checkout_path_resource,
    checkout_prefix_resource,
)
from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
)
from phoenix_os.policy import PhoenixPolicyError, PolicyEngine, PolicyRequest, SecurityContext


@dataclass(frozen=True, slots=True)
class CheckoutListAuthorizationRequest:
    """Exact current-run list authorization request without exposing a native root."""

    run_id: AgentRunId
    registration: RegisteredDevelopmentCheckout
    prefix: str
    max_entries: int
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.registration, RegisteredDevelopmentCheckout):
            raise TypeError("registration must be RegisteredDevelopmentCheckout")
        checkout_prefix_resource(self.registration, self.prefix)
        if (
            isinstance(self.max_entries, bool)
            or not isinstance(self.max_entries, int)
            or not 1 <= self.max_entries <= MAX_CHECKOUT_LIST_ENTRIES
        ):
            raise ValueError("max_entries is out of bounds")
        _require_timestamp(self.created_at)


@dataclass(frozen=True, slots=True)
class CheckoutReadAuthorizationRequest:
    """Exact current-run read authorization request without exposing a native root."""

    run_id: AgentRunId
    registration: RegisteredDevelopmentCheckout
    logical_path: str
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.registration, RegisteredDevelopmentCheckout):
            raise TypeError("registration must be RegisteredDevelopmentCheckout")
        checkout_path_resource(self.registration, self.logical_path)
        _require_timestamp(self.created_at)


@runtime_checkable
class CheckoutWorkspaceAuthorizer(Protocol):
    """Authorize exact checkout list/read operations without touching native paths or bytes."""

    async def authorize_list(
        self,
        request: CheckoutListAuthorizationRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_read(
        self,
        request: CheckoutReadAuthorizationRequest,
        context: SecurityContext,
    ) -> None: ...


class PolicyEngineCheckoutWorkspaceAuthorizer:
    """Apply fresh exact policy to every registered checkout read operation."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    async def authorize_list(
        self,
        request: CheckoutListAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, CheckoutListAuthorizationRequest):
            raise TypeError("request must be CheckoutListAuthorizationRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=WORKSPACE_LIST_ACTION,
            resource=checkout_prefix_resource(request.registration, request.prefix),
            context=context,
            attributes={
                **_registration_attributes(request.registration),
                "run_id": str(request.run_id),
                "prefix_digest": _logical_identity_digest(request.prefix),
                "max_entries": str(request.max_entries),
            },
            created_at=request.created_at,
        )

    async def authorize_read(
        self,
        request: CheckoutReadAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, CheckoutReadAuthorizationRequest):
            raise TypeError("request must be CheckoutReadAuthorizationRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=WORKSPACE_READ_ACTION,
            resource=checkout_path_resource(
                request.registration,
                request.logical_path,
            ),
            context=context,
            attributes={
                **_registration_attributes(request.registration),
                "run_id": str(request.run_id),
                "logical_path_digest": _logical_identity_digest(request.logical_path),
            },
            created_at=request.created_at,
        )

    async def _enforce(
        self,
        *,
        action: str,
        resource: str,
        context: SecurityContext,
        attributes: dict[str, str],
        created_at: datetime,
    ) -> None:
        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=action,
                    resource=resource,
                    context=context,
                    attributes=attributes,
                    created_at=created_at,
                )
            )
        except PhoenixPolicyError as exception:
            raise AgentAuthorizationRejectedError() from exception


def _registration_attributes(
    registration: RegisteredDevelopmentCheckout,
) -> dict[str, str]:
    if not isinstance(registration, RegisteredDevelopmentCheckout):
        raise TypeError("registration must be RegisteredDevelopmentCheckout")
    return {
        "checkout_workspace_id": str(registration.workspace_id),
        "checkout_registration_generation": str(registration.generation),
    }


def _logical_identity_digest(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("logical identity must be a string")
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise AgentAuthorizationRejectedError()


def _require_timestamp(value: datetime) -> None:
    if not isinstance(value, datetime):
        raise TypeError("created_at must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("created_at must be timezone-aware")
