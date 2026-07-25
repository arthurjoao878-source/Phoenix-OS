"""Policy-protected authenticated durable inbound event gateway."""

from __future__ import annotations

from collections.abc import Awaitable
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Protocol

from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.inbound_events.admission import (
    InboundAdmissionResult,
    InboundReplayIdempotencyService,
)
from phoenix_os.inbound_events.authentication import (
    InboundAuthenticationResult,
    InboundAuthenticationVerifier,
)
from phoenix_os.inbound_events.contracts import (
    InboundEventSource,
    InboundHmacPolicy,
    InboundSourceRepository,
)
from phoenix_os.inbound_events.errors import (
    InboundAdmissionLimiterClosedError,
    InboundAdmissionRejectedError,
    InboundAuthenticationRejectedError,
    InboundCorruptionError,
    InboundEventCapacityError,
    InboundEventRepositoryClosedError,
    InboundGatewayUnavailableError,
    InboundIdempotencyConflictError,
    InboundNormalizerError,
    InboundPayloadValidationError,
    InboundPersistenceError,
    InboundPolicyDeniedError,
    InboundReplayCapacityError,
    InboundReplayRejectedError,
    InboundReplayRepositoryClosedError,
    InboundSourceRepositoryClosedError,
)
from phoenix_os.inbound_events.http import (
    InboundHttpRequest,
    InboundHttpResponse,
)
from phoenix_os.inbound_events.limits import InboundAdmissionLimiter
from phoenix_os.inbound_events.schema import (
    InboundNormalizedEnvelope,
    InboundSchemaRegistry,
)
from phoenix_os.policy import (
    PhoenixPolicyError,
    PolicyConfirmationRequiredError,
    PolicyDecision,
    PolicyDeniedError,
    PolicyEngine,
    PolicyEngineClosedError,
    PolicyRequest,
    PrincipalType,
    SecurityContext,
)

INBOUND_SUBMIT_ACTION = "inbound_event.submit"


class InboundAdmissionPolicy(Protocol):
    """Central deny-by-default policy boundary before durable acceptance."""

    def enforce(
        self,
        authentication: InboundAuthenticationResult,
        source: InboundEventSource,
        envelope: InboundNormalizedEnvelope,
    ) -> Awaitable[object]: ...


class PolicyEngineInboundAdmissionPolicy:
    """Adapt the Phoenix Policy Engine to inbound submission decisions."""

    def __init__(self, engine: PolicyEngine) -> None:
        if not isinstance(engine, PolicyEngine):
            raise TypeError("inbound admission policy requires PolicyEngine")
        self._engine = engine

    async def enforce(
        self,
        authentication: InboundAuthenticationResult,
        source: InboundEventSource,
        envelope: InboundNormalizedEnvelope,
    ) -> PolicyDecision:
        if not isinstance(authentication, InboundAuthenticationResult):
            raise TypeError("inbound policy authentication is invalid")
        if not isinstance(source, InboundEventSource):
            raise TypeError("inbound policy source is invalid")
        if not isinstance(envelope, InboundNormalizedEnvelope):
            raise TypeError("inbound policy envelope is invalid")

        resource = (
            f"inbound-source:{source.name}"
            if isinstance(source.authentication, InboundHmacPolicy)
            else source.authentication.resource
        )
        context = SecurityContext(
            principal=authentication.principal,
            principal_type=PrincipalType.SERVICE,
            authenticated=True,
            attributes={
                "authentication_mode": authentication.mode.value,
                "source_id": str(source.id),
                "source_name": source.name,
            },
            correlation_id=None,
            causation_id=source.id,
        )
        request = PolicyRequest(
            action=INBOUND_SUBMIT_ACTION,
            resource=resource,
            context=context,
            attributes={
                "event_type": envelope.event_type,
                "event_schema_version": str(envelope.event_schema_version),
            },
        )
        try:
            return await self._engine.enforce(request)
        except (PolicyDeniedError, PolicyConfirmationRequiredError):
            raise InboundPolicyDeniedError from None
        except PolicyEngineClosedError:
            raise InboundGatewayUnavailableError("inbound policy engine is unavailable") from None
        except PhoenixPolicyError:
            raise InboundGatewayUnavailableError("inbound policy evaluation failed") from None


class InboundEventGateway:
    """Authenticate, normalize, authorize, and durably accept one request."""

    def __init__(
        self,
        *,
        sources: InboundSourceRepository,
        authentication: InboundAuthenticationVerifier,
        schemas: InboundSchemaRegistry,
        admission: InboundReplayIdempotencyService,
        policy: InboundAdmissionPolicy,
        limits: InboundAdmissionLimiter | None = None,
    ) -> None:
        if not callable(getattr(sources, "get", None)):
            raise TypeError("inbound gateway source repository is invalid")
        if not isinstance(authentication, InboundAuthenticationVerifier):
            raise TypeError("inbound gateway authentication verifier is invalid")
        if not isinstance(schemas, InboundSchemaRegistry):
            raise TypeError("inbound gateway schema registry is invalid")
        if not isinstance(admission, InboundReplayIdempotencyService):
            raise TypeError("inbound gateway admission service is invalid")
        if not callable(getattr(policy, "enforce", None)):
            raise TypeError("inbound gateway policy boundary is invalid")
        if limits is not None and not isinstance(limits, InboundAdmissionLimiter):
            raise TypeError("inbound gateway admission limiter is invalid")

        self._sources = sources
        self._authentication = authentication
        self._schemas = schemas
        self._admission = admission
        self._policy = policy
        self._limits = limits or InboundAdmissionLimiter()

    async def __call__(
        self,
        request: InboundHttpRequest,
        transport_context: object | None,
    ) -> InboundHttpResponse:
        return await self.handle(request, transport_context)

    async def handle(
        self,
        request: InboundHttpRequest,
        transport_context: object | None,
    ) -> InboundHttpResponse:
        if not isinstance(request, InboundHttpRequest):
            raise TypeError("inbound gateway request is invalid")

        try:
            lease = await self._limits.acquire(request.source)
            async with lease:
                current = await self._sources.get(request.source.id)
                source = (
                    current if current is not None and current.name == request.source.name else None
                )
                authentication = await self._authentication.verify(
                    source,
                    request.evidence,
                    request.body,
                    signature=request.signature,
                    key_version=request.key_version,
                    authorization=request.authorization,
                    service_account_context=_service_account_context(transport_context),
                    request_target=request.target,
                )
                if source is None:  # pragma: no cover - verifier always rejects
                    raise InboundAuthenticationRejectedError

                envelope = await self._schemas.parse_and_normalize(
                    source,
                    request.body,
                )
                await self._policy.enforce(
                    authentication,
                    source,
                    envelope,
                )

                latest = await self._sources.get(source.id)
                if (
                    latest is None
                    or latest.name != source.name
                    or latest.revision != source.revision
                    or not latest.accepting
                ):
                    raise InboundAuthenticationRejectedError

                result = await self._admission.admit(
                    latest,
                    request.evidence,
                    external_event_type=envelope.event_type,
                    external_schema_version=envelope.event_schema_version,
                    internal_event_type=envelope.internal_event_type,
                    occurred_at=envelope.occurred_at,
                    normalized_payload=envelope.normalized_payload,
                )
                return (
                    HTTPStatus.ACCEPTED,
                    inbound_receipt_to_dict(result),
                    {"Cache-Control": "no-store"},
                )
        except InboundAdmissionRejectedError:
            return _error(
                HTTPStatus.TOO_MANY_REQUESTS,
                "rate_limited",
                retry_after=True,
            )
        except (
            InboundAuthenticationRejectedError,
            InboundReplayRejectedError,
        ):
            return _error(HTTPStatus.UNAUTHORIZED, "unauthorized")
        except InboundPolicyDeniedError:
            return _error(HTTPStatus.FORBIDDEN, "forbidden")
        except InboundIdempotencyConflictError:
            return _error(HTTPStatus.CONFLICT, "conflict")
        except (
            InboundPayloadValidationError,
            InboundNormalizerError,
        ):
            return _error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "invalid_event",
            )
        except (
            InboundAdmissionLimiterClosedError,
            InboundGatewayUnavailableError,
            InboundCorruptionError,
            InboundEventCapacityError,
            InboundReplayCapacityError,
            InboundPersistenceError,
            InboundSourceRepositoryClosedError,
            InboundEventRepositoryClosedError,
            InboundReplayRepositoryClosedError,
        ):
            return _error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "service_unavailable",
            )


def inbound_receipt_to_dict(
    result: InboundAdmissionResult,
) -> dict[str, object]:
    """Serialize only the RFC-approved stable receipt fields."""

    if not isinstance(result, InboundAdmissionResult):
        raise TypeError("inbound receipt serialization requires admission result")
    receipt = result.receipt
    return {
        "schema_version": receipt.schema_version,
        "receipt_id": str(receipt.id),
        "accepted_event_id": str(receipt.accepted_event_id),
        "source_id": str(receipt.source_id),
        "source_event_id": receipt.source_event_id,
        "external_event_type": receipt.external_event_type,
        "external_schema_version": receipt.external_schema_version,
        "accepted_at": _format_timestamp(receipt.accepted_at),
        "status": "idempotent" if result.idempotent else "accepted",
        "correlation_id": receipt.correlation_id,
    }


def _service_account_context(
    value: object | None,
) -> ControlPlaneServiceAccountAuthenticationContext | None:
    return value if isinstance(value, ControlPlaneServiceAccountAuthenticationContext) else None


def _error(
    status: HTTPStatus,
    code: str,
    *,
    retry_after: bool = False,
) -> InboundHttpResponse:
    headers = {"Cache-Control": "no-store"}
    if retry_after:
        headers["Retry-After"] = "1"
    return status, {"error": code}, headers


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("inbound receipt timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
