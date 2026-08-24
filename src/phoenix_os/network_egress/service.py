"""Fresh fail-closed service orchestration for controlled network egress."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, TypeVar, runtime_checkable

from phoenix_os.authority import AuthorityFreshnessValidator, AuthorityIntent
from phoenix_os.network_egress._admission import (
    NetworkDestinationAdmission,
    NetworkResolver,
    admit_network_destination,
    resolve_and_admit_network_destination,
)
from phoenix_os.network_egress._errors import (
    NetworkDestinationRejectedError,
    NetworkTransportError,
)
from phoenix_os.network_egress._transport import (
    NetworkTransport,
    NetworkTransportResponse,
    NetworkTransportSession,
)
from phoenix_os.network_egress.authorization import (
    NetworkEgressAuthorizer,
    network_http_intent,
)
from phoenix_os.network_egress.contracts import (
    NetworkEgressProfileId,
    NetworkHttpRequest,
    NetworkHttpResponse,
)
from phoenix_os.network_egress.profiles import (
    NetworkEgressOperation,
    NetworkEgressProfile,
)
from phoenix_os.policy import SecurityContext
from phoenix_os.secrets import SecretLease, SecretsManager

MAX_NETWORK_CONCURRENT_REQUESTS = 1_024

_T = TypeVar("_T")


class NetworkEgressFailureKind(StrEnum):
    """Sanitized terminal class for one service attempt."""

    REJECTED = "rejected"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class NetworkEgressRequestError(RuntimeError):
    """Sanitized service error that never includes destination or credential detail."""

    def __init__(
        self,
        kind: NetworkEgressFailureKind,
        *,
        request_started: bool,
    ) -> None:
        resolved = NetworkEgressFailureKind(kind)
        if not isinstance(request_started, bool):
            raise TypeError("request_started must be a boolean")
        self.kind = resolved
        self.request_started = request_started
        super().__init__(f"network egress request {resolved.value}")


@dataclass(frozen=True, slots=True)
class NetworkEgressServiceLimits:
    """Finite concurrency limits for service-owned network attempts."""

    max_concurrent_requests: int = 32

    def __post_init__(self) -> None:
        value = self.max_concurrent_requests
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("max_concurrent_requests must be an integer")
        if not 1 <= value <= MAX_NETWORK_CONCURRENT_REQUESTS:
            raise ValueError("max_concurrent_requests is outside supported bounds")


class NetworkEgressCancellationToken:
    """Idempotent cooperative cancellation signal for one network request."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.CANCELLED,
                request_started=False,
            )


@runtime_checkable
class NetworkEgressProfileSource(Protocol):
    """Resolve the current trusted immutable profile by structural profile identity."""

    def require_profile(
        self,
        profile_id: NetworkEgressProfileId,
    ) -> NetworkEgressProfile: ...


@dataclass(frozen=True, slots=True)
class _EffectiveDeadline:
    wall_clock: datetime
    monotonic: float


def _utc_now() -> datetime:
    return datetime.now(UTC)


class NetworkEgressService:
    """Compose profile, authority, freshness, secret, DNS, and pinned transport boundaries."""

    def __init__(
        self,
        *,
        profiles: NetworkEgressProfileSource,
        authorizer: NetworkEgressAuthorizer,
        freshness: AuthorityFreshnessValidator,
        secrets: SecretsManager | None = None,
        resolver: NetworkResolver | None = None,
        transport: NetworkTransport | None = None,
        limits: NetworkEgressServiceLimits | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(profiles, NetworkEgressProfileSource):
            raise TypeError("profiles must implement NetworkEgressProfileSource")
        if not isinstance(authorizer, NetworkEgressAuthorizer):
            raise TypeError("authorizer must implement NetworkEgressAuthorizer")
        if not isinstance(freshness, AuthorityFreshnessValidator):
            raise TypeError("freshness must implement AuthorityFreshnessValidator")
        if secrets is not None and not isinstance(secrets, SecretsManager):
            raise TypeError("secrets must be SecretsManager or None")
        if resolver is not None and not callable(getattr(resolver, "resolve", None)):
            raise TypeError("resolver must implement NetworkResolver")
        if transport is not None and not isinstance(transport, NetworkTransport):
            raise TypeError("transport must be NetworkTransport or None")
        resolved_limits = NetworkEgressServiceLimits() if limits is None else limits
        if not isinstance(resolved_limits, NetworkEgressServiceLimits):
            raise TypeError("limits must be NetworkEgressServiceLimits")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")

        self._profiles = profiles
        self._authorizer = authorizer
        self._freshness = freshness
        self._secrets = secrets
        self._resolver = resolver
        self._transport = NetworkTransport() if transport is None else transport
        self._limits = resolved_limits
        self._clock: Callable[[], datetime] = _utc_now if clock is None else clock
        self._active = 0
        self._active_lock = asyncio.Lock()

    @property
    def limits(self) -> NetworkEgressServiceLimits:
        return self._limits

    async def request(
        self,
        request: NetworkHttpRequest,
        context: SecurityContext,
        *,
        cancellation: NetworkEgressCancellationToken | None = None,
        deadline: datetime | None = None,
    ) -> NetworkHttpResponse:
        if not isinstance(request, NetworkHttpRequest):
            raise TypeError("request must be NetworkHttpRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        token = NetworkEgressCancellationToken() if cancellation is None else cancellation
        if not isinstance(token, NetworkEgressCancellationToken):
            raise TypeError("cancellation must be NetworkEgressCancellationToken")
        self._validate_requested_deadline(deadline)

        await self._acquire_slot()
        try:
            return await self._request_admitted(
                request,
                context,
                cancellation=token,
                requested_deadline=deadline,
            )
        finally:
            await self._release_slot()

    async def _request_admitted(
        self,
        request: NetworkHttpRequest,
        context: SecurityContext,
        *,
        cancellation: NetworkEgressCancellationToken,
        requested_deadline: datetime | None,
    ) -> NetworkHttpResponse:
        profile, operation = self._resolve_request(request)
        effective_deadline = self._effective_deadline(
            operation,
            requested_deadline=requested_deadline,
        )

        self._require_pre_send(cancellation, effective_deadline)
        await self._validate_freshness(context, cancellation, effective_deadline)
        self._require_current(profile, operation, request)
        await self._authorize(
            request,
            profile,
            operation,
            context,
            cancellation,
            effective_deadline,
        )
        self._require_current(profile, operation, request)

        lease = await self._lease_credential(
            profile,
            context,
            cancellation,
            effective_deadline,
        )
        self._require_pre_send(cancellation, effective_deadline)
        self._require_current(profile, operation, request)

        admission = await self._resolve_destination(
            profile,
            operation,
            cancellation,
            effective_deadline,
        )
        self._require_pre_send(cancellation, effective_deadline)
        self._require_current_admission(profile, operation, request, admission)

        session = await self._open_session(
            profile,
            operation,
            admission,
            cancellation,
            effective_deadline,
        )
        try:
            self._require_pre_send(cancellation, effective_deadline)
            self._require_current_admission(profile, operation, request, admission)

            final_lease = await self._resolve_credential_lease(
                profile,
                lease,
                context,
                cancellation,
                effective_deadline,
            )
            self._require_current_admission(profile, operation, request, admission)

            await self._validate_freshness(context, cancellation, effective_deadline)
            self._require_current_admission(profile, operation, request, admission)

            await self._authorize(
                request,
                profile,
                operation,
                context,
                cancellation,
                effective_deadline,
            )
            self._require_pre_send(cancellation, effective_deadline)
            self._require_current_admission(profile, operation, request, admission)

            credential_value: bytes | None = None
            if final_lease is not None:
                try:
                    credential_value = final_lease.value.reveal(bytes)
                except Exception:
                    raise NetworkEgressRequestError(
                        NetworkEgressFailureKind.REJECTED,
                        request_started=False,
                    ) from None

            try:
                transport_response = await self._exchange(
                    session,
                    request,
                    credential_value=credential_value,
                    deadline=effective_deadline,
                )
            finally:
                credential_value = None

            try:
                return self._public_response(request, transport_response)
            except Exception:
                raise NetworkEgressRequestError(
                    NetworkEgressFailureKind.INDETERMINATE,
                    request_started=True,
                ) from None
        finally:
            if not session.closed:
                try:
                    await session.aclose()
                except Exception:
                    pass

    async def _validate_freshness(
        self,
        context: SecurityContext,
        cancellation: NetworkEgressCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        try:
            await self._await_pre_send(
                self._freshness.validate(context),
                cancellation=cancellation,
                deadline=deadline,
            )
        except NetworkEgressRequestError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            ) from None

    async def _authorize(
        self,
        request: NetworkHttpRequest,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        context: SecurityContext,
        cancellation: NetworkEgressCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> AuthorityIntent:
        try:
            intent = await self._await_pre_send(
                self._authorizer.authorize(request, profile, operation, context),
                cancellation=cancellation,
                deadline=deadline,
            )
            expected = network_http_intent(request, profile, operation)
        except NetworkEgressRequestError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            ) from None
        if intent != expected:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            )
        return intent

    async def _lease_credential(
        self,
        profile: NetworkEgressProfile,
        context: SecurityContext,
        cancellation: NetworkEgressCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> SecretLease | None:
        credential = profile.credential
        if credential is None:
            return None
        manager = self._secrets
        if manager is None:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            )

        ttl = timedelta(seconds=self._remaining_seconds(deadline))
        try:
            lease = await self._await_pre_send(
                manager.lease(credential.secret_ref, context, ttl=ttl),
                cancellation=cancellation,
                deadline=deadline,
            )
        except NetworkEgressRequestError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            ) from None
        if lease.ref != credential.secret_ref or lease.principal != context.principal:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            )
        return lease

    async def _resolve_credential_lease(
        self,
        profile: NetworkEgressProfile,
        lease: SecretLease | None,
        context: SecurityContext,
        cancellation: NetworkEgressCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> SecretLease | None:
        credential = profile.credential
        if credential is None:
            if lease is not None:
                raise NetworkEgressRequestError(
                    NetworkEgressFailureKind.REJECTED,
                    request_started=False,
                )
            return None

        manager = self._secrets
        if manager is None or lease is None:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            )
        try:
            current = await self._await_pre_send(
                manager.resolve_lease(lease.id, context),
                cancellation=cancellation,
                deadline=deadline,
            )
        except NetworkEgressRequestError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            ) from None
        if (
            current.id != lease.id
            or current.ref != credential.secret_ref
            or current.principal != context.principal
        ):
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            )
        return current

    async def _resolve_destination(
        self,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        cancellation: NetworkEgressCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> NetworkDestinationAdmission:
        try:
            return await self._await_pre_send(
                resolve_and_admit_network_destination(
                    profile,
                    operation,
                    resolver=self._resolver,
                ),
                cancellation=cancellation,
                deadline=deadline,
            )
        except NetworkEgressRequestError:
            raise
        except asyncio.CancelledError:
            raise
        except NetworkDestinationRejectedError:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            ) from None
        except NetworkTransportError:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.FAILED,
                request_started=False,
            ) from None
        except Exception:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.FAILED,
                request_started=False,
            ) from None

    async def _open_session(
        self,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        admission: NetworkDestinationAdmission,
        cancellation: NetworkEgressCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> NetworkTransportSession:
        try:
            return await self._await_pre_send(
                self._transport.open_session(profile, operation, admission),
                cancellation=cancellation,
                deadline=deadline,
            )
        except NetworkEgressRequestError:
            raise
        except asyncio.CancelledError:
            raise
        except NetworkDestinationRejectedError:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            ) from None
        except NetworkTransportError:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.FAILED,
                request_started=False,
            ) from None
        except Exception:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.FAILED,
                request_started=False,
            ) from None

    async def _exchange(
        self,
        session: NetworkTransportSession,
        request: NetworkHttpRequest,
        *,
        credential_value: bytes | None,
        deadline: _EffectiveDeadline,
    ) -> NetworkTransportResponse:
        remaining = self._remaining_seconds(deadline)
        try:
            async with asyncio.timeout(remaining):
                return await session.exchange(
                    request,
                    credential_value=credential_value,
                )
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            started = session.request_started
            raise NetworkEgressRequestError(
                (
                    NetworkEgressFailureKind.INDETERMINATE
                    if started
                    else NetworkEgressFailureKind.TIMED_OUT
                ),
                request_started=started,
            ) from None
        except NetworkDestinationRejectedError:
            started = session.request_started
            raise NetworkEgressRequestError(
                (
                    NetworkEgressFailureKind.INDETERMINATE
                    if started
                    else NetworkEgressFailureKind.REJECTED
                ),
                request_started=started,
            ) from None
        except NetworkTransportError as exception:
            started = exception.request_started or session.request_started
            raise NetworkEgressRequestError(
                (
                    NetworkEgressFailureKind.INDETERMINATE
                    if started
                    else NetworkEgressFailureKind.FAILED
                ),
                request_started=started,
            ) from None
        except Exception:
            started = session.request_started
            raise NetworkEgressRequestError(
                (
                    NetworkEgressFailureKind.INDETERMINATE
                    if started
                    else NetworkEgressFailureKind.FAILED
                ),
                request_started=started,
            ) from None

    async def _await_pre_send(
        self,
        awaitable: Awaitable[_T],
        *,
        cancellation: NetworkEgressCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> _T:
        self._require_pre_send(cancellation, deadline)
        remaining = self._remaining_seconds(deadline)
        worker = asyncio.ensure_future(awaitable)
        cancellation_waiter = asyncio.create_task(cancellation.wait())
        try:
            done, _pending = await asyncio.wait(
                {worker, cancellation_waiter},
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancellation_waiter in done:
                await self._abandon_pre_send_worker(worker)
                raise NetworkEgressRequestError(
                    NetworkEgressFailureKind.CANCELLED,
                    request_started=False,
                )
            if worker not in done:
                await self._abandon_pre_send_worker(worker)
                raise NetworkEgressRequestError(
                    NetworkEgressFailureKind.TIMED_OUT,
                    request_started=False,
                )
            return worker.result()
        except asyncio.CancelledError:
            await self._abandon_pre_send_worker(worker)
            raise
        finally:
            if not cancellation_waiter.done():
                cancellation_waiter.cancel()
            await asyncio.gather(cancellation_waiter, return_exceptions=True)

    async def _abandon_pre_send_worker(
        self,
        worker: asyncio.Future[_T],
    ) -> None:
        if not worker.done():
            worker.cancel()
        result = (await asyncio.gather(worker, return_exceptions=True))[0]
        if isinstance(result, NetworkTransportSession) and not result.closed:
            try:
                await result.aclose()
            except Exception:
                pass

    def _resolve_request(
        self,
        request: NetworkHttpRequest,
    ) -> tuple[NetworkEgressProfile, NetworkEgressOperation]:
        try:
            profile = self._profiles.require_profile(request.profile_id)
            operation = profile.require_operation(request.operation_id)
        except Exception:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            ) from None
        if not isinstance(profile, NetworkEgressProfile) or not isinstance(
            operation,
            NetworkEgressOperation,
        ):
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            )
        return profile, operation

    def _require_current(
        self,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        request: NetworkHttpRequest,
    ) -> None:
        current_profile, current_operation = self._resolve_request(request)
        if current_profile != profile or current_operation != operation:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            )

    def _require_current_admission(
        self,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        request: NetworkHttpRequest,
        admission: NetworkDestinationAdmission,
    ) -> None:
        self._require_current(profile, operation, request)
        try:
            expected = admit_network_destination(
                profile,
                operation,
                admission.addresses,
            )
        except Exception:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            ) from None
        if expected != admission:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.REJECTED,
                request_started=False,
            )

    def _effective_deadline(
        self,
        operation: NetworkEgressOperation,
        *,
        requested_deadline: datetime | None,
    ) -> _EffectiveDeadline:
        started = self._now()
        operation_deadline = started + operation.limits.total_timeout
        wall_clock = (
            operation_deadline
            if requested_deadline is None
            else min(operation_deadline, requested_deadline)
        )
        seconds = (wall_clock - started).total_seconds()
        if seconds <= 0:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.TIMED_OUT,
                request_started=False,
            )
        return _EffectiveDeadline(
            wall_clock=wall_clock,
            monotonic=asyncio.get_running_loop().time() + seconds,
        )

    def _remaining_seconds(self, deadline: _EffectiveDeadline) -> float:
        wall_remaining = (deadline.wall_clock - self._now()).total_seconds()
        monotonic_remaining = deadline.monotonic - asyncio.get_running_loop().time()
        remaining = min(wall_remaining, monotonic_remaining)
        if remaining <= 0:
            raise NetworkEgressRequestError(
                NetworkEgressFailureKind.TIMED_OUT,
                request_started=False,
            )
        return remaining

    def _require_pre_send(
        self,
        cancellation: NetworkEgressCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        cancellation.raise_if_cancelled()
        self._remaining_seconds(deadline)

    def _validate_requested_deadline(self, deadline: datetime | None) -> None:
        if deadline is None:
            return
        if not isinstance(deadline, datetime):
            raise TypeError("deadline must be datetime or None")
        if deadline.tzinfo is None or deadline.utcoffset() is None:
            raise ValueError("deadline must be timezone-aware")

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("clock result must be datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock result must be timezone-aware")
        return value

    async def _acquire_slot(self) -> None:
        async with self._active_lock:
            if self._active >= self._limits.max_concurrent_requests:
                raise NetworkEgressRequestError(
                    NetworkEgressFailureKind.REJECTED,
                    request_started=False,
                )
            self._active += 1

    async def _release_slot(self) -> None:
        async with self._active_lock:
            if self._active <= 0:
                raise RuntimeError("network egress active request count is inconsistent")
            self._active -= 1

    def _public_response(
        self,
        request: NetworkHttpRequest,
        response: NetworkTransportResponse,
    ) -> NetworkHttpResponse:
        return NetworkHttpResponse(
            request_id=request.request_id,
            profile_id=request.profile_id,
            operation_id=request.operation_id,
            status_code=response.status_code,
            body=response.body,
            headers=response.headers,
            created_at=self._now(),
        )
