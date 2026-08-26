"""Canonical S4 browser sessions, page reads, and stale-safe local fill effects."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, TypeVar, cast, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.authority import AuthorityFreshnessValidator, AuthorityIntent
from phoenix_os.browser_automation.adapter import (
    BrowserAdapter,
    BrowserAdapterCommitResult,
    BrowserNavigationCommitResult,
    BrowserPreparedEffect,
    BrowserPreparedEffectKind,
    BrowserPreparedNavigation,
    BrowserPreparedNavigationPlan,
)
from phoenix_os.browser_automation.authorization import (
    BrowserAuthorizer,
    browser_element_fill_intent,
    browser_page_navigate_intent,
    browser_page_read_intent,
    browser_session_close_intent,
    browser_session_open_intent,
)
from phoenix_os.browser_automation.contracts import (
    MAX_BROWSER_PAGE_REVISION,
    BrowserAdapterId,
    BrowserElementId,
    BrowserFillInput,
    BrowserNavigationTargetId,
    BrowserOperationOutcome,
    BrowserOperationResult,
    BrowserPageDescriptor,
    BrowserPageId,
    BrowserPageSnapshot,
    BrowserProfileId,
    BrowserSessionDescriptor,
    BrowserSessionId,
)
from phoenix_os.browser_automation.errors import (
    BrowserAutomationAdapterError,
    BrowserAutomationCancelledError,
    BrowserAutomationConfigurationError,
    BrowserAutomationError,
    BrowserAutomationIndeterminateEffectError,
    BrowserAutomationLimitExceededError,
    BrowserAutomationOperationDisabledError,
    BrowserAutomationRejectedError,
    BrowserAutomationStaleError,
    BrowserAutomationTargetNotFoundError,
    BrowserAutomationTimeoutError,
)
from phoenix_os.browser_automation.network import (
    BrowserDestinationAdmission,
    BrowserNetworkResolver,
    resolve_and_admit_browser_destination,
)
from phoenix_os.browser_automation.profiles import (
    BrowserNavigationRequest,
    BrowserNavigationTarget,
    BrowserProfile,
    derive_browser_redirect_request,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_T = TypeVar("_T")

_CANCELLATION_GRACE_SECONDS = 0.05
_CLEANUP_CAP_SECONDS = 1.0


@runtime_checkable
class BrowserProfileSource(Protocol):
    """Resolve the current trusted immutable browser profile by stable profile identity."""

    def require_profile(self, profile_id: BrowserProfileId) -> BrowserProfile: ...


@dataclass(frozen=True, slots=True)
class BrowserSessionOpenResult:
    """Content-minimized state returned after one authorized local session open."""

    session: BrowserSessionDescriptor
    page: BrowserPageDescriptor

    def __post_init__(self) -> None:
        if not isinstance(self.session, BrowserSessionDescriptor):
            raise TypeError("session must be BrowserSessionDescriptor")
        if not isinstance(self.page, BrowserPageDescriptor):
            raise TypeError("page must be BrowserPageDescriptor")
        if (
            self.page.session_id != self.session.session_id
            or self.page.page_id != self.session.page_id
        ):
            raise ValueError("opened browser page must belong to the opened session")


class BrowserAutomationCancellationToken:
    """Idempotent cooperative cancellation signal for one browser operation."""

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
            raise BrowserAutomationCancelledError()


@dataclass(frozen=True, slots=True)
class _BrowserSubjectBinding:
    principal: str
    principal_type: PrincipalType
    session_id: UUID | None

    @classmethod
    def from_context(cls, context: SecurityContext) -> _BrowserSubjectBinding:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise BrowserAutomationRejectedError()
        return cls(
            principal=context.principal,
            principal_type=context.principal_type,
            session_id=context.session_id,
        )

    def require_context(self, context: SecurityContext) -> None:
        current = self.from_context(context)
        if current != self:
            raise BrowserAutomationRejectedError()


@dataclass(frozen=True, slots=True)
class _EffectiveDeadline:
    wall_clock: datetime
    monotonic: float


@dataclass(slots=True)
class _BrowserSessionState:
    profile: BrowserProfile
    descriptor: BrowserSessionDescriptor
    subject: _BrowserSubjectBinding
    page: BrowserPageDescriptor | None
    lock: asyncio.Lock


class BrowserAutomationService:
    """Apply exact current browser authority around controlled S5 browser operations."""

    def __init__(
        self,
        *,
        profiles: BrowserProfileSource,
        adapter_id: BrowserAdapterId,
        adapter: BrowserAdapter,
        authorizer: BrowserAuthorizer,
        freshness: AuthorityFreshnessValidator,
        network_resolver: BrowserNetworkResolver | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(profiles, BrowserProfileSource):
            raise TypeError("profiles must implement BrowserProfileSource")
        if not isinstance(adapter_id, BrowserAdapterId):
            raise TypeError("adapter_id must be BrowserAdapterId")
        if not isinstance(adapter, BrowserAdapter):
            raise TypeError("adapter must implement BrowserAdapter")
        if not isinstance(authorizer, BrowserAuthorizer):
            raise TypeError("authorizer must implement BrowserAuthorizer")
        if not isinstance(freshness, AuthorityFreshnessValidator):
            raise TypeError("freshness must implement AuthorityFreshnessValidator")
        if network_resolver is not None and not isinstance(
            network_resolver, BrowserNetworkResolver
        ):
            raise TypeError("network_resolver must implement BrowserNetworkResolver or be None")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._profiles = profiles
        self._adapter_id = adapter_id
        self._adapter = adapter
        self._authorizer = authorizer
        self._freshness = freshness
        self._network_resolver = network_resolver
        self._clock: Callable[[], datetime] = _utc_now if clock is None else clock
        self._sessions: dict[BrowserSessionId, _BrowserSessionState] = {}
        self._session_counts: dict[tuple[BrowserProfileId, int], int] = {}
        self._state_lock = asyncio.Lock()
        self._quarantined = False
        self._quarantine_event = asyncio.Event()
        self._abandoned_tasks: set[asyncio.Future[object]] = set()

    async def open_session(
        self,
        profile_id: BrowserProfileId,
        context: SecurityContext,
        *,
        cancellation: BrowserAutomationCancellationToken | None = None,
        deadline: datetime | None = None,
    ) -> BrowserSessionOpenResult:
        """Open one local ephemeral browser session after exact session-open authority."""

        if not isinstance(profile_id, BrowserProfileId):
            raise TypeError("profile_id must be BrowserProfileId")
        subject = _BrowserSubjectBinding.from_context(context)
        self._require_service_active()
        token = self._token(cancellation)
        self._validate_requested_deadline(deadline)
        profile = self._require_open_profile(profile_id)
        operation_deadline = self._operation_deadline(profile, deadline)
        self._require_pre_effect(token, operation_deadline)
        await self._reap_stale_sessions(
            profile,
            cancellation=token,
            deadline=operation_deadline,
        )
        now = self._now()
        descriptor = BrowserSessionDescriptor(
            profile_id=profile.profile_id,
            profile_generation=profile.generation,
            session_id=BrowserSessionId(),
            page_id=BrowserPageId(),
            created_at=now,
            expires_at=self._session_expiry(profile, now),
        )
        state = _BrowserSessionState(
            profile=profile,
            descriptor=descriptor,
            subject=subject,
            page=None,
            lock=asyncio.Lock(),
        )
        await self._reserve_session(state)
        try:
            async with state.lock:
                effective = self._bound_deadline_to_session(state, operation_deadline)
                self._require_pre_effect(token, effective)
                await self._validate_freshness(context, token, effective)
                await self._authorize_session_open(state, context, token, effective)
                self._require_pre_effect(token, effective)
                subject.require_context(context)
                self._require_current_profile_sync(state)

                try:
                    page = await self._await_pre_effect(
                        self._adapter.open_session(profile, descriptor),
                        cancellation=token,
                        deadline=effective,
                    )
                except asyncio.CancelledError:
                    await self._invalidate_state(state, cancellation=token, deadline=effective)
                    raise
                except BrowserAutomationError:
                    await self._invalidate_state(state, cancellation=token, deadline=effective)
                    raise
                except Exception:
                    await self._invalidate_state(state, cancellation=token, deadline=effective)
                    raise BrowserAutomationAdapterError() from None

                if not isinstance(page, BrowserPageDescriptor) or (
                    page.session_id != descriptor.session_id or page.page_id != descriptor.page_id
                ):
                    await self._invalidate_state(state, cancellation=token, deadline=effective)
                    raise BrowserAutomationAdapterError()
                state.page = page
                return BrowserSessionOpenResult(session=descriptor, page=page)
        except BaseException:
            if state.page is None:
                await self._remove_state(state)
            raise

    async def close_session(
        self,
        session_id: BrowserSessionId,
        context: SecurityContext,
        *,
        cancellation: BrowserAutomationCancellationToken | None = None,
        deadline: datetime | None = None,
    ) -> BrowserOperationResult:
        """Close one exact current session after independent browser.session.close authority."""

        if not isinstance(session_id, BrowserSessionId):
            raise TypeError("session_id must be BrowserSessionId")
        _BrowserSubjectBinding.from_context(context)
        self._require_service_active()
        token = self._token(cancellation)
        self._validate_requested_deadline(deadline)
        state = await self._lookup_state(session_id)
        operation_deadline = self._operation_deadline(state.profile, deadline)
        async with state.lock:
            page = self._require_ready_page(state)
            await self._require_live_current_state(
                state,
                context,
                cancellation=token,
                deadline=operation_deadline,
            )
            effective = self._bound_deadline_to_session(state, operation_deadline)
            self._require_pre_effect(token, effective)
            await self._validate_freshness(context, token, effective)
            await self._authorize_session_close(state, context, token, effective)
            self._require_pre_effect(token, effective)
            state.subject.require_context(context)
            self._require_current_profile_sync(state)

            close_error: BrowserAutomationError | None = None
            try:
                await self._await_pre_effect(
                    self._adapter.close_session(state.descriptor.session_id),
                    cancellation=token,
                    deadline=effective,
                )
            except asyncio.CancelledError:
                await self._remove_state(state)
                await self._trip_quarantine()
                raise
            except BrowserAutomationError as exception:
                close_error = exception
            except Exception:
                close_error = BrowserAutomationAdapterError()
            await self._remove_state(state)
            if close_error is not None:
                if isinstance(close_error, BrowserAutomationOperationDisabledError):
                    raise close_error
                if isinstance(
                    close_error,
                    (
                        BrowserAutomationCancelledError,
                        BrowserAutomationTimeoutError,
                    ),
                ):
                    await self._trip_quarantine()
                    raise close_error
                raise BrowserAutomationAdapterError() from None
            return BrowserOperationResult(
                operation_id=uuid4(),
                outcome=BrowserOperationOutcome.SUCCEEDED,
                session_id=state.descriptor.session_id,
                page_id=page.page_id,
                revision=page.revision,
                effect_started=False,
                created_at=self._now(),
            )

    async def read_page(
        self,
        page: BrowserPageDescriptor,
        context: SecurityContext,
        *,
        cancellation: BrowserAutomationCancellationToken | None = None,
        deadline: datetime | None = None,
    ) -> BrowserPageSnapshot:
        """Return one bounded snapshot only after pre-read and pre-disclosure exact authority."""

        if not isinstance(page, BrowserPageDescriptor):
            raise TypeError("page must be BrowserPageDescriptor")
        _BrowserSubjectBinding.from_context(context)
        self._require_service_active()
        token = self._token(cancellation)
        self._validate_requested_deadline(deadline)
        state = await self._lookup_state(page.session_id)
        operation_deadline = self._operation_deadline(state.profile, deadline)
        async with state.lock:
            await self._require_live_current_state(
                state,
                context,
                expected_page=page,
                cancellation=token,
                deadline=operation_deadline,
            )
            effective = self._bound_deadline_to_session(state, operation_deadline)
            self._require_pre_effect(token, effective)
            await self._validate_freshness(context, token, effective)
            await self._authorize_page_read(state, page, context, token, effective)
            self._require_pre_effect(token, effective)
            self._require_current_page_sync(state, page)
            self._require_current_profile_sync(state)

            try:
                snapshot = await self._call_snapshot(page, token, effective)
                self._validate_snapshot(state.profile, page, snapshot)
            except (BrowserAutomationAdapterError, BrowserAutomationStaleError):
                await self._invalidate_state(state, cancellation=token, deadline=effective)
                raise

            # Snapshot acquisition is an attacker-influenceable wait. Revalidate the
            # subject, profile, page revision, freshness, and exact page.read authority
            # before disclosing any page content to the caller.
            await self._require_live_current_state(
                state,
                context,
                expected_page=page,
                cancellation=token,
                deadline=effective,
            )
            self._require_pre_effect(token, effective)
            await self._validate_freshness(context, token, effective)
            await self._authorize_page_read(state, page, context, token, effective)
            self._require_pre_effect(token, effective)
            state.subject.require_context(context)
            self._require_current_profile_sync(state)
            self._require_current_page_sync(state, page)
            return snapshot

    async def navigate(
        self,
        page: BrowserPageDescriptor,
        target_id: BrowserNavigationTargetId,
        context: SecurityContext,
        *,
        cancellation: BrowserAutomationCancellationToken | None = None,
        deadline: datetime | None = None,
    ) -> BrowserOperationResult:
        """Follow one finite exact-authorized top-level navigation chain without retries."""

        if not isinstance(page, BrowserPageDescriptor):
            raise TypeError("page must be BrowserPageDescriptor")
        if not isinstance(target_id, BrowserNavigationTargetId):
            raise TypeError("target_id must be BrowserNavigationTargetId")
        _BrowserSubjectBinding.from_context(context)
        self._require_service_active()
        token = self._token(cancellation)
        self._validate_requested_deadline(deadline)
        state = await self._lookup_state(page.session_id)
        operation_deadline = self._operation_deadline(state.profile, deadline)

        async with state.lock:
            await self._require_live_current_state(
                state,
                context,
                expected_page=page,
                cancellation=token,
                deadline=operation_deadline,
            )
            effective = self._bound_deadline_to_session(state, operation_deadline)
            target = self._require_navigation_target(state.profile, target_id)
            request = BrowserNavigationRequest.from_target(target)
            self._require_pre_effect(token, effective)
            if page.revision.value >= MAX_BROWSER_PAGE_REVISION:
                raise BrowserAutomationLimitExceededError()

            operation_id = uuid4()
            result_created_at = self._now()
            remote_started = False

            while True:
                plan: BrowserPreparedNavigationPlan | None = None
                try:
                    try:
                        plan = await self._call_prepare_navigation(
                            page,
                            request,
                            token,
                            effective,
                        )
                        self._validate_prepared_navigation_plan(page, request, plan)
                    except (BrowserAutomationAdapterError, BrowserAutomationStaleError):
                        if plan is not None:
                            await self._discard_navigation_best_effort(
                                plan,
                                cancellation=token,
                                deadline=effective,
                            )
                            plan = None
                        if remote_started:
                            await self._poison_after_possible_effect(
                                state,
                                cancellation=token,
                                deadline=effective,
                            )
                            raise BrowserAutomationIndeterminateEffectError() from None
                        await self._invalidate_state(
                            state,
                            cancellation=token,
                            deadline=effective,
                        )
                        raise

                    if plan is None:  # pragma: no cover - exact preparation invariant
                        raise BrowserAutomationAdapterError()

                    destination = await self._resolve_navigation_destination(
                        state.profile,
                        request,
                        token,
                        effective,
                    )
                    await self._require_live_current_state(
                        state,
                        context,
                        expected_page=page,
                        cancellation=token,
                        deadline=effective,
                    )
                    self._require_pre_effect(token, effective)

                    # DNS and adapter preparation are attacker-influenceable zero-effect
                    # waits. This is the final freshness and exact authority decision for
                    # this hop; no attacker-controlled wait occurs before commit.
                    await self._validate_freshness(context, token, effective)
                    await self._authorize_page_navigate(
                        state,
                        page,
                        request,
                        context,
                        token,
                        effective,
                    )
                    self._require_pre_effect(token, effective)
                    state.subject.require_context(context)
                    self._require_current_profile_sync(state)
                    self._require_current_page_sync(state, page)

                    prepared = BrowserPreparedNavigation(
                        plan=plan,
                        destination=destination,
                    )
                    try:
                        committed = await self._await_commit(
                            self._adapter.commit_navigation(prepared),
                            cancellation=token,
                            deadline=effective,
                        )
                    except asyncio.CancelledError:
                        await self._poison_after_possible_effect(
                            state,
                            cancellation=token,
                            deadline=effective,
                        )
                        raise BrowserAutomationIndeterminateEffectError() from None
                    except BrowserAutomationIndeterminateEffectError:
                        await self._poison_after_possible_effect(
                            state,
                            cancellation=token,
                            deadline=effective,
                        )
                        raise
                    except Exception:
                        await self._poison_after_possible_effect(
                            state,
                            cancellation=token,
                            deadline=effective,
                        )
                        raise BrowserAutomationIndeterminateEffectError() from None

                    remote_started = True
                    plan = None
                    if not self._valid_navigation_hop_result(page, prepared, committed):
                        await self._poison_after_possible_effect(
                            state,
                            cancellation=token,
                            deadline=effective,
                        )
                        raise BrowserAutomationIndeterminateEffectError()

                    if committed.redirect_location is not None:
                        try:
                            request = derive_browser_redirect_request(
                                state.profile,
                                request,
                                committed.redirect_location,
                            )
                        except Exception:
                            await self._poison_after_possible_effect(
                                state,
                                cancellation=token,
                                deadline=effective,
                            )
                            raise BrowserAutomationIndeterminateEffectError() from None
                        continue

                    next_page = committed.page
                    if next_page is None:  # pragma: no cover - result invariant
                        await self._poison_after_possible_effect(
                            state,
                            cancellation=token,
                            deadline=effective,
                        )
                        raise BrowserAutomationIndeterminateEffectError()
                    state.page = next_page
                    return BrowserOperationResult(
                        operation_id=operation_id,
                        outcome=BrowserOperationOutcome.SUCCEEDED,
                        session_id=next_page.session_id,
                        page_id=next_page.page_id,
                        revision=next_page.revision,
                        effect_started=True,
                        created_at=result_created_at,
                    )
                except BrowserAutomationIndeterminateEffectError:
                    raise
                except BaseException:
                    if plan is not None:
                        await self._discard_navigation_best_effort(
                            plan,
                            cancellation=token,
                            deadline=effective,
                        )
                    if remote_started:
                        await self._poison_after_possible_effect(
                            state,
                            cancellation=token,
                            deadline=effective,
                        )
                        raise BrowserAutomationIndeterminateEffectError() from None
                    raise

    async def fill_element(
        self,
        page: BrowserPageDescriptor,
        element_id: BrowserElementId,
        value: BrowserFillInput,
        context: SecurityContext,
        *,
        cancellation: BrowserAutomationCancellationToken | None = None,
        deadline: datetime | None = None,
    ) -> BrowserOperationResult:
        """Prepare zero-effect fill, then admit and commit exactly one current local effect."""

        if not isinstance(page, BrowserPageDescriptor):
            raise TypeError("page must be BrowserPageDescriptor")
        if not isinstance(element_id, BrowserElementId):
            raise TypeError("element_id must be BrowserElementId")
        if not isinstance(value, BrowserFillInput):
            raise TypeError("value must be BrowserFillInput")
        _BrowserSubjectBinding.from_context(context)
        self._require_service_active()
        token = self._token(cancellation)
        self._validate_requested_deadline(deadline)
        state = await self._lookup_state(page.session_id)
        operation_deadline = self._operation_deadline(state.profile, deadline)

        async with state.lock:
            await self._require_live_current_state(
                state,
                context,
                expected_page=page,
                cancellation=token,
                deadline=operation_deadline,
            )
            effective = self._bound_deadline_to_session(state, operation_deadline)
            self._require_fill_limits(state.profile, value)
            self._require_pre_effect(token, effective)
            if page.revision.value >= MAX_BROWSER_PAGE_REVISION:
                raise BrowserAutomationLimitExceededError()

            prepared: BrowserPreparedEffect | None = None
            try:
                try:
                    prepared = await self._call_prepare_fill(
                        page,
                        element_id,
                        value,
                        token,
                        effective,
                    )
                    self._validate_prepared_fill(page, element_id, value, prepared)
                except (BrowserAutomationAdapterError, BrowserAutomationStaleError):
                    if prepared is not None:
                        await self._discard_best_effort(
                            prepared, cancellation=token, deadline=effective
                        )
                        prepared = None
                    await self._invalidate_state(state, cancellation=token, deadline=effective)
                    raise
                if prepared is None:  # pragma: no cover - exact preparation invariant
                    raise BrowserAutomationAdapterError()
                await self._require_live_current_state(
                    state,
                    context,
                    expected_page=page,
                    cancellation=token,
                    deadline=effective,
                )
                self._require_pre_effect(token, effective)

                # This freshness + exact element.fill decision is the final canonical
                # admission after the last attacker-influenceable zero-effect wait.
                await self._validate_freshness(context, token, effective)
                await self._authorize_element_fill(
                    state,
                    page,
                    prepared,
                    context,
                    token,
                    effective,
                )
                self._require_pre_effect(token, effective)
                state.subject.require_context(context)
                self._require_current_profile_sync(state)
                self._require_current_page_sync(state, page)

                operation_id = uuid4()
                result_created_at = self._now()
                try:
                    committed = await self._await_commit(
                        self._adapter.commit_prepared(prepared),
                        cancellation=token,
                        deadline=effective,
                    )
                except asyncio.CancelledError:
                    await self._poison_after_possible_effect(
                        state, cancellation=token, deadline=effective
                    )
                    raise BrowserAutomationIndeterminateEffectError() from None
                except BrowserAutomationIndeterminateEffectError:
                    await self._poison_after_possible_effect(
                        state, cancellation=token, deadline=effective
                    )
                    raise
                except Exception:
                    await self._poison_after_possible_effect(
                        state, cancellation=token, deadline=effective
                    )
                    raise BrowserAutomationIndeterminateEffectError() from None

                if not self._valid_commit_result(page, prepared, committed):
                    await self._poison_after_possible_effect(
                        state, cancellation=token, deadline=effective
                    )
                    raise BrowserAutomationIndeterminateEffectError()

                state.page = committed.page
                return BrowserOperationResult(
                    operation_id=operation_id,
                    outcome=BrowserOperationOutcome.SUCCEEDED,
                    session_id=committed.page.session_id,
                    page_id=committed.page.page_id,
                    revision=committed.page.revision,
                    effect_started=True,
                    created_at=result_created_at,
                )
            except BrowserAutomationIndeterminateEffectError:
                raise
            except BaseException:
                if prepared is not None:
                    await self._discard_best_effort(
                        prepared, cancellation=token, deadline=effective
                    )
                raise

    async def _reap_stale_sessions(
        self,
        profile: BrowserProfile,
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        self._require_pre_effect(cancellation, deadline)
        now = self._now()
        async with self._state_lock:
            candidates = tuple(
                state
                for state in self._sessions.values()
                if state.profile.profile_id == profile.profile_id
                and (now >= state.descriptor.expires_at or state.profile != profile)
            )

        for state in candidates:
            self._require_pre_effect(cancellation, deadline)
            async with state.lock:
                async with self._state_lock:
                    registered = self._sessions.get(state.descriptor.session_id) is state
                if not registered:
                    continue
                if self._now() < state.descriptor.expires_at and self._profile_is_current(state):
                    continue
                await self._remove_state(state)
                await self._close_reaped_session_best_effort(
                    state,
                    cancellation=cancellation,
                    deadline=deadline,
                )

    async def _close_reaped_session_best_effort(
        self,
        state: _BrowserSessionState,
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        self._require_pre_effect(cancellation, deadline)
        operation = asyncio.ensure_future(self._adapter.close_session(state.descriptor.session_id))
        cancelled = asyncio.create_task(cancellation.wait())
        quarantined = asyncio.create_task(self._quarantine_event.wait())
        cleanup_cap = min(_CLEANUP_CAP_SECONDS, state.profile.limits.operation_timeout_seconds)
        try:
            timeout = min(cleanup_cap, self._remaining_seconds(deadline))
            done, _ = await asyncio.wait(
                {operation, cancelled, quarantined},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if operation in done:
                self._cancel_local_waiter(cancelled)
                self._cancel_local_waiter(quarantined)
                with suppress(BaseException):
                    operation.result()
                self._require_pre_effect(cancellation, deadline)
                return
            if quarantined in done or self._quarantined:
                self._abandon_untrusted_task(operation)
                raise BrowserAutomationOperationDisabledError()
            if cancelled in done or cancellation.cancelled:
                await self._cancel_untrusted_with_grace(operation, deadline)
                await self._trip_quarantine()
                raise BrowserAutomationCancelledError()
            await self._cancel_untrusted_with_grace(operation, deadline)
            await self._trip_quarantine()
            raise BrowserAutomationTimeoutError()
        except asyncio.CancelledError:
            self._abandon_untrusted_task(operation)
            await self._trip_quarantine()
            raise
        finally:
            self._cancel_local_waiter(cancelled)
            self._cancel_local_waiter(quarantined)

    async def _reserve_session(self, state: _BrowserSessionState) -> None:
        key = (state.profile.profile_id, state.profile.generation)
        async with self._state_lock:
            self._require_service_active()
            count = self._session_counts.get(key, 0)
            if count >= state.profile.limits.max_concurrent_sessions:
                raise BrowserAutomationLimitExceededError()
            if state.descriptor.session_id in self._sessions:
                raise BrowserAutomationStaleError()
            self._sessions[state.descriptor.session_id] = state
            self._session_counts[key] = count + 1

    async def _lookup_state(self, session_id: BrowserSessionId) -> _BrowserSessionState:
        self._require_service_active()
        async with self._state_lock:
            self._require_service_active()
            state = self._sessions.get(session_id)
        if state is None:
            raise BrowserAutomationTargetNotFoundError()
        return state

    async def _remove_state(self, state: _BrowserSessionState) -> None:
        key = (state.profile.profile_id, state.profile.generation)
        async with self._state_lock:
            if self._sessions.get(state.descriptor.session_id) is not state:
                return
            del self._sessions[state.descriptor.session_id]
            count = self._session_counts.get(key, 0)
            if count <= 1:
                self._session_counts.pop(key, None)
            else:
                self._session_counts[key] = count - 1

    async def _invalidate_state(
        self,
        state: _BrowserSessionState,
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        await self._remove_state(state)
        if not self._cleanup_may_wait(cancellation, deadline):
            if not self._quarantined:
                await self._trip_quarantine()
            return
        await self._cleanup_best_effort(
            self._adapter.close_session(state.descriptor.session_id),
            cancellation=cancellation,
            deadline=deadline,
            cap_seconds=min(_CLEANUP_CAP_SECONDS, state.profile.limits.operation_timeout_seconds),
        )

    async def _poison_after_possible_effect(
        self,
        state: _BrowserSessionState,
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        await self._invalidate_state(state, cancellation=cancellation, deadline=deadline)

    async def _require_live_current_state(
        self,
        state: _BrowserSessionState,
        context: SecurityContext,
        *,
        expected_page: BrowserPageDescriptor | None = None,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        self._require_service_active()
        state.subject.require_context(context)
        now = self._now()
        if now >= state.descriptor.expires_at:
            await self._invalidate_state(state, cancellation=cancellation, deadline=deadline)
            raise BrowserAutomationStaleError()
        if not self._profile_is_current(state):
            await self._invalidate_state(state, cancellation=cancellation, deadline=deadline)
            raise BrowserAutomationStaleError()
        if expected_page is not None:
            self._require_current_page_sync(state, expected_page)

    def _require_current_profile_sync(self, state: _BrowserSessionState) -> None:
        if not self._profile_is_current(state):
            raise BrowserAutomationStaleError()

    def _profile_is_current(self, state: _BrowserSessionState) -> bool:
        try:
            current = self._profiles.require_profile(state.profile.profile_id)
        except Exception:
            return False
        return (
            isinstance(current, BrowserProfile)
            and current == state.profile
            and current.adapter_id == self._adapter_id
        )

    def _require_current_page_sync(
        self,
        state: _BrowserSessionState,
        expected: BrowserPageDescriptor,
    ) -> None:
        current = self._require_ready_page(state)
        if current != expected:
            raise BrowserAutomationStaleError()

    @staticmethod
    def _require_ready_page(state: _BrowserSessionState) -> BrowserPageDescriptor:
        page = state.page
        if page is None:
            raise BrowserAutomationStaleError()
        return page

    def _require_open_profile(self, profile_id: BrowserProfileId) -> BrowserProfile:
        self._require_service_active()
        try:
            profile = self._profiles.require_profile(profile_id)
        except Exception:
            raise BrowserAutomationTargetNotFoundError() from None
        if not isinstance(profile, BrowserProfile):
            raise BrowserAutomationConfigurationError()
        if profile.adapter_id != self._adapter_id:
            raise BrowserAutomationOperationDisabledError()
        return profile

    async def _validate_freshness(
        self,
        context: SecurityContext,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        try:
            await self._await_pre_effect(
                self._freshness.validate(context),
                cancellation=cancellation,
                deadline=deadline,
            )
        except asyncio.CancelledError:
            raise
        except (
            BrowserAutomationCancelledError,
            BrowserAutomationOperationDisabledError,
            BrowserAutomationTimeoutError,
        ):
            raise
        except Exception:
            raise BrowserAutomationRejectedError() from None

    async def _authorize_session_open(
        self,
        state: _BrowserSessionState,
        context: SecurityContext,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> AuthorityIntent:
        try:
            expected = browser_session_open_intent(state.profile, state.descriptor)
        except Exception:
            raise BrowserAutomationRejectedError() from None
        return await self._authorize_exact(
            self._authorizer.authorize_session_open(
                state.profile,
                state.descriptor,
                context,
            ),
            expected,
            cancellation,
            deadline,
        )

    async def _authorize_session_close(
        self,
        state: _BrowserSessionState,
        context: SecurityContext,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> AuthorityIntent:
        try:
            expected = browser_session_close_intent(state.profile, state.descriptor)
        except Exception:
            raise BrowserAutomationRejectedError() from None
        return await self._authorize_exact(
            self._authorizer.authorize_session_close(
                state.profile,
                state.descriptor,
                context,
            ),
            expected,
            cancellation,
            deadline,
        )

    async def _authorize_page_navigate(
        self,
        state: _BrowserSessionState,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
        context: SecurityContext,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> AuthorityIntent:
        try:
            expected = browser_page_navigate_intent(
                state.profile,
                state.descriptor,
                page,
                request,
            )
        except Exception:
            raise BrowserAutomationRejectedError() from None
        return await self._authorize_exact(
            self._authorizer.authorize_page_navigate(
                state.profile,
                state.descriptor,
                page,
                request,
                context,
            ),
            expected,
            cancellation,
            deadline,
        )

    async def _authorize_page_read(
        self,
        state: _BrowserSessionState,
        page: BrowserPageDescriptor,
        context: SecurityContext,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> AuthorityIntent:
        try:
            expected = browser_page_read_intent(state.profile, state.descriptor, page)
        except Exception:
            raise BrowserAutomationRejectedError() from None
        return await self._authorize_exact(
            self._authorizer.authorize_page_read(
                state.profile,
                state.descriptor,
                page,
                context,
            ),
            expected,
            cancellation,
            deadline,
        )

    async def _authorize_element_fill(
        self,
        state: _BrowserSessionState,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> AuthorityIntent:
        try:
            expected = browser_element_fill_intent(
                state.profile,
                state.descriptor,
                page,
                prepared,
            )
        except Exception:
            raise BrowserAutomationRejectedError() from None
        return await self._authorize_exact(
            self._authorizer.authorize_element_fill(
                state.profile,
                state.descriptor,
                page,
                prepared,
                context,
            ),
            expected,
            cancellation,
            deadline,
        )

    async def _authorize_exact(
        self,
        awaitable: Awaitable[AuthorityIntent],
        expected: AuthorityIntent,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> AuthorityIntent:
        try:
            result = await self._await_pre_effect(
                awaitable,
                cancellation=cancellation,
                deadline=deadline,
            )
        except asyncio.CancelledError:
            raise
        except (
            BrowserAutomationCancelledError,
            BrowserAutomationOperationDisabledError,
            BrowserAutomationTimeoutError,
        ):
            raise
        except Exception:
            raise BrowserAutomationRejectedError() from None
        if not isinstance(result, AuthorityIntent) or result != expected:
            raise BrowserAutomationRejectedError()
        return result

    async def _call_snapshot(
        self,
        page: BrowserPageDescriptor,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> BrowserPageSnapshot:
        try:
            result = await self._await_pre_effect(
                self._adapter.snapshot(page),
                cancellation=cancellation,
                deadline=deadline,
            )
        except asyncio.CancelledError:
            raise
        except BrowserAutomationError:
            raise
        except Exception:
            raise BrowserAutomationAdapterError() from None
        if not isinstance(result, BrowserPageSnapshot):
            raise BrowserAutomationAdapterError()
        return result

    async def _call_prepare_navigation(
        self,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> BrowserPreparedNavigationPlan:
        try:
            result = await self._await_pre_effect(
                self._adapter.prepare_navigation(page, request),
                cancellation=cancellation,
                deadline=deadline,
            )
        except asyncio.CancelledError:
            raise
        except BrowserAutomationError:
            raise
        except Exception:
            raise BrowserAutomationAdapterError() from None
        if not isinstance(result, BrowserPreparedNavigationPlan):
            raise BrowserAutomationAdapterError()
        return result

    async def _resolve_navigation_destination(
        self,
        profile: BrowserProfile,
        request: BrowserNavigationRequest,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> BrowserDestinationAdmission:
        resolver = self._network_resolver
        if resolver is None:
            raise BrowserAutomationOperationDisabledError()
        try:
            result = await self._await_pre_effect(
                resolve_and_admit_browser_destination(
                    profile,
                    request.origin,
                    resolver=resolver,
                ),
                cancellation=cancellation,
                deadline=deadline,
            )
        except asyncio.CancelledError:
            raise
        except BrowserAutomationError:
            raise
        except Exception:
            raise BrowserAutomationAdapterError() from None
        if (
            not isinstance(result, BrowserDestinationAdmission)
            or result.profile_id != profile.profile_id
            or result.profile_generation != profile.generation
            or result.origin != request.origin
        ):
            raise BrowserAutomationAdapterError()
        return result

    async def _call_prepare_fill(
        self,
        page: BrowserPageDescriptor,
        element_id: BrowserElementId,
        value: BrowserFillInput,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> BrowserPreparedEffect:
        try:
            result = await self._await_pre_effect(
                self._adapter.prepare_fill(page, element_id, value),
                cancellation=cancellation,
                deadline=deadline,
            )
        except asyncio.CancelledError:
            raise
        except BrowserAutomationError:
            raise
        except Exception:
            raise BrowserAutomationAdapterError() from None
        if not isinstance(result, BrowserPreparedEffect):
            raise BrowserAutomationAdapterError()
        return result

    async def _discard_navigation_best_effort(
        self,
        prepared: BrowserPreparedNavigationPlan,
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        if not self._cleanup_may_wait(cancellation, deadline):
            if not self._quarantined:
                await self._trip_quarantine()
            return
        await self._cleanup_best_effort(
            self._adapter.discard_navigation(prepared),
            cancellation=cancellation,
            deadline=deadline,
            cap_seconds=_CLEANUP_CAP_SECONDS,
        )

    async def _discard_best_effort(
        self,
        prepared: BrowserPreparedEffect,
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        if not self._cleanup_may_wait(cancellation, deadline):
            if not self._quarantined:
                await self._trip_quarantine()
            return
        await self._cleanup_best_effort(
            self._adapter.discard_prepared(prepared),
            cancellation=cancellation,
            deadline=deadline,
            cap_seconds=_CLEANUP_CAP_SECONDS,
        )

    @staticmethod
    def _validate_prepared_navigation_plan(
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
        prepared: BrowserPreparedNavigationPlan,
    ) -> None:
        if (
            prepared.session_id != page.session_id
            or prepared.page_id != page.page_id
            or prepared.revision != page.revision
            or prepared.request != request
        ):
            raise BrowserAutomationAdapterError()

    @staticmethod
    def _validate_prepared_fill(
        page: BrowserPageDescriptor,
        element_id: BrowserElementId,
        value: BrowserFillInput,
        prepared: BrowserPreparedEffect,
    ) -> None:
        if (
            prepared.kind is not BrowserPreparedEffectKind.FILL
            or prepared.session_id != page.session_id
            or prepared.page_id != page.page_id
            or prepared.revision != page.revision
            or prepared.element_id != element_id
            or prepared.input_digest != value.digest
        ):
            raise BrowserAutomationAdapterError()

    @staticmethod
    def _valid_navigation_hop_result(
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedNavigation,
        committed: object,
    ) -> bool:
        if not isinstance(committed, BrowserNavigationCommitResult):
            return False
        if committed.prepared_token != prepared.token or committed.effect_started is not True:
            return False
        if committed.redirect_location is not None:
            return committed.page is None
        next_page = committed.page
        if next_page is None:
            return False
        return (
            next_page.session_id == page.session_id
            and next_page.page_id == page.page_id
            and next_page.revision.value == page.revision.value + 1
        )

    @staticmethod
    def _valid_commit_result(
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        committed: object,
    ) -> bool:
        if not isinstance(committed, BrowserAdapterCommitResult):
            return False
        if committed.prepared_token != prepared.token or committed.effect_started is not True:
            return False
        next_page = committed.page
        return (
            next_page.session_id == page.session_id
            and next_page.page_id == page.page_id
            and next_page.revision.value == page.revision.value + 1
        )

    @staticmethod
    def _validate_snapshot(
        profile: BrowserProfile,
        page: BrowserPageDescriptor,
        snapshot: BrowserPageSnapshot,
    ) -> None:
        if (
            snapshot.session_id != page.session_id
            or snapshot.page_id != page.page_id
            or snapshot.revision != page.revision
        ):
            raise BrowserAutomationStaleError()
        limits = profile.limits
        if len(snapshot.title) > limits.max_snapshot_title_chars:
            raise BrowserAutomationAdapterError()
        if len(snapshot.text) > limits.max_snapshot_text_chars:
            raise BrowserAutomationAdapterError()
        if len(snapshot.text.encode("utf-8")) > limits.max_snapshot_text_bytes:
            raise BrowserAutomationAdapterError()
        if len(snapshot.elements) > limits.max_snapshot_elements:
            raise BrowserAutomationAdapterError()
        for element in snapshot.elements:
            if len(element.name) > limits.max_element_name_chars:
                raise BrowserAutomationAdapterError()
            if element.value is not None and len(element.value) > limits.max_element_value_chars:
                raise BrowserAutomationAdapterError()

    @staticmethod
    def _require_navigation_target(
        profile: BrowserProfile,
        target_id: BrowserNavigationTargetId,
    ) -> BrowserNavigationTarget:
        try:
            return profile.require_target(target_id)
        except KeyError:
            raise BrowserAutomationTargetNotFoundError() from None

    @staticmethod
    def _require_fill_limits(profile: BrowserProfile, value: BrowserFillInput) -> None:
        if len(value.value) > profile.limits.max_fill_text_chars:
            raise BrowserAutomationLimitExceededError()
        if len(value.value.encode("utf-8")) > profile.limits.max_fill_text_bytes:
            raise BrowserAutomationLimitExceededError()

    async def _await_pre_effect(
        self,
        awaitable: Awaitable[_T],
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> _T:
        self._require_pre_effect(cancellation, deadline)
        operation = asyncio.ensure_future(awaitable)
        cancelled = asyncio.create_task(cancellation.wait())
        quarantined = asyncio.create_task(self._quarantine_event.wait())
        try:
            timeout = self._remaining_seconds(deadline)
            done, _ = await asyncio.wait(
                {operation, cancelled, quarantined},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if operation in done:
                result = operation.result()
                self._require_pre_effect(cancellation, deadline)
                return result
            if quarantined in done or self._quarantined:
                self._abandon_untrusted_task(operation)
                raise BrowserAutomationOperationDisabledError()
            if cancelled in done or cancellation.cancelled:
                abandoned = await self._cancel_untrusted_with_grace(operation, deadline)
                if abandoned:
                    await self._trip_quarantine()
                raise BrowserAutomationCancelledError()
            if self._abandon_untrusted_task(operation):
                await self._trip_quarantine()
            raise BrowserAutomationTimeoutError()
        except asyncio.CancelledError:
            if self._abandon_untrusted_task(operation):
                await self._trip_quarantine()
            raise
        finally:
            self._cancel_local_waiter(cancelled)
            self._cancel_local_waiter(quarantined)

    async def _await_commit(
        self,
        awaitable: Awaitable[_T],
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> _T:
        self._require_pre_effect(cancellation, deadline)
        operation = asyncio.ensure_future(awaitable)
        cancelled = asyncio.create_task(cancellation.wait())
        quarantined = asyncio.create_task(self._quarantine_event.wait())
        try:
            timeout = self._remaining_seconds(deadline)
            done, _ = await asyncio.wait(
                {operation, cancelled, quarantined},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if operation in done:
                try:
                    result = operation.result()
                except BaseException:
                    raise BrowserAutomationIndeterminateEffectError() from None
                if self._quarantined or cancellation.cancelled:
                    raise BrowserAutomationIndeterminateEffectError()
                try:
                    self._remaining_seconds(deadline)
                except BrowserAutomationTimeoutError:
                    raise BrowserAutomationIndeterminateEffectError() from None
                return result
            self._abandon_untrusted_task(operation)
            await self._trip_quarantine()
            raise BrowserAutomationIndeterminateEffectError()
        except asyncio.CancelledError:
            self._abandon_untrusted_task(operation)
            await self._trip_quarantine()
            raise
        finally:
            self._cancel_local_waiter(cancelled)
            self._cancel_local_waiter(quarantined)

    async def _cleanup_best_effort(
        self,
        awaitable: Awaitable[object],
        *,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
        cap_seconds: float,
    ) -> None:
        operation = asyncio.ensure_future(awaitable)
        cancelled = asyncio.create_task(cancellation.wait())
        quarantined = asyncio.create_task(self._quarantine_event.wait())
        try:
            timeout = min(cap_seconds, self._remaining_seconds(deadline))
            done, _ = await asyncio.wait(
                {operation, cancelled, quarantined},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if operation in done:
                with suppress(BaseException):
                    operation.result()
                return
            if quarantined in done or self._quarantined:
                self._abandon_untrusted_task(operation)
                return
            await self._cancel_untrusted_with_grace(operation, deadline)
            await self._trip_quarantine()
        except (BrowserAutomationTimeoutError, BrowserAutomationCancelledError):
            self._abandon_untrusted_task(operation)
            await self._trip_quarantine()
        except asyncio.CancelledError:
            self._abandon_untrusted_task(operation)
            await self._trip_quarantine()
            raise
        finally:
            self._cancel_local_waiter(cancelled)
            self._cancel_local_waiter(quarantined)

    async def _cancel_untrusted_with_grace(
        self,
        operation: asyncio.Future[_T],
        deadline: _EffectiveDeadline,
    ) -> bool:
        operation.cancel()
        if operation.done():
            self._consume_future(operation)
            return False
        try:
            grace = min(_CANCELLATION_GRACE_SECONDS, self._remaining_seconds(deadline))
        except BrowserAutomationTimeoutError:
            grace = 0.0
        if grace > 0:
            quarantined = asyncio.create_task(self._quarantine_event.wait())
            try:
                waiters: set[asyncio.Future[object]] = {
                    cast(asyncio.Future[object], operation),
                    cast(asyncio.Future[object], quarantined),
                }
                done, _ = await asyncio.wait(
                    waiters,
                    timeout=grace,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if operation in done:
                    self._consume_future(operation)
                    return False
            finally:
                self._cancel_local_waiter(quarantined)
        return self._abandon_untrusted_task(operation)

    def _abandon_untrusted_task(self, operation: asyncio.Future[_T]) -> bool:
        if operation.done():
            self._consume_future(operation)
            return False
        operation.cancel()
        if operation.done():
            self._consume_future(operation)
            return False
        tracked = cast(asyncio.Future[object], operation)
        if tracked not in self._abandoned_tasks:
            self._abandoned_tasks.add(tracked)
            tracked.add_done_callback(self._consume_abandoned_task)
        return True

    def _consume_abandoned_task(self, operation: asyncio.Future[object]) -> None:
        self._abandoned_tasks.discard(operation)
        self._consume_future(operation)

    @staticmethod
    def _consume_future(operation: asyncio.Future[_T]) -> None:
        with suppress(BaseException):
            operation.exception()

    @classmethod
    def _cancel_local_waiter(cls, waiter: asyncio.Future[_T]) -> None:
        if waiter.done():
            cls._consume_future(waiter)
            return
        waiter.cancel()
        waiter.add_done_callback(cls._consume_future)

    async def _trip_quarantine(self) -> None:
        self._quarantined = True
        self._quarantine_event.set()
        async with self._state_lock:
            self._sessions.clear()
            self._session_counts.clear()

    def _cleanup_may_wait(
        self,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> bool:
        if self._quarantined or cancellation.cancelled:
            return False
        current = asyncio.current_task()
        if current is not None and current.cancelling():
            return False
        try:
            self._remaining_seconds(deadline)
        except BrowserAutomationTimeoutError:
            return False
        return True

    def _effective_deadline(
        self,
        state: _BrowserSessionState,
        requested: datetime | None,
    ) -> _EffectiveDeadline:
        operation_deadline = self._operation_deadline(state.profile, requested)
        return self._bound_deadline_to_session(state, operation_deadline)

    def _operation_deadline(
        self,
        profile: BrowserProfile,
        requested: datetime | None,
    ) -> _EffectiveDeadline:
        now = self._now()
        wall_clock = now + timedelta(seconds=profile.limits.operation_timeout_seconds)
        if requested is not None:
            wall_clock = min(wall_clock, requested)
        seconds = (wall_clock - now).total_seconds()
        if seconds <= 0:
            raise BrowserAutomationTimeoutError()
        return _EffectiveDeadline(
            wall_clock=wall_clock,
            monotonic=asyncio.get_running_loop().time() + seconds,
        )

    def _bound_deadline_to_session(
        self,
        state: _BrowserSessionState,
        operation_deadline: _EffectiveDeadline,
    ) -> _EffectiveDeadline:
        now = self._now()
        loop_now = asyncio.get_running_loop().time()
        wall_clock = min(operation_deadline.wall_clock, state.descriptor.expires_at)
        session_seconds = (state.descriptor.expires_at - now).total_seconds()
        if session_seconds <= 0:
            raise BrowserAutomationTimeoutError()
        monotonic = min(operation_deadline.monotonic, loop_now + session_seconds)
        if wall_clock <= now or monotonic <= loop_now:
            raise BrowserAutomationTimeoutError()
        return _EffectiveDeadline(wall_clock=wall_clock, monotonic=monotonic)

    def _session_expiry(self, profile: BrowserProfile, created_at: datetime) -> datetime:
        microseconds = int(profile.limits.session_ttl_seconds * 1_000_000)
        if microseconds <= 0:
            raise BrowserAutomationConfigurationError()
        return created_at + timedelta(microseconds=microseconds)

    def _require_pre_effect(
        self,
        cancellation: BrowserAutomationCancellationToken,
        deadline: _EffectiveDeadline,
    ) -> None:
        self._require_service_active()
        cancellation.raise_if_cancelled()
        self._remaining_seconds(deadline)

    def _require_service_active(self) -> None:
        if self._quarantined:
            raise BrowserAutomationOperationDisabledError()

    def _remaining_seconds(self, deadline: _EffectiveDeadline) -> float:
        wall_remaining = (deadline.wall_clock - self._now()).total_seconds()
        monotonic_remaining = deadline.monotonic - asyncio.get_running_loop().time()
        remaining = min(wall_remaining, monotonic_remaining)
        if remaining <= 0:
            raise BrowserAutomationTimeoutError()
        return remaining

    @staticmethod
    def _validate_requested_deadline(deadline: datetime | None) -> None:
        if deadline is None:
            return
        if not isinstance(deadline, datetime):
            raise TypeError("deadline must be datetime or None")
        if deadline.tzinfo is None or deadline.utcoffset() is None:
            raise ValueError("deadline must be timezone-aware")

    @staticmethod
    def _token(
        cancellation: BrowserAutomationCancellationToken | None,
    ) -> BrowserAutomationCancellationToken:
        if cancellation is None:
            return BrowserAutomationCancellationToken()
        if not isinstance(cancellation, BrowserAutomationCancellationToken):
            raise TypeError("cancellation must be BrowserAutomationCancellationToken or None")
        return cancellation

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("clock result must be datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock result must be timezone-aware")
        return value.astimezone(UTC)


def _utc_now() -> datetime:
    return datetime.now(UTC)
