"""Separately authorized read-only authority inspection and explanation."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Protocol, runtime_checkable

from phoenix_os.authority.catalog import (
    AUTHORITY_EXPLAIN_ACTION,
    AUTHORITY_INSPECT_ACTION,
    BUILTIN_AUTHORITY_CATALOG,
)
from phoenix_os.authority.contracts import (
    AuthorityExplainRequest,
    AuthorityExplanationResult,
    AuthorityInspectionResult,
    AuthorityInspectionState,
    AuthorityInspectRequest,
    AuthorityIntent,
    AuthorityPathObservation,
    AuthoritySubject,
    authority_intent_fingerprint,
    authority_subject_fingerprint,
)
from phoenix_os.authority.freshness import AuthorityFreshnessValidator
from phoenix_os.authority.redaction import project_explanation, project_inspection
from phoenix_os.policy import PolicyEngine, PolicyRequest, SecurityContext


class AuthorityInspectionRejectedError(RuntimeError):
    """Inspection/explanation failed closed without leaking target state."""


@runtime_checkable
class AuthorityInspectionSource(Protocol):
    """Trusted read-only server-owned source for exact authority observations.

    Selector strings are data only. Implementations must resolve structural subject and
    intent identity from Phoenix-owned current state and must not read sensitive resource
    content merely to resolve a selector.
    """

    async def resolve_subject(self, target_ref: str) -> AuthoritySubject: ...

    async def inspect(self, subject: AuthoritySubject) -> AuthorityInspectionState: ...

    async def resolve_intent(
        self,
        subject: AuthoritySubject,
        *,
        action: str,
        resource_ref: str | None,
    ) -> AuthorityIntent: ...

    async def explain(
        self,
        subject: AuthoritySubject,
        intent: AuthorityIntent,
    ) -> tuple[AuthorityPathObservation, datetime]: ...


def authority_subject_resource(subject: AuthoritySubject) -> str:
    """Return the exact content-free policy resource for one resolved subject."""

    if not isinstance(subject, AuthoritySubject):
        raise TypeError("subject must be AuthoritySubject")
    return f"authority-subject:{authority_subject_fingerprint(subject)}"


def authority_explanation_resource(subject: AuthoritySubject, intent: AuthorityIntent) -> str:
    """Return the exact content-free policy resource for one resolved subject and intent."""

    if not isinstance(subject, AuthoritySubject):
        raise TypeError("subject must be AuthoritySubject")
    if not isinstance(intent, AuthorityIntent):
        raise TypeError("intent must be AuthorityIntent")
    return (
        "authority-intent:"
        f"{authority_subject_fingerprint(subject)}/{authority_intent_fingerprint(intent)}"
    )


class AuthorityService:
    """Authorize and compose read-only redacted authority observations."""

    def __init__(
        self,
        policy: PolicyEngine,
        source: AuthorityInspectionSource,
        caller_freshness: AuthorityFreshnessValidator,
    ) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        if not isinstance(source, AuthorityInspectionSource):
            raise TypeError("source must implement AuthorityInspectionSource")
        if not isinstance(caller_freshness, AuthorityFreshnessValidator):
            raise TypeError("caller_freshness must implement AuthorityFreshnessValidator")
        self._policy = policy
        self._source = source
        self._caller_freshness = caller_freshness
        self._catalog = BUILTIN_AUTHORITY_CATALOG

    async def inspect(
        self,
        request: AuthorityInspectRequest,
        context: SecurityContext,
    ) -> AuthorityInspectionResult:
        """Inspect one exact server-resolved subject after independent authorization."""

        if not isinstance(request, AuthorityInspectRequest):
            raise TypeError("request must be AuthorityInspectRequest")
        self._require_authenticated(context)

        subject = await self._resolve_subject(request.target_ref)
        resource = authority_subject_resource(subject)
        await self._authorize_current(
            action=AUTHORITY_INSPECT_ACTION,
            resource=resource,
            context=context,
            created_at=request.created_at,
        )

        try:
            state = await self._source.inspect(subject)
        except Exception:
            state = None
        if not isinstance(state, AuthorityInspectionState) or state.subject != subject:
            raise AuthorityInspectionRejectedError("authority inspection rejected")
        try:
            for observation in state.observations:
                self._catalog.validate_observation(observation)
            result = project_inspection(state, self._catalog)
        except Exception:
            result = None
        if result is None:
            raise AuthorityInspectionRejectedError("authority inspection rejected")

        # A trusted source read may take time. Revalidate the caller immediately before
        # releasing protected diagnostic data so revocation/policy changes fail closed.
        await self._authorize_current(
            action=AUTHORITY_INSPECT_ACTION,
            resource=resource,
            context=context,
            created_at=request.created_at,
        )
        return result

    async def explain(
        self,
        request: AuthorityExplainRequest,
        context: SecurityContext,
    ) -> AuthorityExplanationResult:
        """Explain one exact server-resolved intent after independent authorization."""

        if not isinstance(request, AuthorityExplainRequest):
            raise TypeError("request must be AuthorityExplainRequest")
        self._require_authenticated(context)

        subject = await self._resolve_subject(request.target_ref)
        intent = await self._resolve_intent(subject, request)
        resource = authority_explanation_resource(subject, intent)
        await self._authorize_current(
            action=AUTHORITY_EXPLAIN_ACTION,
            resource=resource,
            context=context,
            created_at=request.created_at,
        )

        try:
            explanation = await self._source.explain(subject, intent)
        except Exception:
            explanation = None
        if explanation is None:
            raise AuthorityInspectionRejectedError("authority inspection rejected")
        observation, observed_at = explanation
        if (
            not isinstance(observation, AuthorityPathObservation)
            or observation.intent != intent
            or not isinstance(observed_at, datetime)
            or observed_at.tzinfo is None
            or observed_at.utcoffset() is None
        ):
            raise AuthorityInspectionRejectedError("authority inspection rejected")
        try:
            self._catalog.validate_observation(observation)
            result = project_explanation(subject, observation, observed_at, self._catalog)
        except Exception:
            result = None
        if result is None:
            raise AuthorityInspectionRejectedError("authority inspection rejected")

        await self._authorize_current(
            action=AUTHORITY_EXPLAIN_ACTION,
            resource=resource,
            context=context,
            created_at=request.created_at,
        )
        return result

    async def _resolve_subject(self, target_ref: str) -> AuthoritySubject:
        try:
            subject = await self._source.resolve_subject(target_ref)
        except Exception:
            subject = None
        if not isinstance(subject, AuthoritySubject):
            raise AuthorityInspectionRejectedError("authority inspection rejected")
        return subject

    async def _resolve_intent(
        self,
        subject: AuthoritySubject,
        request: AuthorityExplainRequest,
    ) -> AuthorityIntent:
        try:
            intent = await self._source.resolve_intent(
                subject,
                action=request.action,
                resource_ref=request.resource_ref,
            )
        except Exception:
            intent = None
        if not isinstance(intent, AuthorityIntent) or intent.action != request.action:
            raise AuthorityInspectionRejectedError("authority inspection rejected")
        try:
            self._catalog.validate_intent(intent)
        except Exception:
            valid = False
        else:
            valid = True
        if not valid:
            raise AuthorityInspectionRejectedError("authority inspection rejected")
        return intent

    async def _authorize_current(
        self,
        *,
        action: str,
        resource: str,
        context: SecurityContext,
        created_at: datetime,
    ) -> None:
        try:
            entry = self._catalog.require(action)
            if not entry.accepts_resource(resource):
                raise AuthorityInspectionRejectedError("authority inspection rejected")
            await self._caller_freshness.validate(context)
            await self._policy.enforce(
                PolicyRequest(
                    action=action,
                    resource=resource,
                    context=replace(context, confirmed=False),
                    created_at=created_at,
                )
            )
        except Exception:
            allowed = False
        else:
            allowed = True
        if not allowed:
            raise AuthorityInspectionRejectedError("authority inspection rejected")

    @staticmethod
    def _require_authenticated(context: SecurityContext) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise AuthorityInspectionRejectedError("authority inspection rejected")
