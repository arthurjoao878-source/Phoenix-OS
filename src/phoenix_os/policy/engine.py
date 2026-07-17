"""Deterministic, deny-by-default Phoenix policy engine."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from fnmatch import fnmatchcase
from uuid import UUID, uuid4

from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy.contracts import (
    PolicyDecision,
    PolicyEffect,
    PolicyRegistration,
    PolicyRequest,
    PolicyRule,
    PolicySnapshot,
)
from phoenix_os.policy.errors import (
    PolicyConfirmationRequiredError,
    PolicyDeniedError,
    PolicyEngineClosedError,
    PolicyRuleAlreadyRegisteredError,
    PolicyRuleNotFoundError,
)

_EFFECT_ORDER = {
    PolicyEffect.DENY: 0,
    PolicyEffect.REQUIRE_CONFIRMATION: 1,
    PolicyEffect.ALLOW: 2,
}


@dataclass(slots=True)
class _RegisteredRule:
    registration: PolicyRegistration
    rule: PolicyRule
    sequence: int


class PolicyEngine:
    """Evaluate declarative rules in deterministic priority order."""

    def __init__(
        self,
        rules: Iterable[PolicyRule] = (),
        *,
        events: EventBus | None = None,
        observability: ObservabilityHub | None = None,
        source: str = "phoenix.policy",
    ) -> None:
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        self._rules: dict[str, _RegisteredRule] = {}
        self._by_id: dict[UUID, str] = {}
        self._sequence = 0
        self._events = events
        self._observability = observability
        self._source = normalized_source
        self._closed = False
        self._lock = asyncio.Lock()
        self._evaluations = 0
        self._allowed = 0
        self._denied = 0
        self._confirmations = 0
        for rule in rules:
            self._register_initial(rule)

    @property
    def closed(self) -> bool:
        return self._closed

    async def register(self, rule: PolicyRule) -> PolicyRegistration:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            return self._register_initial(rule).registration

    async def unregister(self, registration: PolicyRegistration) -> bool:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            rule_id = self._by_id.get(registration.id)
            if rule_id is None or rule_id != registration.rule_id:
                return False
            current = self._rules.get(rule_id)
            if current is None or current.registration != registration:
                return False
            del self._rules[rule_id]
            del self._by_id[registration.id]
            return True

    async def list_rules(self) -> tuple[PolicyRule, ...]:
        rules = await self._ordered_rules()
        return tuple(item.rule for item in rules)

    async def describe(self, rule_id: str) -> PolicyRule:
        """Resolve one registered rule by its stable identifier."""

        normalized = rule_id.strip().lower()
        if not normalized:
            raise ValueError("rule_id must not be blank")
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            try:
                return self._rules[normalized].rule
            except KeyError as exception:
                raise PolicyRuleNotFoundError(f"policy rule not found: {normalized}") from exception

    async def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        self._ensure_open()
        async with self._trace(request):
            ordered = await self._ordered_rules()
            matched = tuple(item for item in ordered if _matches(item.rule, request))
            decision = _decide(request, matched)
            await self._record(decision)
            await self._signal(request, decision)
            return decision

    async def enforce(self, request: PolicyRequest) -> PolicyDecision:
        decision = await self.evaluate(request)
        if decision.effect is PolicyEffect.DENY:
            raise PolicyDeniedError(decision)
        if decision.effect is PolicyEffect.REQUIRE_CONFIRMATION:
            raise PolicyConfirmationRequiredError(decision)
        return decision

    async def snapshot(self) -> PolicySnapshot:
        async with self._lock:
            ordered = sorted(
                self._rules.values(),
                key=lambda item: (
                    -item.rule.priority,
                    _EFFECT_ORDER[item.rule.effect],
                    item.sequence,
                ),
            )
            return PolicySnapshot(
                closed=self._closed,
                rules=tuple(item.rule.rule_id for item in ordered),
                evaluations=self._evaluations,
                allowed=self._allowed,
                denied=self._denied,
                confirmations=self._confirmations,
            )

    async def close(self) -> None:
        async with self._lock:
            self._rules.clear()
            self._by_id.clear()
            self._closed = True

    async def start(self, context: object) -> None:
        del context
        self._ensure_open()

    async def stop(self, context: object) -> None:
        del context
        await self.close()

    def _register_initial(self, rule: PolicyRule) -> _RegisteredRule:
        if rule.rule_id in self._rules:
            raise PolicyRuleAlreadyRegisteredError(
                f"policy rule already registered: {rule.rule_id}"
            )
        registration = PolicyRegistration(uuid4(), rule.rule_id)
        registered = _RegisteredRule(registration, rule, self._sequence)
        self._sequence += 1
        self._rules[rule.rule_id] = registered
        self._by_id[registration.id] = rule.rule_id
        return registered

    async def _ordered_rules(self) -> tuple[_RegisteredRule, ...]:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            return tuple(
                sorted(
                    self._rules.values(),
                    key=lambda item: (
                        -item.rule.priority,
                        _EFFECT_ORDER[item.rule.effect],
                        item.sequence,
                    ),
                )
            )

    async def _record(self, decision: PolicyDecision) -> None:
        async with self._lock:
            self._evaluations += 1
            if decision.effect is PolicyEffect.ALLOW:
                self._allowed += 1
            elif decision.effect is PolicyEffect.DENY:
                self._denied += 1
            else:
                self._confirmations += 1

    async def _signal(self, request: PolicyRequest, decision: PolicyDecision) -> None:
        payload: dict[str, object] = {
            "request_id": str(request.id),
            "action": request.action,
            "resource": request.resource,
            "principal": request.context.principal,
            "principal_type": request.context.principal_type.value,
            "effect": decision.effect.value,
            "rule_id": decision.rule_id,
            "confirmation_satisfied": decision.confirmation_satisfied,
        }
        if self._events is not None:
            await self._events.emit(
                "policy.evaluated",
                source=self._source,
                payload=payload,
                correlation_id=request.context.correlation_id,
                causation_id=request.context.causation_id,
            )
        if self._observability is not None:
            await self._observability.metric(
                "policy.decisions",
                1,
                source=self._source,
                kind=MetricKind.COUNTER,
                attributes={
                    "effect": decision.effect.value,
                    "action": request.action,
                },
                correlation_id=request.context.correlation_id,
                causation_id=request.context.causation_id,
            )
            if decision.effect is not PolicyEffect.ALLOW:
                await self._observability.log(
                    "policy.decision.restricted",
                    source=self._source,
                    message=decision.reason,
                    severity=Severity.WARNING,
                    attributes=payload,
                    correlation_id=request.context.correlation_id,
                    causation_id=request.context.causation_id,
                )

    @asynccontextmanager
    async def _trace(self, request: PolicyRequest) -> AsyncIterator[None]:
        if self._observability is None:
            yield
            return
        async with self._observability.span(
            "policy.evaluate",
            source=self._source,
            attributes={"action": request.action, "resource": request.resource},
            correlation_id=request.context.correlation_id,
        ):
            yield

    def _ensure_open(self) -> None:
        if self._closed:
            raise PolicyEngineClosedError("policy engine is closed")


def _matches(rule: PolicyRule, request: PolicyRequest) -> bool:
    context = request.context
    if not any(fnmatchcase(request.action, pattern) for pattern in rule.actions):
        return False
    if not any(fnmatchcase(request.resource, pattern) for pattern in rule.resources):
        return False
    if not any(fnmatchcase(context.principal.lower(), pattern) for pattern in rule.principals):
        return False
    if rule.principal_types and context.principal_type not in rule.principal_types:
        return False
    if rule.authenticated is not None and context.authenticated is not rule.authenticated:
        return False
    if not rule.required_roles <= context.roles:
        return False
    if not rule.required_permissions <= context.permissions:
        return False
    if not rule.required_scopes <= context.scopes:
        return False
    attributes: dict[str, str] = dict(context.attributes)
    attributes.update(request.attributes)
    return all(attributes.get(key) == value for key, value in rule.attribute_equals.items())


def _decide(
    request: PolicyRequest,
    matched: tuple[_RegisteredRule, ...],
) -> PolicyDecision:
    if not matched:
        return PolicyDecision(
            request_id=request.id,
            effect=PolicyEffect.DENY,
            reason="no policy rule matched; default deny",
        )
    selected = matched[0].rule
    matched_ids = tuple(item.rule.rule_id for item in matched)
    reason = selected.reason or f"matched policy rule {selected.rule_id}"
    if selected.effect is PolicyEffect.REQUIRE_CONFIRMATION and request.context.confirmed:
        return PolicyDecision(
            request_id=request.id,
            effect=PolicyEffect.ALLOW,
            reason=f"confirmation satisfied: {reason}",
            rule_id=selected.rule_id,
            matched_rules=matched_ids,
            confirmation_satisfied=True,
            metadata=selected.metadata,
        )
    return PolicyDecision(
        request_id=request.id,
        effect=selected.effect,
        reason=reason,
        rule_id=selected.rule_id,
        matched_rules=matched_ids,
        metadata=selected.metadata,
    )
