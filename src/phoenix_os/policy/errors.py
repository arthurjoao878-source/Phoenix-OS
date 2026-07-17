"""Policy engine exception hierarchy."""

from __future__ import annotations

from phoenix_os.policy.contracts import PolicyDecision


class PhoenixPolicyError(Exception):
    """Base error for policy evaluation and enforcement."""


class PolicyEngineClosedError(PhoenixPolicyError):
    pass


class PolicyRuleAlreadyRegisteredError(PhoenixPolicyError):
    pass


class PolicyRuleNotFoundError(PhoenixPolicyError):
    pass


class PolicyDeniedError(PhoenixPolicyError):
    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


class PolicyConfirmationRequiredError(PhoenixPolicyError):
    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision
