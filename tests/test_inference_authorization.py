from datetime import UTC, datetime

import pytest

from phoenix_os.inference import (
    INFERENCE_MODEL_ACTION,
    InferenceAuthorizationRejectedError,
    InferenceMessage,
    InferenceRequest,
    InferenceRole,
    ModelId,
    ModelProviderId,
    PolicyEngineInferenceAuthorizer,
    inference_model_resource,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)


def _request(
    *,
    provider: str = "hosted",
    model: str = "chat",
) -> InferenceRequest:
    return InferenceRequest(
        provider_id=ModelProviderId(provider),
        model_id=ModelId(model),
        messages=(InferenceMessage(InferenceRole.USER, "hello"),),
        created_at=datetime(2026, 7, 26, 12, tzinfo=UTC),
        deadline=datetime(2026, 7, 26, 12, 1, tzinfo=UTC),
    )


def _context(*, authenticated: bool = True) -> SecurityContext:
    return SecurityContext(
        principal="service:assistant" if authenticated else "anonymous",
        principal_type=(PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS),
        authenticated=authenticated,
    )


def test_inference_action_and_resource_are_exact() -> None:
    request = _request()

    assert INFERENCE_MODEL_ACTION == "model.infer"
    assert (
        inference_model_resource(request.provider_id, request.model_id)
        == "model-provider:hosted/model:chat"
    )


@pytest.mark.asyncio
async def test_policy_authorizer_allows_only_matching_provider_and_model() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.hosted.chat",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"model.infer"}),
                resources=frozenset({"model-provider:hosted/model:chat"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )
    authorizer = PolicyEngineInferenceAuthorizer(policy)

    await authorizer.authorize(_request(), _context())

    with pytest.raises(InferenceAuthorizationRejectedError):
        await authorizer.authorize(_request(model="other"), _context())
    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_policy_authorizer_is_default_deny_without_rules() -> None:
    authorizer = PolicyEngineInferenceAuthorizer(PolicyEngine())

    with pytest.raises(
        InferenceAuthorizationRejectedError,
        match="authorization failed",
    ):
        await authorizer.authorize(_request(), _context())


@pytest.mark.asyncio
async def test_policy_authorizer_rejects_unauthenticated_context_before_evaluation() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineInferenceAuthorizer(policy)

    with pytest.raises(InferenceAuthorizationRejectedError):
        await authorizer.authorize(_request(), _context(authenticated=False))

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_policy_confirmation_is_not_accepted_implicitly() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="confirm.inference",
                effect=PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset({"model.infer"}),
                resources=frozenset({"model-provider:hosted/model:chat"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )
    authorizer = PolicyEngineInferenceAuthorizer(policy)

    with pytest.raises(InferenceAuthorizationRejectedError):
        await authorizer.authorize(_request(), _context())


@pytest.mark.asyncio
async def test_public_denials_do_not_enumerate_provider_or_model() -> None:
    authorizer = PolicyEngineInferenceAuthorizer(PolicyEngine())

    messages: set[str] = set()
    for request in (
        _request(provider="missing", model="one"),
        _request(provider="other", model="two"),
    ):
        with pytest.raises(InferenceAuthorizationRejectedError) as captured:
            await authorizer.authorize(request, _context())
        messages.add(str(captured.value))

    assert messages == {"inference request authorization failed"}
