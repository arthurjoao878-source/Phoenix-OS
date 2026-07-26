"""Exact policy authorization boundary for model inference."""

from __future__ import annotations

from typing import Protocol

from phoenix_os.inference.contracts import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.inference.errors import InferenceAuthorizationRejectedError
from phoenix_os.policy import (
    PhoenixPolicyError,
    PolicyEngine,
    PolicyRequest,
    SecurityContext,
)

INFERENCE_MODEL_ACTION = "model.infer"


def inference_model_resource(
    provider_id: ModelProviderId,
    model_id: ModelId,
) -> str:
    """Return the concrete policy resource for one registered provider and model."""

    if not isinstance(provider_id, ModelProviderId):
        raise TypeError("provider_id must be ModelProviderId")
    if not isinstance(model_id, ModelId):
        raise TypeError("model_id must be ModelId")
    return f"model-provider:{provider_id}/model:{model_id}"


class InferenceAuthorizer(Protocol):
    """Authorize only the bounded inference action for one concrete model."""

    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None: ...


class PolicyEngineInferenceAuthorizer:
    """Use the central deny-by-default Policy Engine without permission fallback."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, InferenceRequest):
            raise TypeError("request must be InferenceRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise InferenceAuthorizationRejectedError()

        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=INFERENCE_MODEL_ACTION,
                    resource=inference_model_resource(
                        request.provider_id,
                        request.model_id,
                    ),
                    context=context,
                    attributes={
                        "provider_id": str(request.provider_id),
                        "model_id": str(request.model_id),
                        "request_id": str(request.request_id),
                    },
                )
            )
        except PhoenixPolicyError as exception:
            raise InferenceAuthorizationRejectedError() from exception
