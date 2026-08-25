from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.authority import BUILTIN_AUTHORITY_CATALOG
from phoenix_os.network_egress import (
    NETWORK_HTTP_REQUEST_ACTION,
    NetworkCredentialBinding,
    NetworkDestinationMode,
    NetworkEgressAuthorizationRejectedError,
    NetworkEgressOperation,
    NetworkEgressOperationId,
    NetworkEgressProfile,
    NetworkEgressProfileId,
    NetworkHttpMethod,
    NetworkHttpRequest,
    NetworkOperationEffect,
    NetworkOperationLimits,
    PolicyEngineNetworkEgressAuthorizer,
    network_http_intent,
    network_http_parameter_digest,
    network_http_resource,
)
from phoenix_os.policy import (
    PolicyDecision,
    PolicyEffect,
    PolicyEngine,
    PolicyRequest,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 8, 24, 3, tzinfo=UTC)
_PROFILE_ID = NetworkEgressProfileId("payments")
_OPERATION_ID = NetworkEgressOperationId("charge")
_REQUEST_ID = UUID("34000000-0000-4000-8000-000000000003")
_PRINCIPAL = "service:requester"


class RecordingPolicyEngine(PolicyEngine):
    def __init__(self, rules: tuple[PolicyRule, ...]) -> None:
        super().__init__(rules)
        self.enforced: list[PolicyRequest] = []

    async def enforce(self, request: PolicyRequest) -> PolicyDecision:
        self.enforced.append(request)
        return await super().enforce(request)


class NeverPolicyEngine(PolicyEngine):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    async def enforce(self, request: PolicyRequest) -> PolicyDecision:
        del request
        self.calls += 1
        raise AssertionError("policy must not be reached for an invalid exact binding")


def _operation() -> NetworkEgressOperation:
    return NetworkEgressOperation(
        operation_id=_OPERATION_ID,
        method=NetworkHttpMethod.POST,
        request_target="/v1/charge?mode=fixed",
        effect=NetworkOperationEffect.REMOTE_EFFECT,
        limits=NetworkOperationLimits(
            max_request_body_bytes=1024,
            max_response_body_bytes=4096,
            max_response_headers=16,
            max_response_header_bytes=4096,
            max_resolved_addresses=4,
            connect_timeout_seconds=2.0,
            total_timeout_seconds=10.0,
        ),
        accept="application/json",
        content_type="application/json",
        exposed_response_headers=("content-type", "x-request-id"),
    )


def _profile(
    *,
    generation: int = 7,
    operation: NetworkEgressOperation | None = None,
    credential_version: int = 3,
) -> NetworkEgressProfile:
    selected = _operation() if operation is None else operation
    return NetworkEgressProfile(
        profile_id=_PROFILE_ID,
        generation=generation,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="api.example.com",
        port=443,
        allow_public_networks=True,
        allowed_networks=(),
        credential=NetworkCredentialBinding(
            header_name="authorization",
            secret_ref=SecretRef("api-token", "network", credential_version),
            value_prefix="Bearer ",
        ),
        operations=(selected,),
    )


def _request(body: bytes = b'{"amount":100}') -> NetworkHttpRequest:
    return NetworkHttpRequest(
        profile_id=_PROFILE_ID,
        operation_id=_OPERATION_ID,
        body=body,
        request_id=_REQUEST_ID,
        created_at=_NOW,
    )


def _context(*, confirmed: bool = False) -> SecurityContext:
    return SecurityContext(
        principal=_PRINCIPAL,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        confirmed=confirmed,
    )


def _allow_rule(resource: str) -> PolicyRule:
    return PolicyRule(
        rule_id="allow-network-request",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({NETWORK_HTTP_REQUEST_ACTION}),
        resources=frozenset({resource}),
        principals=frozenset({_PRINCIPAL}),
        authenticated=True,
    )


def test_network_resource_is_exact_generation_bound_catalog_resource() -> None:
    operation = _operation()
    profile = _profile(operation=operation)

    resource = network_http_resource(profile, operation)

    assert resource == "network-egress:payments/generation:7/operation:charge"
    entry = BUILTIN_AUTHORITY_CATALOG.require(NETWORK_HTTP_REQUEST_ACTION)
    assert entry.canonical_boundary == NETWORK_HTTP_REQUEST_ACTION
    assert entry.accepts_resource(resource)
    assert not entry.accepts_resource("network-egress:payments/generation:0/operation:charge")
    assert not entry.accepts_resource("network-egress:payments/operation:charge")


def test_network_intent_binds_body_and_effective_server_owned_configuration() -> None:
    operation = _operation()
    profile = _profile(operation=operation)
    request = _request()

    intent = network_http_intent(request, profile, operation)

    assert intent.action == NETWORK_HTTP_REQUEST_ACTION
    assert intent.canonical_resource == network_http_resource(profile, operation)
    assert intent.parameter_digest == network_http_parameter_digest(
        request,
        profile,
        operation,
    )
    assert intent.freshness_bindings[0].kind == "network.profile.generation"
    assert intent.freshness_bindings[0].identity == "payments:7"

    changed_body = replace(request, body=b'{"amount":101}')
    assert (
        network_http_parameter_digest(changed_body, profile, operation) != intent.parameter_digest
    )

    changed_target = replace(operation, request_target="/v1/other")
    changed_profile = _profile(operation=changed_target)
    assert (
        network_http_parameter_digest(request, changed_profile, changed_target)
        != intent.parameter_digest
    )

    changed_credential = _profile(operation=operation, credential_version=4)
    assert (
        network_http_parameter_digest(request, changed_credential, operation)
        != intent.parameter_digest
    )


@pytest.mark.asyncio
async def test_authorizer_enforces_exact_network_policy_and_clears_ambient_confirmation() -> None:
    operation = _operation()
    profile = _profile(operation=operation)
    request = _request()
    resource = network_http_resource(profile, operation)
    policy = RecordingPolicyEngine((_allow_rule(resource),))

    intent = await PolicyEngineNetworkEgressAuthorizer(policy).authorize(
        request,
        profile,
        operation,
        _context(confirmed=True),
    )

    assert intent.canonical_resource == resource
    assert len(policy.enforced) == 1
    policy_request = policy.enforced[0]
    assert policy_request.action == NETWORK_HTTP_REQUEST_ACTION
    assert policy_request.resource == resource
    assert policy_request.context.principal == _PRINCIPAL
    assert policy_request.context.confirmed is False
    assert policy_request.attributes["profile_id"] == "payments"
    assert policy_request.attributes["profile_generation"] == "7"
    assert policy_request.attributes["operation_id"] == "charge"
    assert policy_request.attributes["request_body_digest"] == request.body_digest
    assert "api.example.com" not in policy_request.resource
    assert request.body.decode("utf-8") not in repr(intent)
    assert "api-token" not in repr(intent)


@pytest.mark.asyncio
async def test_old_generation_policy_does_not_authorize_new_generation() -> None:
    operation = _operation()
    old_profile = _profile(generation=7, operation=operation)
    new_profile = _profile(generation=8, operation=operation)
    policy = PolicyEngine((_allow_rule(network_http_resource(old_profile, operation)),))
    authorizer = PolicyEngineNetworkEgressAuthorizer(policy)

    with pytest.raises(NetworkEgressAuthorizationRejectedError):
        await authorizer.authorize(
            _request(),
            new_profile,
            operation,
            _context(),
        )


@pytest.mark.asyncio
async def test_tool_invoke_authority_does_not_imply_network_authority() -> None:
    operation = _operation()
    profile = _profile(operation=operation)
    resource = network_http_resource(profile, operation)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow-tool-only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"tool.invoke"}),
                resources=frozenset({f"tool:http/{resource}"}),
                principals=frozenset({_PRINCIPAL}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(NetworkEgressAuthorizationRejectedError):
        await PolicyEngineNetworkEgressAuthorizer(policy).authorize(
            _request(),
            profile,
            operation,
            _context(),
        )


@pytest.mark.asyncio
async def test_generic_confirmation_does_not_satisfy_network_confirmation_rule() -> None:
    operation = _operation()
    profile = _profile(operation=operation)
    resource = network_http_resource(profile, operation)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="confirm-network",
                effect=PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset({NETWORK_HTTP_REQUEST_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({_PRINCIPAL}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(NetworkEgressAuthorizationRejectedError):
        await PolicyEngineNetworkEgressAuthorizer(policy).authorize(
            _request(),
            profile,
            operation,
            _context(confirmed=True),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", ["profile", "operation", "configured-operation", "body-limit"])
async def test_exact_binding_mismatches_fail_before_policy(mismatch: str) -> None:
    operation = _operation()
    profile = _profile(operation=operation)
    request = _request()

    if mismatch == "profile":
        request = replace(request, profile_id=NetworkEgressProfileId("other"))
    elif mismatch == "operation":
        request = replace(
            request,
            operation_id=NetworkEgressOperationId("other"),
        )
    elif mismatch == "configured-operation":
        operation = replace(operation, request_target="/v1/forged")
    else:
        tiny = replace(
            operation,
            limits=replace(operation.limits, max_request_body_bytes=1),
        )
        profile = _profile(operation=tiny)
        operation = tiny

    policy = NeverPolicyEngine()
    with pytest.raises(NetworkEgressAuthorizationRejectedError):
        await PolicyEngineNetworkEgressAuthorizer(policy).authorize(
            request,
            profile,
            operation,
            _context(),
        )
    assert policy.calls == 0


@pytest.mark.asyncio
async def test_unauthenticated_context_fails_before_policy() -> None:
    operation = _operation()
    profile = _profile(operation=operation)
    policy = NeverPolicyEngine()
    context = SecurityContext()

    with pytest.raises(NetworkEgressAuthorizationRejectedError):
        await PolicyEngineNetworkEgressAuthorizer(policy).authorize(
            _request(),
            profile,
            operation,
            context,
        )
    assert policy.calls == 0


def test_authorization_error_is_content_free() -> None:
    error = NetworkEgressAuthorizationRejectedError()
    rendered = str(error)

    assert rendered == "network egress request authorization failed"
    assert "api.example.com" not in rendered
    assert "api-token" not in rendered
    assert "charge" not in rendered
