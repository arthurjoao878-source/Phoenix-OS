"""Scoped service-account administration for secure model inference."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from http import HTTPStatus

from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountAuthorizer,
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineRequest,
    ControlPlaneServiceAccountMachineResponse,
    ControlPlaneServiceAccountMachineRoute,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.inference import (
    INFERENCE_HEALTH_READ_PERMISSION,
    INFERENCE_MODELS_DISABLE_PERMISSION,
    INFERENCE_MODELS_ENABLE_PERMISSION,
    INFERENCE_MODELS_READ_PERMISSION,
    INFERENCE_PROVIDERS_DISABLE_PERMISSION,
    INFERENCE_PROVIDERS_ENABLE_PERMISSION,
    INFERENCE_PROVIDERS_READ_PERMISSION,
    INFERENCE_RUNTIME_RESOURCE,
    InferenceAdministration,
    InferenceAdministrationAccessDeniedError,
    InferenceAdministrationConflictError,
    InferenceRegistryClosedError,
    ModelId,
    ModelNotFoundError,
    ModelProviderId,
    ModelProviderNotFoundError,
    inference_administration_snapshot_to_dict,
    inference_model_resource,
    inference_model_view_to_dict,
    inference_provider_resource,
    inference_provider_view_to_dict,
)
from phoenix_os.policy import PrincipalType, SecurityContext

CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE = "inference-machine"
CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH = "/v1/control-plane/machine/inference"

_HEALTH = f"{CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH}/health"
_PROVIDER = f"{CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH}/provider"
_PROVIDER_DISABLE = f"{_PROVIDER}/disable"
_PROVIDER_ENABLE = f"{_PROVIDER}/enable"
_MODEL = f"{CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH}/model"
_MODEL_DISABLE = f"{_MODEL}/disable"
_MODEL_ENABLE = f"{_MODEL}/enable"
_NO_STORE = {"Cache-Control": "no-store"}

_ROUTE_SPECS = (
    ("GET", _HEALTH, INFERENCE_HEALTH_READ_PERMISSION),
    ("GET", _PROVIDER, INFERENCE_PROVIDERS_READ_PERMISSION),
    (
        "POST",
        _PROVIDER_DISABLE,
        INFERENCE_PROVIDERS_DISABLE_PERMISSION,
    ),
    (
        "POST",
        _PROVIDER_ENABLE,
        INFERENCE_PROVIDERS_ENABLE_PERMISSION,
    ),
    ("GET", _MODEL, INFERENCE_MODELS_READ_PERMISSION),
    ("POST", _MODEL_DISABLE, INFERENCE_MODELS_DISABLE_PERMISSION),
    ("POST", _MODEL_ENABLE, INFERENCE_MODELS_ENABLE_PERMISSION),
)


class ControlPlaneInferenceMachineAdministration:
    """Expose exact-resource inference lifecycle through machine-only routes."""

    def __init__(
        self,
        administration: InferenceAdministration,
        *,
        exact_authorizer: (ControlPlaneServiceAccountAuthorizer | None) = None,
    ) -> None:
        if not isinstance(administration, InferenceAdministration):
            raise TypeError("inference machine administration requires InferenceAdministration")
        authorizer = (
            ControlPlaneServiceAccountAuthorizer() if exact_authorizer is None else exact_authorizer
        )
        if not isinstance(
            authorizer,
            ControlPlaneServiceAccountAuthorizer,
        ):
            raise TypeError("inference machine exact authorizer has an invalid type")

        self._administration = administration
        self._exact_authorizer = authorizer
        self._actions = {(method, path): action for method, path, action in _ROUTE_SPECS}
        self._routes = tuple(
            ControlPlaneServiceAccountMachineRoute(
                method=method,
                path=path,
                action=action,
                resource=CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE,
                handler=self._handle,
            )
            for method, path, action in _ROUTE_SPECS
        )

    @property
    def administration(self) -> InferenceAdministration:
        return self._administration

    @property
    def routes(
        self,
    ) -> tuple[ControlPlaneServiceAccountMachineRoute, ...]:
        return self._routes

    async def _handle(
        self,
        context: ControlPlaneServiceAccountApiContext,
        request: ControlPlaneServiceAccountMachineRequest,
    ) -> ControlPlaneServiceAccountMachineResponse:
        try:
            action = self._actions[
                (
                    request.method,
                    request.path,
                )
            ]

            if request.path == _HEALTH:
                _require_get(
                    request,
                    fields=frozenset(),
                )
                resource = INFERENCE_RUNTIME_RESOURCE
                self._require_concrete(
                    context,
                    action=action,
                    resource=resource,
                )
                snapshot = await self._administration.snapshot(
                    _administration_context(
                        context,
                        action,
                        resource,
                    )
                )
                return (
                    HTTPStatus.OK,
                    inference_administration_snapshot_to_dict(snapshot),
                    dict(_NO_STORE),
                )

            if request.path == _PROVIDER:
                values = _require_get(
                    request,
                    fields=frozenset({"provider_id"}),
                )
                provider_id = ModelProviderId(values["provider_id"])
                resource = inference_provider_resource(provider_id)
                self._require_concrete(
                    context,
                    action=action,
                    resource=resource,
                )
                provider = await self._administration.provider(
                    provider_id,
                    _administration_context(
                        context,
                        action,
                        resource,
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inference_provider_view_to_dict(provider),
                    dict(_NO_STORE),
                )

            if request.path == _MODEL:
                values = _require_get(
                    request,
                    fields=frozenset(
                        {
                            "provider_id",
                            "model_id",
                        }
                    ),
                )
                provider_id = ModelProviderId(values["provider_id"])
                model_id = ModelId(values["model_id"])
                resource = inference_model_resource(
                    provider_id,
                    model_id,
                )
                self._require_concrete(
                    context,
                    action=action,
                    resource=resource,
                )
                model = await self._administration.model(
                    provider_id,
                    model_id,
                    _administration_context(
                        context,
                        action,
                        resource,
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inference_model_view_to_dict(model),
                    dict(_NO_STORE),
                )

            document = _post_document(request)

            if request.path in {
                _PROVIDER_DISABLE,
                _PROVIDER_ENABLE,
            }:
                _require_fields(
                    document,
                    {
                        "provider_id",
                        "expected_revision",
                    },
                )
                provider_id = ModelProviderId(_string(document, "provider_id"))
                resource = inference_provider_resource(provider_id)
                self._require_concrete(
                    context,
                    action=action,
                    resource=resource,
                )
                provider = await self._administration.set_provider_enabled(
                    provider_id,
                    _administration_context(
                        context,
                        action,
                        resource,
                    ),
                    enabled=(request.path == _PROVIDER_ENABLE),
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inference_provider_view_to_dict(provider),
                    dict(_NO_STORE),
                )

            if request.path in {
                _MODEL_DISABLE,
                _MODEL_ENABLE,
            }:
                _require_fields(
                    document,
                    {
                        "provider_id",
                        "model_id",
                        "expected_revision",
                    },
                )
                provider_id = ModelProviderId(_string(document, "provider_id"))
                model_id = ModelId(_string(document, "model_id"))
                resource = inference_model_resource(
                    provider_id,
                    model_id,
                )
                self._require_concrete(
                    context,
                    action=action,
                    resource=resource,
                )
                model = await self._administration.set_model_enabled(
                    provider_id,
                    model_id,
                    _administration_context(
                        context,
                        action,
                        resource,
                    ),
                    enabled=(request.path == _MODEL_ENABLE),
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inference_model_view_to_dict(model),
                    dict(_NO_STORE),
                )

            raise ValueError("unknown inference machine route")

        except (
            ControlPlaneServiceAccountPermissionDeniedError,
            InferenceAdministrationAccessDeniedError,
        ):
            return (
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden"},
                dict(_NO_STORE),
            )
        except (
            ModelProviderNotFoundError,
            ModelNotFoundError,
        ):
            return (
                HTTPStatus.NOT_FOUND,
                {"error": ("inference_registration_not_found")},
                dict(_NO_STORE),
            )
        except InferenceAdministrationConflictError:
            return (
                HTTPStatus.CONFLICT,
                {"error": "inference_conflict"},
                dict(_NO_STORE),
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return (
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_inference_request"},
                dict(_NO_STORE),
            )
        except (
            InferenceRegistryClosedError,
            RuntimeError,
        ):
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": ("inference_administration_unavailable")},
                dict(_NO_STORE),
            )

    def _require_concrete(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> None:
        self._exact_authorizer.require(
            context.authentication,
            action=action,
            resource=resource,
        )


def control_plane_inference_machine_routes(
    administration: InferenceAdministration,
    *,
    exact_authorizer: (ControlPlaneServiceAccountAuthorizer | None) = None,
) -> tuple[ControlPlaneServiceAccountMachineRoute, ...]:
    """Build the explicit concrete-resource inference machine route set."""

    return ControlPlaneInferenceMachineAdministration(
        administration,
        exact_authorizer=exact_authorizer,
    ).routes


def _administration_context(
    context: ControlPlaneServiceAccountApiContext,
    permission: str,
    resource: str,
) -> SecurityContext:
    security = context.security_context
    attributes = dict(security.attributes)
    attributes["resource"] = resource
    return SecurityContext(
        principal=context.principal_name,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        roles=frozenset(),
        permissions=frozenset({permission}),
        scopes=context.scopes,
        attributes=attributes,
        correlation_id=context.correlation_id,
        causation_id=context.request_id,
        confirmed=False,
    )


def _require_get(
    request: ControlPlaneServiceAccountMachineRequest,
    *,
    fields: frozenset[str],
) -> dict[str, str]:
    if request.body:
        raise ValueError("inference machine GET requests must not contain a body")
    if set(request.query) != fields:
        raise ValueError("inference machine GET query fields are invalid")

    values: dict[str, str] = {}
    for name in fields:
        raw_values = request.query[name]
        if len(raw_values) != 1 or not raw_values[0] or raw_values[0] != raw_values[0].strip():
            raise ValueError("inference machine identifier must appear exactly once")
        values[name] = raw_values[0]

    return values


def _post_document(
    request: ControlPlaneServiceAccountMachineRequest,
) -> Mapping[str, object]:
    if request.query:
        raise ValueError("inference machine mutation does not accept query fields")

    content_types = request.headers.get(
        "content-type",
        (),
    )
    if len(content_types) != 1:
        raise ValueError("inference machine content type is required")

    media_type = content_types[0].split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise ValueError("inference machine body must be JSON")
    if not request.body:
        raise ValueError("inference machine body is required")

    document = json.loads(
        request.body.decode("utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(document, dict):
        raise TypeError("inference machine body must be an object")
    return document


def _strict_object(
    pairs: Sequence[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def _require_fields(
    document: Mapping[str, object],
    fields: set[str],
) -> None:
    if set(document) != fields:
        raise ValueError("inference machine request fields are invalid")


def _string(
    document: Mapping[str, object],
    name: str,
) -> str:
    value = document[name]
    if not isinstance(value, str) or not value or value != value.strip():
        raise TypeError(f"{name} must be a nonblank string")
    return value


def _positive_integer(
    document: Mapping[str, object],
    name: str,
) -> int:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{name} must be a positive integer")
    return value
