"""Maintainer-only HTTP administration for secure model inference."""

from __future__ import annotations

import json
from collections.abc import Mapping
from http import HTTPStatus
from typing import Protocol

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.step_up import ControlPlaneStepUpAction
from phoenix_os.inference import (
    DEFAULT_INFERENCE_ADMIN_PAGE_SIZE,
    InferenceAdministration,
    InferenceAdministrationAccessDeniedError,
    InferenceAdministrationConflictError,
    InferenceAdminPageRequest,
    InferenceRegistryClosedError,
    ModelNotFoundError,
    ModelProviderNotFoundError,
    inference_administration_snapshot_to_dict,
    inference_model_page_to_dict,
    inference_model_view_to_dict,
    inference_provider_page_to_dict,
    inference_provider_view_to_dict,
)
from phoenix_os.policy import PrincipalType, SecurityContext

INFERENCE_CONTROL_PLANE_BASE_PATH = "/v1/control-plane/inference"

_PROVIDERS_PATH = f"{INFERENCE_CONTROL_PLANE_BASE_PATH}/providers"
_PROVIDER_PREFIX = f"{_PROVIDERS_PATH}/"
_MODELS_PATH = f"{INFERENCE_CONTROL_PLANE_BASE_PATH}/models"
_MODEL_PREFIX = f"{_MODELS_PATH}/"
_HEALTH_PATH = f"{INFERENCE_CONTROL_PLANE_BASE_PATH}/health"
_NO_STORE = {"Cache-Control": "no-store"}


class ControlPlaneInferenceCsrfVerifier(Protocol):
    """Durable-session CSRF verification boundary."""

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object: ...


class _ControlPlaneInferenceStepUpVerifier(Protocol):
    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object: ...


class ControlPlaneInferenceHttpAdapter:
    """Expose exact-permission inference administration to Maintainer sessions."""

    def __init__(
        self,
        *,
        administration: InferenceAdministration,
        boundary: ControlPlaneInferenceCsrfVerifier,
        step_up: _ControlPlaneInferenceStepUpVerifier,
    ) -> None:
        if not isinstance(administration, InferenceAdministration):
            raise TypeError("inference HTTP requires an InferenceAdministration service")
        if not callable(getattr(boundary, "verify_csrf", None)):
            raise TypeError("inference HTTP requires a CSRF boundary")
        if not callable(getattr(step_up, "verify", None)):
            raise TypeError("inference HTTP requires step-up verification")
        self._administration = administration
        self._boundary = boundary
        self._step_up = step_up

    @property
    def administration(self) -> InferenceAdministration:
        return self._administration

    @staticmethod
    def handles(path: str) -> bool:
        return path == _HEALTH_PATH or path.startswith(f"{INFERENCE_CONTROL_PLANE_BASE_PATH}/")

    async def dispatch(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        method: str,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        context = _security_context(authentication.principal)
        try:
            if method == "GET":
                return await self._dispatch_get(
                    context=context,
                    path=path,
                    query=query,
                    body=body,
                )
            if method != "POST":
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "method_not_allowed"},
                    {"Allow": "GET, POST", **_NO_STORE},
                )
            if query:
                return (
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_request"},
                    dict(_NO_STORE),
                )
            await self._verify_csrf(authentication, headers, server_origin)
            return await self._dispatch_post(
                authentication=authentication,
                context=context,
                path=path,
                headers=headers,
                document=_json_object(body),
            )
        except InferenceAdministrationAccessDeniedError:
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, dict(_NO_STORE)
        except (
            ControlPlaneDurableSessionCsrfRejectedError,
            ControlPlaneStepUpRejectedError,
        ):
            return (
                HTTPStatus.FORBIDDEN,
                {"error": "request_rejected"},
                dict(_NO_STORE),
            )
        except (
            ModelProviderNotFoundError,
            ModelNotFoundError,
        ):
            return (
                HTTPStatus.NOT_FOUND,
                {"error": "inference_registration_not_found"},
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
                {"error": "inference_administration_unavailable"},
                dict(_NO_STORE),
            )

    async def _dispatch_get(
        self,
        *,
        context: SecurityContext,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        body: bytes,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        if body:
            raise ValueError("inference GET requests must not contain a body")

        if path == _HEALTH_PATH:
            if query:
                raise ValueError("inference health does not accept query fields")
            snapshot = await self._administration.snapshot(context)
            return (
                HTTPStatus.OK,
                inference_administration_snapshot_to_dict(snapshot),
                dict(_NO_STORE),
            )

        if path == _PROVIDERS_PATH:
            provider_page = await self._administration.list_providers(
                context,
                _page_request(query),
            )
            return (
                HTTPStatus.OK,
                inference_provider_page_to_dict(provider_page),
                dict(_NO_STORE),
            )

        if path == _MODELS_PATH:
            page_request, provider_id = _model_page_request(query)
            model_page = await self._administration.list_models(
                context,
                page_request,
                provider_id=provider_id,
            )
            return (
                HTTPStatus.OK,
                inference_model_page_to_dict(model_page),
                dict(_NO_STORE),
            )

        if query:
            raise ValueError("inference detail routes do not accept query fields")

        provider_id = _provider_detail(path)
        if provider_id is not None:
            provider_view = await self._administration.provider(
                provider_id,
                context,
            )
            return (
                HTTPStatus.OK,
                inference_provider_view_to_dict(provider_view),
                dict(_NO_STORE),
            )

        model_detail = _model_detail(path)
        if model_detail is not None:
            provider_id, model_id = model_detail
            model_view = await self._administration.model(
                provider_id,
                model_id,
                context,
            )
            return (
                HTTPStatus.OK,
                inference_model_view_to_dict(model_view),
                dict(_NO_STORE),
            )

        return HTTPStatus.NOT_FOUND, {"error": "not_found"}, dict(_NO_STORE)

    async def _dispatch_post(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        context: SecurityContext,
        path: str,
        headers: Mapping[str, tuple[str, ...]],
        document: Mapping[str, object],
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        _revision_only(document)
        expected_revision = _positive_integer(
            document,
            "expected_revision",
        )

        provider_action = _provider_action(path)
        if provider_action is not None:
            provider_id, action = provider_action
            enabled = action == "enable"
            if enabled:
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.ENABLE_INFERENCE_PROVIDER,
                )
            provider_view = await self._administration.set_provider_enabled(
                provider_id,
                context,
                enabled=enabled,
                expected_revision=expected_revision,
            )
            return (
                HTTPStatus.OK,
                inference_provider_view_to_dict(provider_view),
                dict(_NO_STORE),
            )

        model_action = _model_action(path)
        if model_action is not None:
            provider_id, model_id, action = model_action
            enabled = action == "enable"
            if enabled:
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.ENABLE_INFERENCE_MODEL,
                )
            model_view = await self._administration.set_model_enabled(
                provider_id,
                model_id,
                context,
                enabled=enabled,
                expected_revision=expected_revision,
            )
            return (
                HTTPStatus.OK,
                inference_model_view_to_dict(model_view),
                dict(_NO_STORE),
            )

        return HTTPStatus.NOT_FOUND, {"error": "not_found"}, dict(_NO_STORE)

    async def _verify_csrf(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        server_origin: ControlPlaneBrowserOrigin,
    ) -> None:
        try:
            supplied_origin = _exact_origin(headers)
        except ValueError as exception:
            raise ControlPlaneDurableSessionCsrfRejectedError(
                "inference request origin rejected"
            ) from exception
        await self._boundary.verify_csrf(
            _one_optional_header(headers, "x-phoenix-csrf"),
            authentication,
            supplied_origin=supplied_origin,
            expected_origin=server_origin,
        )

    async def _verify_step_up(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        action: ControlPlaneStepUpAction,
    ) -> None:
        await self._step_up.verify(
            _one_optional_header(headers, "x-phoenix-step-up"),
            authentication,
            action,
        )


def _security_context(principal: ControlPlanePrincipal) -> SecurityContext:
    return SecurityContext(
        principal=principal.name,
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=principal.permissions,
    )


def _page_request(
    query: Mapping[str, tuple[str, ...]],
) -> InferenceAdminPageRequest:
    if set(query) - {"offset", "limit"}:
        raise ValueError("unsupported inference pagination field")
    return InferenceAdminPageRequest(
        offset=_query_integer(query, "offset", 0),
        limit=_query_integer(
            query,
            "limit",
            DEFAULT_INFERENCE_ADMIN_PAGE_SIZE,
        ),
    )


def _model_page_request(
    query: Mapping[str, tuple[str, ...]],
) -> tuple[InferenceAdminPageRequest, str | None]:
    if set(query) - {"offset", "limit", "provider_id"}:
        raise ValueError("unsupported inference model pagination field")
    provider_values = query.get("provider_id")
    provider_id = None
    if provider_values is not None:
        if len(provider_values) != 1 or not provider_values[0]:
            raise ValueError("provider_id must appear exactly once")
        provider_id = provider_values[0]
    return (
        InferenceAdminPageRequest(
            offset=_query_integer(query, "offset", 0),
            limit=_query_integer(
                query,
                "limit",
                DEFAULT_INFERENCE_ADMIN_PAGE_SIZE,
            ),
        ),
        provider_id,
    )


def _query_integer(
    query: Mapping[str, tuple[str, ...]],
    name: str,
    default: int,
) -> int:
    values = query.get(name)
    if values is None:
        return default
    if len(values) != 1 or not values[0] or not values[0].isascii() or not values[0].isdigit():
        raise ValueError("pagination value must be one unsigned integer")
    return int(values[0])


def _provider_detail(path: str) -> str | None:
    if not path.startswith(_PROVIDER_PREFIX):
        return None
    suffix = path[len(_PROVIDER_PREFIX) :]
    if not suffix or "/" in suffix:
        return None
    return suffix


def _model_detail(path: str) -> tuple[str, str] | None:
    if not path.startswith(_MODEL_PREFIX):
        return None
    parts = path[len(_MODEL_PREFIX) :].split("/")
    if len(parts) != 2 or not all(parts):
        return None
    return parts[0], parts[1]


def _provider_action(path: str) -> tuple[str, str] | None:
    if not path.startswith(_PROVIDER_PREFIX):
        return None
    parts = path[len(_PROVIDER_PREFIX) :].split("/")
    if len(parts) != 2 or not parts[0] or parts[1] not in {"disable", "enable"}:
        return None
    return parts[0], parts[1]


def _model_action(path: str) -> tuple[str, str, str] | None:
    if not path.startswith(_MODEL_PREFIX):
        return None
    parts = path[len(_MODEL_PREFIX) :].split("/")
    if len(parts) != 3 or not parts[0] or not parts[1] or parts[2] not in {"disable", "enable"}:
        return None
    return parts[0], parts[1], parts[2]


def _json_object(body: bytes) -> Mapping[str, object]:
    if not body:
        raise ValueError("inference request body is required")
    document = json.loads(body.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("inference request body must be an object")
    return document


def _revision_only(document: Mapping[str, object]) -> None:
    if set(document) != {"expected_revision"}:
        raise ValueError("inference lifecycle request fields are invalid")


def _positive_integer(document: Mapping[str, object], name: str) -> int:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{name} must be a positive integer")
    return value


def _one_optional_header(
    headers: Mapping[str, tuple[str, ...]],
    name: str,
) -> str | None:
    values = headers.get(name, ())
    if not values:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError(f"{name} must appear at most once")
    return values[0]


def _exact_origin(
    headers: Mapping[str, tuple[str, ...]],
) -> ControlPlaneBrowserOrigin:
    value = _one_optional_header(headers, "origin")
    if value is None:
        raise ValueError("origin header is required")
    return ControlPlaneBrowserOrigin(value)
