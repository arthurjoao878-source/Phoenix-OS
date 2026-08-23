"""Read-only RFC-0033 authority diagnostics for durable control-plane operators."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Protocol

from phoenix_os.authority import (
    AuthorityExplainRequest,
    AuthorityExplanationResult,
    AuthorityInspectionRejectedError,
    AuthorityInspectionResult,
    AuthorityInspectRequest,
    AuthorityObservationProjection,
    AuthorityService,
    AuthoritySubjectProjection,
)
from phoenix_os.control_plane.authority_integration import (
    control_plane_authority_security_context,
)
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import ControlPlaneDurableSessionCsrfRejectedError

AUTHORITY_CONTROL_PLANE_BASE_PATH = "/v1/control-plane/authority"
AUTHORITY_INSPECT_CONTROL_PLANE_PATH = f"{AUTHORITY_CONTROL_PLANE_BASE_PATH}/inspect"
AUTHORITY_EXPLAIN_CONTROL_PLANE_PATH = f"{AUTHORITY_CONTROL_PLANE_BASE_PATH}/explain"
_NO_STORE = {"Cache-Control": "no-store"}

type ControlPlaneAuthorityHttpClock = Callable[[], datetime]


class ControlPlaneAuthorityCsrfVerifier(Protocol):
    """Durable-session CSRF boundary borrowed by authority diagnostics."""

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ControlPlaneAuthorityHttpAdapter:
    """Expose only separately authorized redacted authority inspection and explanation."""

    def __init__(
        self,
        *,
        service: AuthorityService,
        boundary: ControlPlaneAuthorityCsrfVerifier,
        clock: ControlPlaneAuthorityHttpClock = _utc_now,
    ) -> None:
        if not isinstance(service, AuthorityService):
            raise TypeError("authority HTTP requires AuthorityService")
        if not callable(getattr(boundary, "verify_csrf", None)):
            raise TypeError("authority HTTP requires a durable CSRF boundary")
        if not callable(clock):
            raise TypeError("authority HTTP clock must be callable")
        self._service = service
        self._boundary = boundary
        self._clock = clock

    @staticmethod
    def handles(path: str) -> bool:
        return path in {
            AUTHORITY_INSPECT_CONTROL_PLANE_PATH,
            AUTHORITY_EXPLAIN_CONTROL_PLANE_PATH,
        }

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
        if not isinstance(authentication, ControlPlaneDurableSessionAuthentication):
            raise TypeError("authentication must be ControlPlaneDurableSessionAuthentication")
        if method != "POST":
            return (
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed"},
                {"Allow": "POST", **_NO_STORE},
            )
        if query:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, dict(_NO_STORE)

        try:
            await self._verify_csrf(authentication, headers, server_origin)
            document = _json_object(body)
            context = control_plane_authority_security_context(authentication)
            now = self._now()

            if path == AUTHORITY_INSPECT_CONTROL_PLANE_PATH:
                _require_fields(document, required={"target_ref"})
                inspection_result = await self._service.inspect(
                    AuthorityInspectRequest(
                        target_ref=_string(document, "target_ref"),
                        created_at=now,
                    ),
                    context,
                )
                return HTTPStatus.OK, _inspection_to_dict(inspection_result), dict(_NO_STORE)

            if path == AUTHORITY_EXPLAIN_CONTROL_PLANE_PATH:
                _require_fields(
                    document,
                    required={"target_ref", "action"},
                    optional={"resource_ref"},
                )
                explanation_result = await self._service.explain(
                    AuthorityExplainRequest(
                        target_ref=_string(document, "target_ref"),
                        action=_string(document, "action"),
                        resource_ref=_optional_string(document, "resource_ref"),
                        created_at=now,
                    ),
                    context,
                )
                return HTTPStatus.OK, _explanation_to_dict(explanation_result), dict(_NO_STORE)

            return HTTPStatus.NOT_FOUND, {"error": "not_found"}, dict(_NO_STORE)
        except ControlPlaneDurableSessionCsrfRejectedError:
            return HTTPStatus.FORBIDDEN, {"error": "request_rejected"}, dict(_NO_STORE)
        except AuthorityInspectionRejectedError:
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, dict(_NO_STORE)
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return (
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_authority_request"},
                dict(_NO_STORE),
            )

    async def _verify_csrf(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        server_origin: ControlPlaneBrowserOrigin,
    ) -> None:
        try:
            supplied_origin = ControlPlaneBrowserOrigin(_one_header(headers, "origin"))
            await self._boundary.verify_csrf(
                _optional_header(headers, "x-phoenix-csrf"),
                authentication,
                supplied_origin=supplied_origin,
                expected_origin=server_origin,
            )
        except (ControlPlaneDurableSessionCsrfRejectedError, TypeError, ValueError) as exception:
            raise ControlPlaneDurableSessionCsrfRejectedError(
                "authority request CSRF validation failed"
            ) from exception

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("authority HTTP clock must return datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority HTTP clock must return a timezone-aware datetime")
        return value


def _inspection_to_dict(result: AuthorityInspectionResult) -> Mapping[str, object]:
    if not isinstance(result, AuthorityInspectionResult):
        raise TypeError("authority inspection result contract mismatch")
    return {
        "schema_version": 1,
        "subject": _subject_to_dict(result.subject),
        "observed_at": result.observed_at.isoformat(),
        "observations": [_observation_to_dict(item) for item in result.observations],
    }


def _explanation_to_dict(result: AuthorityExplanationResult) -> Mapping[str, object]:
    if not isinstance(result, AuthorityExplanationResult):
        raise TypeError("authority explanation result contract mismatch")
    return {
        "schema_version": 1,
        "subject": _subject_to_dict(result.subject),
        "observed_at": result.observed_at.isoformat(),
        "observation": _observation_to_dict(result.observation),
    }


def _subject_to_dict(subject: AuthoritySubjectProjection) -> Mapping[str, object]:
    if not isinstance(subject, AuthoritySubjectProjection):
        raise TypeError("authority subject projection contract mismatch")
    return {
        "principal_type": subject.principal_type.value,
        "principal": subject.principal,
        "session_identity": subject.session_identity,
        "agent_id": subject.agent_id,
        "run_id": subject.run_id,
    }


def _observation_to_dict(observation: AuthorityObservationProjection) -> Mapping[str, object]:
    if not isinstance(observation, AuthorityObservationProjection):
        raise TypeError("authority observation projection contract mismatch")
    return {
        "effect": observation.effect.value,
        "requested_action": observation.requested_action,
        "canonical_resource": observation.canonical_resource,
        "authority_path": list(observation.authority_path),
        "applicable_constraints": [item.value for item in observation.applicable_constraints],
        "denial_reason": (
            None if observation.denial_reason is None else observation.denial_reason.value
        ),
        "blocked_downstream_alternatives": list(observation.blocked_downstream_alternatives),
    }


def _json_object(body: bytes) -> Mapping[str, object]:
    if not body:
        raise ValueError("authority request body is required")
    document = json.loads(body.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("authority request body must be an object")
    return document


def _require_fields(
    document: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    allowed = required | (set() if optional is None else optional)
    if not required.issubset(document) or set(document) - allowed:
        raise ValueError("authority request fields do not match route schema")


def _string(document: Mapping[str, object], name: str) -> str:
    value = document[name]
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _optional_string(document: Mapping[str, object], name: str) -> str | None:
    value = document.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _one_header(headers: Mapping[str, tuple[str, ...]], name: str) -> str:
    values = headers.get(name, ())
    if len(values) != 1 or not values[0]:
        raise ValueError(f"one {name} header is required")
    return values[0]


def _optional_header(headers: Mapping[str, tuple[str, ...]], name: str) -> str | None:
    values = headers.get(name, ())
    if not values:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError(f"at most one {name} header is allowed")
    return values[0]
