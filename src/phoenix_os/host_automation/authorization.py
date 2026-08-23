"""Fresh exact deny-by-default authorization for secure host automation."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Protocol, runtime_checkable

from phoenix_os.host_automation.contracts import (
    HostApplicationCloseRequest,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostId,
    HostProcessId,
    HostProcessListRequest,
    HostWindowFocusRequest,
    HostWindowId,
    HostWindowListRequest,
)
from phoenix_os.host_automation.errors import HostAutomationAuthorizationRejectedError
from phoenix_os.policy import PhoenixPolicyError, PolicyEngine, PolicyRequest, SecurityContext

HOST_PROCESS_LIST_ACTION = "host.process.list"
HOST_WINDOW_LIST_ACTION = "host.window.list"
HOST_APPLICATION_LAUNCH_ACTION = "host.app.launch"
HOST_WINDOW_FOCUS_ACTION = "host.window.focus"
HOST_APPLICATION_CLOSE_ACTION = "host.app.close"
HOST_CLIPBOARD_WRITE_ACTION = "host.clipboard.write"
HOST_CLIPBOARD_READ_ACTION = "host.clipboard.read"
_CLIPBOARD_TEXT_DIGEST_PREFIX = "sha256:"


def _canonical_clipboard_text_digest(request: HostClipboardWriteRequest) -> str:
    """Return a content-free digest over exact normalized clipboard text."""

    return _CLIPBOARD_TEXT_DIGEST_PREFIX + hashlib.sha256(request.text.encode("utf-8")).hexdigest()


def host_resource(host_id: HostId) -> str:
    """Return the exact policy root for one configured Phoenix host."""

    if not isinstance(host_id, HostId):
        raise TypeError("host_id must be HostId")
    return f"host-automation:host:{host_id}"


def host_process_collection_resource(host_id: HostId) -> str:
    """Return the exact process-enumeration resource for one host."""

    return f"{host_resource(host_id)}/processes"


def host_window_collection_resource(host_id: HostId) -> str:
    """Return the exact window-enumeration resource for one host."""

    return f"{host_resource(host_id)}/windows"


def host_clipboard_resource(host_id: HostId) -> str:
    """Return the exact text-clipboard resource for one host."""

    return f"{host_resource(host_id)}/clipboard:text"


def host_application_resource(
    host_id: HostId,
    application_id: HostApplicationId,
) -> str:
    """Return the exact configured-application resource for one host."""

    if not isinstance(application_id, HostApplicationId):
        raise TypeError("application_id must be HostApplicationId")
    return f"{host_resource(host_id)}/application:{application_id}"


def host_process_resource(host_id: HostId, process_id: HostProcessId) -> str:
    """Return the exact opaque process resource for one host epoch binding."""

    if not isinstance(process_id, HostProcessId):
        raise TypeError("process_id must be HostProcessId")
    return f"{host_resource(host_id)}/process:{process_id}"


def host_window_resource(host_id: HostId, window_id: HostWindowId) -> str:
    """Return the exact opaque window resource for one host epoch binding."""

    if not isinstance(window_id, HostWindowId):
        raise TypeError("window_id must be HostWindowId")
    return f"{host_resource(host_id)}/window:{window_id}"


@runtime_checkable
class HostAutomationAuthorizer(Protocol):
    """Authorize every exact host operation against current Phoenix policy."""

    async def authorize_process_list(
        self,
        request: HostProcessListRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_window_list(
        self,
        request: HostWindowListRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_application_launch(
        self,
        request: HostApplicationLaunchRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_window_focus(
        self,
        request: HostWindowFocusRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_application_close(
        self,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_clipboard_write(
        self,
        request: HostClipboardWriteRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_clipboard_read(
        self,
        request: HostClipboardReadRequest,
        context: SecurityContext,
    ) -> None: ...


class PolicyEngineHostAutomationAuthorizer:
    """Apply fresh exact policy without permission or confirmation fallback."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize_process_list(
        self,
        request: HostProcessListRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, HostProcessListRequest):
            raise TypeError("request must be HostProcessListRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=HOST_PROCESS_LIST_ACTION,
            resource=host_process_collection_resource(request.host_id),
            context=context,
            attributes={
                **_base_attributes(request.host_id, request.request_id),
                "max_results": str(request.limit),
            },
            created_at=request.created_at,
        )

    async def authorize_window_list(
        self,
        request: HostWindowListRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, HostWindowListRequest):
            raise TypeError("request must be HostWindowListRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=HOST_WINDOW_LIST_ACTION,
            resource=host_window_collection_resource(request.host_id),
            context=context,
            attributes={
                **_base_attributes(request.host_id, request.request_id),
                "max_results": str(request.limit),
            },
            created_at=request.created_at,
        )

    async def authorize_application_launch(
        self,
        request: HostApplicationLaunchRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, HostApplicationLaunchRequest):
            raise TypeError("request must be HostApplicationLaunchRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=HOST_APPLICATION_LAUNCH_ACTION,
            resource=host_application_resource(request.host_id, request.application_id),
            context=context,
            attributes={
                **_base_attributes(request.host_id, request.request_id),
                "application_id": str(request.application_id),
            },
            created_at=request.created_at,
        )

    async def authorize_window_focus(
        self,
        request: HostWindowFocusRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, HostWindowFocusRequest):
            raise TypeError("request must be HostWindowFocusRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=HOST_WINDOW_FOCUS_ACTION,
            resource=host_window_resource(request.host_id, request.window_id),
            context=context,
            attributes={
                **_base_attributes(request.host_id, request.request_id),
                "host_epoch": str(request.host_epoch),
                "window_id": str(request.window_id),
                "process_id": str(request.process_id),
                "application_id": (
                    str(request.application_id) if request.application_id is not None else "absent"
                ),
            },
            created_at=request.created_at,
        )

    async def authorize_application_close(
        self,
        request: HostApplicationCloseRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, HostApplicationCloseRequest):
            raise TypeError("request must be HostApplicationCloseRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=HOST_APPLICATION_CLOSE_ACTION,
            resource=host_process_resource(request.host_id, request.process_id),
            context=context,
            attributes={
                **_base_attributes(request.host_id, request.request_id),
                "host_epoch": str(request.host_epoch),
                "application_id": str(request.application_id),
                "process_id": str(request.process_id),
            },
            created_at=request.created_at,
        )

    async def authorize_clipboard_write(
        self,
        request: HostClipboardWriteRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, HostClipboardWriteRequest):
            raise TypeError("request must be HostClipboardWriteRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=HOST_CLIPBOARD_WRITE_ACTION,
            resource=host_clipboard_resource(request.host_id),
            context=context,
            attributes={
                **_base_attributes(request.host_id, request.request_id),
                "text_characters": str(len(request.text)),
                "text_bytes": str(len(request.text.encode("utf-8"))),
                "text_digest": _canonical_clipboard_text_digest(request),
            },
            created_at=request.created_at,
        )

    async def authorize_clipboard_read(
        self,
        request: HostClipboardReadRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, HostClipboardReadRequest):
            raise TypeError("request must be HostClipboardReadRequest")
        _require_authenticated_context(context)
        await self._enforce(
            action=HOST_CLIPBOARD_READ_ACTION,
            resource=host_clipboard_resource(request.host_id),
            context=context,
            attributes=_base_attributes(request.host_id, request.request_id),
            created_at=request.created_at,
        )

    async def _enforce(
        self,
        *,
        action: str,
        resource: str,
        context: SecurityContext,
        attributes: dict[str, str],
        created_at: datetime,
    ) -> None:
        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=action,
                    resource=resource,
                    context=context,
                    attributes=attributes,
                    created_at=created_at,
                )
            )
        except PhoenixPolicyError as exception:
            raise HostAutomationAuthorizationRejectedError() from exception


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise HostAutomationAuthorizationRejectedError()


def _base_attributes(host_id: HostId, request_id: object) -> dict[str, str]:
    return {
        "host_id": str(host_id),
        "request_id": str(request_id),
    }
