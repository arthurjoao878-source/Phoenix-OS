"""Least-privilege content-free administration for browser automation."""

from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.browser_automation.service import (
    BrowserAutomationService,
    BrowserAutomationServiceSnapshot,
)
from phoenix_os.policy import PrincipalType, SecurityContext

BROWSER_HEALTH_READ_PERMISSION = "browser.health.read"
BROWSER_HEALTH_RESOURCE = "browser-automation:health"


class BrowserAutomationAdministrationAccessDeniedError(PermissionError):
    """Sanitized denial for the bounded browser-administration surface."""

    def __init__(self) -> None:
        super().__init__("browser automation administration access denied")


@dataclass(frozen=True, slots=True)
class BrowserAutomationAdministrationSnapshot:
    """Content-free bounded health for the configured browser service."""

    runtime: BrowserAutomationServiceSnapshot
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, BrowserAutomationServiceSnapshot):
            raise TypeError("runtime must be BrowserAutomationServiceSnapshot")
        if self.schema_version != 1:
            raise ValueError("unsupported browser administration snapshot version")


class BrowserAutomationAdministration:
    """Expose one read-only bounded browser health surface."""

    def __init__(self, service: BrowserAutomationService) -> None:
        if not isinstance(service, BrowserAutomationService):
            raise TypeError("service must be BrowserAutomationService")
        self._service = service

    async def snapshot(
        self,
        context: SecurityContext,
    ) -> BrowserAutomationAdministrationSnapshot:
        self._authorize(context)
        return BrowserAutomationAdministrationSnapshot(runtime=await self._service.snapshot())

    @staticmethod
    def _authorize(context: SecurityContext) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise BrowserAutomationAdministrationAccessDeniedError()
        if (
            BROWSER_HEALTH_READ_PERMISSION not in context.permissions
            and "*" not in context.permissions
        ):
            raise BrowserAutomationAdministrationAccessDeniedError()
        if (
            context.principal_type is PrincipalType.SERVICE
            and context.attributes.get("resource") != BROWSER_HEALTH_RESOURCE
        ):
            raise BrowserAutomationAdministrationAccessDeniedError()
