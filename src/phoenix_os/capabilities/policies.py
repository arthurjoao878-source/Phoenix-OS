"""Reference permission and confirmation policies."""

from phoenix_os.capabilities.contracts import (
    CapabilityDescriptor,
    CapabilityInvocation,
    ConfirmationDecision,
    ConfirmationStatus,
    PermissionDecision,
    PermissionStatus,
)


class AllowAllPermissionPolicy:
    async def decide(
        self,
        invocation: CapabilityInvocation,
        descriptor: CapabilityDescriptor,
    ) -> PermissionDecision:
        del invocation, descriptor
        return PermissionDecision(PermissionStatus.ALLOW)


class RequiredPermissionsPolicy:
    """Allow only when the trusted context contains every declared permission."""

    async def decide(
        self,
        invocation: CapabilityInvocation,
        descriptor: CapabilityDescriptor,
    ) -> PermissionDecision:
        missing = descriptor.required_permissions - invocation.context.permissions
        if missing:
            names = ", ".join(sorted(missing))
            return PermissionDecision(
                PermissionStatus.DENY,
                f"missing required permissions: {names}",
            )
        return PermissionDecision(PermissionStatus.ALLOW)


class DescriptorConfirmationPolicy:
    """Require confirmation when the descriptor explicitly declares it."""

    async def decide(
        self,
        invocation: CapabilityInvocation,
        descriptor: CapabilityDescriptor,
    ) -> ConfirmationDecision:
        del invocation
        if descriptor.confirmation_required:
            return ConfirmationDecision(
                ConfirmationStatus.REQUIRED,
                "capability requires explicit confirmation",
            )
        return ConfirmationDecision(ConfirmationStatus.NOT_REQUIRED)


class NeverRequireConfirmationPolicy:
    async def decide(
        self,
        invocation: CapabilityInvocation,
        descriptor: CapabilityDescriptor,
    ) -> ConfirmationDecision:
        del invocation, descriptor
        return ConfirmationDecision(ConfirmationStatus.NOT_REQUIRED)
