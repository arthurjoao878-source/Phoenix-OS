"""Fresh exact canonical authority for RFC-0035 browser operations."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC
from typing import Protocol, runtime_checkable

from phoenix_os.authority import (
    BUILTIN_AUTHORITY_CATALOG,
    AuthorityFreshnessBinding,
    AuthorityIntent,
)
from phoenix_os.authority.catalog import (
    BROWSER_ELEMENT_CLICK_ACTION as BROWSER_ELEMENT_CLICK_ACTION,
)
from phoenix_os.authority.catalog import (
    BROWSER_ELEMENT_FILL_ACTION as BROWSER_ELEMENT_FILL_ACTION,
)
from phoenix_os.authority.catalog import (
    BROWSER_PAGE_NAVIGATE_ACTION as BROWSER_PAGE_NAVIGATE_ACTION,
)
from phoenix_os.authority.catalog import (
    BROWSER_PAGE_READ_ACTION as BROWSER_PAGE_READ_ACTION,
)
from phoenix_os.authority.catalog import (
    BROWSER_SESSION_CLOSE_ACTION as BROWSER_SESSION_CLOSE_ACTION,
)
from phoenix_os.authority.catalog import (
    BROWSER_SESSION_OPEN_ACTION as BROWSER_SESSION_OPEN_ACTION,
)
from phoenix_os.browser_automation.adapter import BrowserPreparedEffect, BrowserPreparedEffectKind
from phoenix_os.browser_automation.contracts import (
    BrowserPageDescriptor,
    BrowserSessionDescriptor,
)
from phoenix_os.browser_automation.profiles import BrowserNavigationTarget, BrowserProfile
from phoenix_os.policy import PhoenixPolicyError, PolicyEngine, PolicyRequest, SecurityContext


class _Digest(Protocol):
    def update(self, data: bytes) -> None: ...


class BrowserAuthorizationRejectedError(RuntimeError):
    """Browser authority failed closed without exposing policy or browser details."""

    def __init__(self) -> None:
        super().__init__("browser operation authorization failed")


@runtime_checkable
class BrowserAuthorizer(Protocol):
    """Authorize exact current browser intents; returned intents are data, not capabilities."""

    async def authorize_session_open(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent: ...

    async def authorize_session_close(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent: ...

    async def authorize_page_navigate(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        target: BrowserNavigationTarget,
        context: SecurityContext,
    ) -> AuthorityIntent: ...

    async def authorize_page_read(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent: ...

    async def authorize_element_fill(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent: ...

    async def authorize_element_click(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent: ...


def browser_profile_resource(profile: BrowserProfile) -> str:
    """Return the exact generation-bound canonical browser-profile resource."""

    _require_profile(profile)
    return f"browser:{profile.profile_id}/generation:{profile.generation}"


def browser_session_resource(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
) -> str:
    """Return the exact canonical browser-session resource after membership validation."""

    _require_session_binding(profile, session)
    return f"{browser_profile_resource(profile)}/session:{session.session_id}"


def browser_page_resource(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
    page: BrowserPageDescriptor,
) -> str:
    """Return the exact revision-bound canonical browser-page resource."""

    _require_page_binding(profile, session, page)
    return (
        f"{browser_session_resource(profile, session)}/page:{page.page_id}/revision:{page.revision}"
    )


def browser_element_resource(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
    page: BrowserPageDescriptor,
    prepared: BrowserPreparedEffect,
) -> str:
    """Return the exact prepared element resource; opaque IDs alone grant no authority."""

    _require_prepared_binding(profile, session, page, prepared)
    return f"{browser_page_resource(profile, session, page)}/element:{prepared.element_id}"


def browser_session_open_intent(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
) -> AuthorityIntent:
    """Build one fresh exact browser.session.open intent from trusted current state."""

    _require_session_binding(profile, session)
    return _intent(
        action=BROWSER_SESSION_OPEN_ACTION,
        resource=browser_profile_resource(profile),
        parameter_digest=_parameter_digest(
            BROWSER_SESSION_OPEN_ACTION,
            profile,
            session=session,
        ),
        freshness=_freshness(profile, session=session),
    )


def browser_session_close_intent(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
) -> AuthorityIntent:
    """Build one fresh exact browser.session.close intent."""

    _require_session_binding(profile, session)
    return _intent(
        action=BROWSER_SESSION_CLOSE_ACTION,
        resource=browser_session_resource(profile, session),
        parameter_digest=_parameter_digest(
            BROWSER_SESSION_CLOSE_ACTION,
            profile,
            session=session,
        ),
        freshness=_freshness(profile, session=session),
    )


def browser_page_navigate_intent(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
    page: BrowserPageDescriptor,
    target: BrowserNavigationTarget,
) -> AuthorityIntent:
    """Build one exact page.navigate intent for one server-owned navigation target."""

    _require_page_binding(profile, session, page)
    _require_target_binding(profile, target)
    return _intent(
        action=BROWSER_PAGE_NAVIGATE_ACTION,
        resource=browser_page_resource(profile, session, page),
        parameter_digest=_parameter_digest(
            BROWSER_PAGE_NAVIGATE_ACTION,
            profile,
            session=session,
            page=page,
            target=target,
        ),
        freshness=_freshness(profile, session=session, page=page),
    )


def browser_page_read_intent(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
    page: BrowserPageDescriptor,
) -> AuthorityIntent:
    """Build one exact page.read intent for the current page revision."""

    _require_page_binding(profile, session, page)
    return _intent(
        action=BROWSER_PAGE_READ_ACTION,
        resource=browser_page_resource(profile, session, page),
        parameter_digest=_parameter_digest(
            BROWSER_PAGE_READ_ACTION,
            profile,
            session=session,
            page=page,
        ),
        freshness=_freshness(profile, session=session, page=page),
    )


def browser_element_fill_intent(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
    page: BrowserPageDescriptor,
    prepared: BrowserPreparedEffect,
) -> AuthorityIntent:
    """Build one exact element.fill intent using only the prepared fill digest."""

    _require_prepared_binding(
        profile,
        session,
        page,
        prepared,
        expected_kind=BrowserPreparedEffectKind.FILL,
    )
    return _intent(
        action=BROWSER_ELEMENT_FILL_ACTION,
        resource=browser_element_resource(profile, session, page, prepared),
        parameter_digest=_parameter_digest(
            BROWSER_ELEMENT_FILL_ACTION,
            profile,
            session=session,
            page=page,
            prepared=prepared,
        ),
        freshness=_freshness(profile, session=session, page=page, prepared=prepared),
    )


def browser_element_click_intent(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
    page: BrowserPageDescriptor,
    prepared: BrowserPreparedEffect,
) -> AuthorityIntent:
    """Build one exact element.click intent for one zero-effect prepared click."""

    _require_prepared_binding(
        profile,
        session,
        page,
        prepared,
        expected_kind=BrowserPreparedEffectKind.CLICK,
    )
    return _intent(
        action=BROWSER_ELEMENT_CLICK_ACTION,
        resource=browser_element_resource(profile, session, page, prepared),
        parameter_digest=_parameter_digest(
            BROWSER_ELEMENT_CLICK_ACTION,
            profile,
            session=session,
            page=page,
            prepared=prepared,
        ),
        freshness=_freshness(profile, session=session, page=page, prepared=prepared),
    )


class PolicyEngineBrowserAuthorizer:
    """Apply fresh exact policy independently at each canonical browser boundary."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize_session_open(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        intent = browser_session_open_intent(profile, session)
        return await self._enforce(
            intent,
            context,
            {
                "profile_id": str(profile.profile_id),
                "profile_generation": str(profile.generation),
                "session_id": str(session.session_id),
                "page_id": str(session.page_id),
            },
        )

    async def authorize_session_close(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        intent = browser_session_close_intent(profile, session)
        return await self._enforce(
            intent,
            context,
            {
                "profile_id": str(profile.profile_id),
                "profile_generation": str(profile.generation),
                "session_id": str(session.session_id),
            },
        )

    async def authorize_page_navigate(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        target: BrowserNavigationTarget,
        context: SecurityContext,
    ) -> AuthorityIntent:
        intent = browser_page_navigate_intent(profile, session, page, target)
        return await self._enforce(
            intent,
            context,
            {
                "profile_id": str(profile.profile_id),
                "profile_generation": str(profile.generation),
                "session_id": str(session.session_id),
                "page_id": str(page.page_id),
                "page_revision": str(page.revision),
                "target_id": str(target.target_id),
            },
        )

    async def authorize_page_read(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        intent = browser_page_read_intent(profile, session, page)
        return await self._enforce(
            intent,
            context,
            {
                "profile_id": str(profile.profile_id),
                "profile_generation": str(profile.generation),
                "session_id": str(session.session_id),
                "page_id": str(page.page_id),
                "page_revision": str(page.revision),
            },
        )

    async def authorize_element_fill(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        intent = browser_element_fill_intent(profile, session, page, prepared)
        input_digest = prepared.input_digest
        if input_digest is None:  # pragma: no cover - BrowserPreparedEffect invariant
            raise BrowserAuthorizationRejectedError()
        attributes = {
            "profile_id": str(profile.profile_id),
            "profile_generation": str(profile.generation),
            "session_id": str(session.session_id),
            "page_id": str(page.page_id),
            "page_revision": str(page.revision),
            "element_id": str(prepared.element_id),
            "prepared_token": str(prepared.token),
            "effect_kind": prepared.kind.value,
            "input_digest": input_digest,
        }
        return await self._enforce(intent, context, attributes)

    async def authorize_element_click(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        intent = browser_element_click_intent(profile, session, page, prepared)
        return await self._enforce(
            intent,
            context,
            {
                "profile_id": str(profile.profile_id),
                "profile_generation": str(profile.generation),
                "session_id": str(session.session_id),
                "page_id": str(page.page_id),
                "page_revision": str(page.revision),
                "element_id": str(prepared.element_id),
                "prepared_token": str(prepared.token),
                "effect_kind": prepared.kind.value,
            },
        )

    async def _enforce(
        self,
        intent: AuthorityIntent,
        context: SecurityContext,
        attributes: dict[str, str],
    ) -> AuthorityIntent:
        _require_authenticated_context(context)
        attributes["intent_parameter_digest"] = intent.parameter_digest
        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=intent.action,
                    resource=intent.canonical_resource,
                    context=replace(context, confirmed=False),
                    attributes=attributes,
                )
            )
        except PhoenixPolicyError as exception:
            raise BrowserAuthorizationRejectedError() from exception
        return intent


def _intent(
    *,
    action: str,
    resource: str,
    parameter_digest: str,
    freshness: tuple[AuthorityFreshnessBinding, ...],
) -> AuthorityIntent:
    intent = AuthorityIntent(
        action=action,
        canonical_resource=resource,
        parameter_digest=parameter_digest,
        freshness_bindings=freshness,
    )
    try:
        BUILTIN_AUTHORITY_CATALOG.validate_intent(intent)
    except Exception as exception:
        raise BrowserAuthorizationRejectedError() from exception
    return intent


def _require_profile(profile: BrowserProfile) -> None:
    if not isinstance(profile, BrowserProfile):
        raise TypeError("profile must be BrowserProfile")


def _require_session_binding(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
) -> None:
    _require_profile(profile)
    if not isinstance(session, BrowserSessionDescriptor):
        raise TypeError("session must be BrowserSessionDescriptor")
    if session.profile_id != profile.profile_id or session.profile_generation != profile.generation:
        raise BrowserAuthorizationRejectedError()
    lifetime_seconds = (session.expires_at - session.created_at).total_seconds()
    if lifetime_seconds > profile.limits.session_ttl_seconds:
        raise BrowserAuthorizationRejectedError()


def _require_page_binding(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
    page: BrowserPageDescriptor,
) -> None:
    _require_session_binding(profile, session)
    if not isinstance(page, BrowserPageDescriptor):
        raise TypeError("page must be BrowserPageDescriptor")
    if page.session_id != session.session_id or page.page_id != session.page_id:
        raise BrowserAuthorizationRejectedError()


def _require_target_binding(
    profile: BrowserProfile,
    target: BrowserNavigationTarget,
) -> None:
    _require_profile(profile)
    if not isinstance(target, BrowserNavigationTarget):
        raise TypeError("target must be BrowserNavigationTarget")
    try:
        configured = profile.require_target(target.target_id)
    except KeyError as exception:
        raise BrowserAuthorizationRejectedError() from exception
    if configured != target:
        raise BrowserAuthorizationRejectedError()


def _require_prepared_binding(
    profile: BrowserProfile,
    session: BrowserSessionDescriptor,
    page: BrowserPageDescriptor,
    prepared: BrowserPreparedEffect,
    *,
    expected_kind: BrowserPreparedEffectKind | None = None,
) -> None:
    _require_page_binding(profile, session, page)
    if not isinstance(prepared, BrowserPreparedEffect):
        raise TypeError("prepared must be BrowserPreparedEffect")
    if (
        prepared.session_id != session.session_id
        or prepared.page_id != page.page_id
        or prepared.revision != page.revision
    ):
        raise BrowserAuthorizationRejectedError()
    if expected_kind is not None and prepared.kind is not expected_kind:
        raise BrowserAuthorizationRejectedError()


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise BrowserAuthorizationRejectedError()


def _freshness(
    profile: BrowserProfile,
    *,
    session: BrowserSessionDescriptor | None = None,
    page: BrowserPageDescriptor | None = None,
    prepared: BrowserPreparedEffect | None = None,
) -> tuple[AuthorityFreshnessBinding, ...]:
    bindings = [
        AuthorityFreshnessBinding(
            "browser.profile.generation",
            f"{profile.profile_id}:{profile.generation}",
        )
    ]
    if session is not None:
        bindings.append(AuthorityFreshnessBinding("browser.session", str(session.session_id)))
    if page is not None:
        bindings.append(
            AuthorityFreshnessBinding(
                "browser.page.revision",
                f"{page.page_id}:{page.revision}",
            )
        )
    if prepared is not None:
        bindings.append(AuthorityFreshnessBinding("browser.prepared.effect", str(prepared.token)))
    return tuple(bindings)


def _parameter_digest(
    action: str,
    profile: BrowserProfile,
    *,
    session: BrowserSessionDescriptor | None = None,
    page: BrowserPageDescriptor | None = None,
    target: BrowserNavigationTarget | None = None,
    prepared: BrowserPreparedEffect | None = None,
) -> str:
    digest = hashlib.sha256()
    _update_field(digest, "action", action)
    _update_profile(digest, profile)
    if session is not None:
        _update_session(digest, session)
    if page is not None:
        _update_page(digest, page)
    if target is not None:
        _update_target(digest, target)
    if prepared is not None:
        _update_prepared(digest, prepared)
    return "sha256:" + digest.hexdigest()


def _update_profile(digest: _Digest, profile: BrowserProfile) -> None:
    _update_field(digest, "profile.id", str(profile.profile_id))
    _update_field(digest, "profile.generation", str(profile.generation))
    _update_field(digest, "profile.adapter_id", str(profile.adapter_id))
    _update_sequence(
        digest,
        "profile.allowed_origins",
        tuple(origin.canonical for origin in profile.allowed_origins),
    )
    _update_field(digest, "profile.initial_targets.count", str(len(profile.initial_targets)))
    for index, target in enumerate(profile.initial_targets):
        prefix = f"profile.initial_targets.{index}"
        _update_field(digest, f"{prefix}.id", str(target.target_id))
        _update_field(digest, f"{prefix}.origin", target.origin.canonical)
        _update_field(digest, f"{prefix}.request_target", target.request_target)
    _update_field(
        digest,
        "profile.network.allow_public_networks",
        "true" if profile.network_policy.allow_public_networks else "false",
    )
    _update_sequence(
        digest,
        "profile.network.allowed_networks",
        profile.network_policy.allowed_networks,
    )
    limits = profile.limits
    for label in (
        "max_snapshot_title_chars",
        "max_snapshot_text_chars",
        "max_snapshot_text_bytes",
        "max_snapshot_elements",
        "max_element_name_chars",
        "max_element_value_chars",
        "max_fill_text_chars",
        "max_fill_text_bytes",
        "max_cookies",
        "max_cookie_bytes",
        "max_resolved_addresses",
        "max_redirects",
        "max_concurrent_sessions",
    ):
        _update_field(digest, f"profile.limits.{label}", str(getattr(limits, label)))
    _update_field(
        digest,
        "profile.limits.session_ttl_seconds",
        limits.session_ttl_seconds.hex(),
    )
    _update_field(
        digest,
        "profile.limits.operation_timeout_seconds",
        limits.operation_timeout_seconds.hex(),
    )
    _update_field(digest, "profile.javascript_enabled", "false")
    _update_field(digest, "profile.subresources_enabled", "false")
    _update_field(digest, "profile.downloads_enabled", "false")
    _update_field(digest, "profile.uploads_enabled", "false")
    _update_field(digest, "profile.persistent_storage_enabled", "false")
    _update_field(digest, "profile.max_pages_per_session", str(profile.max_pages_per_session))


def _update_session(digest: _Digest, session: BrowserSessionDescriptor) -> None:
    _update_field(digest, "session.profile_id", str(session.profile_id))
    _update_field(digest, "session.profile_generation", str(session.profile_generation))
    _update_field(digest, "session.id", str(session.session_id))
    _update_field(digest, "session.page_id", str(session.page_id))
    _update_field(
        digest,
        "session.created_at",
        session.created_at.astimezone(UTC).isoformat(timespec="microseconds"),
    )
    _update_field(
        digest,
        "session.expires_at",
        session.expires_at.astimezone(UTC).isoformat(timespec="microseconds"),
    )


def _update_page(digest: _Digest, page: BrowserPageDescriptor) -> None:
    _update_field(digest, "page.session_id", str(page.session_id))
    _update_field(digest, "page.id", str(page.page_id))
    _update_field(digest, "page.revision", str(page.revision))


def _update_target(digest: _Digest, target: BrowserNavigationTarget) -> None:
    _update_field(digest, "target.id", str(target.target_id))
    _update_field(digest, "target.origin", target.origin.canonical)
    _update_field(digest, "target.request_target", target.request_target)


def _update_prepared(digest: _Digest, prepared: BrowserPreparedEffect) -> None:
    _update_field(digest, "prepared.token", str(prepared.token))
    _update_field(digest, "prepared.kind", prepared.kind.value)
    _update_field(digest, "prepared.session_id", str(prepared.session_id))
    _update_field(digest, "prepared.page_id", str(prepared.page_id))
    _update_field(digest, "prepared.revision", str(prepared.revision))
    _update_field(digest, "prepared.element_id", str(prepared.element_id))
    _update_field(digest, "prepared.input_digest", prepared.input_digest)


def _update_sequence(digest: _Digest, label: str, values: tuple[str, ...]) -> None:
    _update_field(digest, f"{label}.count", str(len(values)))
    for index, value in enumerate(values):
        _update_field(digest, f"{label}.{index}", value)


def _update_field(digest: _Digest, label: str, value: str | None) -> None:
    label_bytes = label.encode("utf-8")
    digest.update(len(label_bytes).to_bytes(2, "big"))
    digest.update(label_bytes)
    if value is None:
        digest.update(b"\x00")
        return
    data = value.encode("utf-8")
    digest.update(b"\x01")
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)
