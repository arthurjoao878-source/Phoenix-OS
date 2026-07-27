"""Least-privilege administration for configured inference registrations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from phoenix_os.audit import (
    AuditCategory,
    AuditLedger,
    AuditOutcome,
    AuditSeverity,
)
from phoenix_os.events import EventBus
from phoenix_os.inference.authorization import inference_model_resource
from phoenix_os.inference.configuration import (
    InferenceProviderConfiguration,
    InferenceServiceConfiguration,
)
from phoenix_os.inference.contracts import ModelId, ModelProviderId
from phoenix_os.inference.errors import InferenceAdministrationAccessDeniedError
from phoenix_os.inference.registry import (
    InferenceRegistrationStatus,
    ModelProviderRegistry,
    ModelProviderState,
    ModelState,
)
from phoenix_os.inference.service import InferenceService, InferenceServiceSnapshot
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import PrincipalType, SecurityContext

DEFAULT_INFERENCE_ADMIN_PAGE_SIZE = 50
MAX_INFERENCE_ADMIN_PAGE_SIZE = 200

INFERENCE_PROVIDERS_READ_PERMISSION = "inference.provider.read"
INFERENCE_PROVIDERS_DISABLE_PERMISSION = "inference.provider.disable"
INFERENCE_PROVIDERS_ENABLE_PERMISSION = "inference.provider.enable"
INFERENCE_MODELS_READ_PERMISSION = "inference.model.read"
INFERENCE_MODELS_DISABLE_PERMISSION = "inference.model.disable"
INFERENCE_MODELS_ENABLE_PERMISSION = "inference.model.enable"
INFERENCE_HEALTH_READ_PERMISSION = "inference.health.read"

INFERENCE_PROVIDERS_RESOURCE = "inference:providers"
INFERENCE_MODELS_RESOURCE = "inference:models"
INFERENCE_RUNTIME_RESOURCE = "inference:runtime"


def inference_provider_resource(provider_id: ModelProviderId | str) -> str:
    provider = (
        provider_id if isinstance(provider_id, ModelProviderId) else ModelProviderId(provider_id)
    )
    return f"model-provider:{provider}"


@dataclass(frozen=True, slots=True)
class InferenceAdminPageRequest:
    offset: int = 0
    limit: int = DEFAULT_INFERENCE_ADMIN_PAGE_SIZE

    def __post_init__(self) -> None:
        if isinstance(self.offset, bool) or not isinstance(self.offset, int):
            raise TypeError("inference page offset must be an integer")
        if isinstance(self.limit, bool) or not isinstance(self.limit, int):
            raise TypeError("inference page limit must be an integer")
        if self.offset < 0:
            raise ValueError("inference page offset must not be negative")
        if not 1 <= self.limit <= MAX_INFERENCE_ADMIN_PAGE_SIZE:
            raise ValueError("inference page limit is outside supported bounds")


@dataclass(frozen=True, slots=True)
class InferenceAdminPageInfo:
    offset: int
    limit: int
    total: int
    returned: int

    def __post_init__(self) -> None:
        if min(self.offset, self.total, self.returned) < 0:
            raise ValueError("inference page counters must not be negative")
        if self.limit <= 0 or self.returned > self.limit or self.returned > self.total:
            raise ValueError("inference page counters are inconsistent")


@dataclass(frozen=True, slots=True)
class InferenceProviderView:
    """Provider inventory without endpoint, credential, or adapter-private details."""

    provider_id: ModelProviderId
    status: InferenceRegistrationStatus
    revision: int
    complete: bool
    streaming: bool
    models: int
    enabled_models: int
    endpoint_mode: str | None
    credential_configured: bool
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.revision <= 0 or self.models < 0 or not 0 <= self.enabled_models <= self.models:
            raise ValueError("inference provider view counters are invalid")
        if self.schema_version != 1:
            raise ValueError("unsupported inference provider view version")
        object.__setattr__(self, "status", InferenceRegistrationStatus(self.status))


@dataclass(frozen=True, slots=True)
class InferenceModelView:
    """Model inventory without provider model names, metadata, or generated content."""

    provider_id: ModelProviderId
    model_id: ModelId
    status: InferenceRegistrationStatus
    revision: int
    complete: bool
    streaming: bool
    max_messages: int
    max_message_chars: int
    max_total_input_chars: int
    max_output_tokens: int
    max_response_chars: int
    max_chunks: int
    max_chunk_chars: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.revision <= 0:
            raise ValueError("inference model view revision must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported inference model view version")
        object.__setattr__(self, "status", InferenceRegistrationStatus(self.status))


@dataclass(frozen=True, slots=True)
class InferenceProviderPage:
    items: tuple[InferenceProviderView, ...]
    page: InferenceAdminPageInfo


@dataclass(frozen=True, slots=True)
class InferenceModelPage:
    items: tuple[InferenceModelView, ...]
    page: InferenceAdminPageInfo


@dataclass(frozen=True, slots=True)
class InferenceAdministrationSnapshot:
    """Content-free subsystem health for operators and scoped service accounts."""

    runtime: InferenceServiceSnapshot
    providers: int
    enabled_providers: int
    models: int
    enabled_models: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if min(self.providers, self.enabled_providers, self.models, self.enabled_models) < 0:
            raise ValueError("inference administration counters must not be negative")
        if self.enabled_providers > self.providers or self.enabled_models > self.models:
            raise ValueError("inference administration enabled counters are invalid")
        if self.schema_version != 1:
            raise ValueError("unsupported inference administration snapshot version")


class InferenceAdministration:
    """Expose reviewed inventory and optimistic lifecycle transitions only."""

    def __init__(
        self,
        registry: ModelProviderRegistry,
        service: InferenceService,
        configuration: InferenceServiceConfiguration,
        *,
        events: EventBus,
        audit: AuditLedger | None = None,
        observability: ObservabilityHub | None = None,
    ) -> None:
        if not isinstance(registry, ModelProviderRegistry):
            raise TypeError("registry must be ModelProviderRegistry")
        if not isinstance(service, InferenceService):
            raise TypeError("service must be InferenceService")
        if not isinstance(configuration, InferenceServiceConfiguration):
            raise TypeError("configuration must be InferenceServiceConfiguration")
        if not isinstance(events, EventBus):
            raise TypeError("events must be EventBus")
        self._registry = registry
        self._service = service
        self._configuration = configuration
        self._events = events
        self._audit = audit
        self._observability = observability
        self._provider_configuration: Mapping[
            ModelProviderId,
            InferenceProviderConfiguration,
        ] = MappingProxyType({item.provider_id: item for item in configuration.providers})

    async def list_providers(
        self,
        context: SecurityContext,
        page: InferenceAdminPageRequest | None = None,
    ) -> InferenceProviderPage:
        self._authorize(context, INFERENCE_PROVIDERS_READ_PERMISSION, INFERENCE_PROVIDERS_RESOURCE)
        states = self._registry.list_provider_states()
        views = tuple(self._provider_view(state) for state in states)
        request = InferenceAdminPageRequest() if page is None else page
        items, info = _page(views, request)
        return InferenceProviderPage(items=items, page=info)

    async def list_models(
        self,
        context: SecurityContext,
        page: InferenceAdminPageRequest | None = None,
        *,
        provider_id: ModelProviderId | str | None = None,
    ) -> InferenceModelPage:
        self._authorize(context, INFERENCE_MODELS_READ_PERMISSION, INFERENCE_MODELS_RESOURCE)
        states = self._registry.list_model_states(provider_id)
        views = tuple(_model_view(state) for state in states)
        request = InferenceAdminPageRequest() if page is None else page
        items, info = _page(views, request)
        return InferenceModelPage(items=items, page=info)

    async def provider(
        self,
        provider_id: ModelProviderId | str,
        context: SecurityContext,
    ) -> InferenceProviderView:
        resource = inference_provider_resource(provider_id)
        self._authorize(context, INFERENCE_PROVIDERS_READ_PERMISSION, resource)
        return self._provider_view(self._registry.provider_state(provider_id))

    async def model(
        self,
        provider_id: ModelProviderId | str,
        model_id: ModelId | str,
        context: SecurityContext,
    ) -> InferenceModelView:
        provider = (
            provider_id
            if isinstance(provider_id, ModelProviderId)
            else ModelProviderId(provider_id)
        )
        model = model_id if isinstance(model_id, ModelId) else ModelId(model_id)
        resource = inference_model_resource(provider, model)
        self._authorize(context, INFERENCE_MODELS_READ_PERMISSION, resource)
        return _model_view(self._registry.model_state(provider, model))

    async def set_provider_enabled(
        self,
        provider_id: ModelProviderId | str,
        context: SecurityContext,
        *,
        enabled: bool,
        expected_revision: int,
    ) -> InferenceProviderView:
        permission = (
            INFERENCE_PROVIDERS_ENABLE_PERMISSION
            if enabled
            else INFERENCE_PROVIDERS_DISABLE_PERMISSION
        )
        resource = inference_provider_resource(provider_id)
        self._authorize(context, permission, resource)
        state = self._registry.set_provider_enabled(
            provider_id,
            enabled=enabled,
            expected_revision=expected_revision,
        )
        await self._signal(
            kind="provider",
            resource=resource,
            identifier=str(state.provider_id),
            state=state.status,
            revision=state.revision,
            permission=permission,
            context=context,
        )
        return self._provider_view(state)

    async def set_model_enabled(
        self,
        provider_id: ModelProviderId | str,
        model_id: ModelId | str,
        context: SecurityContext,
        *,
        enabled: bool,
        expected_revision: int,
    ) -> InferenceModelView:
        provider = (
            provider_id
            if isinstance(provider_id, ModelProviderId)
            else ModelProviderId(provider_id)
        )
        model = model_id if isinstance(model_id, ModelId) else ModelId(model_id)
        permission = (
            INFERENCE_MODELS_ENABLE_PERMISSION if enabled else INFERENCE_MODELS_DISABLE_PERMISSION
        )
        resource = inference_model_resource(provider, model)
        self._authorize(context, permission, resource)
        state = self._registry.set_model_enabled(
            provider,
            model,
            enabled=enabled,
            expected_revision=expected_revision,
        )
        await self._signal(
            kind="model",
            resource=resource,
            identifier=f"{provider}/{model}",
            state=state.status,
            revision=state.revision,
            permission=permission,
            context=context,
        )
        return _model_view(state)

    async def snapshot(self, context: SecurityContext) -> InferenceAdministrationSnapshot:
        self._authorize(context, INFERENCE_HEALTH_READ_PERMISSION, INFERENCE_RUNTIME_RESOURCE)
        providers = self._registry.list_provider_states()
        models = self._registry.list_model_states()
        return InferenceAdministrationSnapshot(
            runtime=await self._service.snapshot(),
            providers=len(providers),
            enabled_providers=sum(item.enabled for item in providers),
            models=len(models),
            enabled_models=sum(item.enabled for item in models),
        )

    def _provider_view(self, state: ModelProviderState) -> InferenceProviderView:
        configuration = self._provider_configuration[state.provider_id]
        model_states = self._registry.list_model_states(state.provider_id)
        endpoint_mode = (
            None
            if configuration.endpoint_policy is None
            else configuration.endpoint_policy.mode.value
        )
        return InferenceProviderView(
            provider_id=state.provider_id,
            status=state.status,
            revision=state.revision,
            complete=state.capabilities.complete,
            streaming=state.capabilities.streaming,
            models=len(model_states),
            enabled_models=sum(item.enabled for item in model_states),
            endpoint_mode=endpoint_mode,
            credential_configured=configuration.credential_policy is not None,
        )

    @staticmethod
    def _authorize(context: SecurityContext, permission: str, resource: str) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise InferenceAdministrationAccessDeniedError()
        if permission not in context.permissions and "*" not in context.permissions:
            raise InferenceAdministrationAccessDeniedError()
        if (
            context.principal_type is PrincipalType.SERVICE
            and context.attributes.get("resource") != resource
        ):
            raise InferenceAdministrationAccessDeniedError()

    async def _signal(
        self,
        *,
        kind: str,
        resource: str,
        identifier: str,
        state: InferenceRegistrationStatus,
        revision: int,
        permission: str,
        context: SecurityContext,
    ) -> None:
        name = f"inference.{kind}.{state.value}"
        metadata = {
            "identifier": identifier,
            "status": state.value,
            "revision": str(revision),
        }
        try:
            await self._events.emit(
                name,
                source=self._configuration.source,
                payload={},
                metadata=metadata,
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )
        except Exception:
            pass
        if self._audit is not None:
            try:
                await self._audit.record_security(
                    name,
                    category=AuditCategory.CONFIGURATION,
                    action=permission,
                    resource=resource,
                    context=context,
                    outcome=AuditOutcome.SUCCEEDED,
                    severity=AuditSeverity.INFO,
                    details=metadata,
                    source=self._configuration.source,
                )
            except Exception:
                pass
        if self._observability is not None:
            try:
                await self._observability.log(
                    name,
                    source=self._configuration.source,
                    message=f"inference {kind} lifecycle changed",
                    severity=Severity.INFO,
                    attributes=metadata,
                    correlation_id=context.correlation_id,
                    causation_id=context.causation_id,
                )
                await self._observability.metric(
                    "inference.administration.changes",
                    1,
                    source=self._configuration.source,
                    kind=MetricKind.COUNTER,
                    unit="change",
                    attributes={"kind": kind, "status": state.value},
                    correlation_id=context.correlation_id,
                    causation_id=context.causation_id,
                )
            except Exception:
                pass


def _model_view(state: ModelState) -> InferenceModelView:
    descriptor = state.descriptor
    limits = descriptor.limits
    return InferenceModelView(
        provider_id=descriptor.provider_id,
        model_id=descriptor.model_id,
        status=state.status,
        revision=state.revision,
        complete=descriptor.capabilities.complete,
        streaming=descriptor.capabilities.streaming,
        max_messages=limits.max_messages,
        max_message_chars=limits.max_message_chars,
        max_total_input_chars=limits.max_total_input_chars,
        max_output_tokens=limits.max_output_tokens,
        max_response_chars=limits.max_response_chars,
        max_chunks=limits.max_chunks,
        max_chunk_chars=limits.max_chunk_chars,
    )


def _page[T](
    values: Sequence[T],
    request: InferenceAdminPageRequest,
) -> tuple[tuple[T, ...], InferenceAdminPageInfo]:
    if not isinstance(request, InferenceAdminPageRequest):
        raise TypeError("page must be InferenceAdminPageRequest")
    total = len(values)
    items = tuple(values[request.offset : request.offset + request.limit])
    return items, InferenceAdminPageInfo(
        offset=request.offset,
        limit=request.limit,
        total=total,
        returned=len(items),
    )


def inference_provider_view_to_dict(view: InferenceProviderView) -> Mapping[str, object]:
    return {
        "provider_id": str(view.provider_id),
        "status": view.status.value,
        "revision": view.revision,
        "capabilities": {
            "complete": view.complete,
            "streaming": view.streaming,
        },
        "models": view.models,
        "enabled_models": view.enabled_models,
        "endpoint_mode": view.endpoint_mode,
        "credential_configured": view.credential_configured,
        "schema_version": view.schema_version,
    }


def inference_model_view_to_dict(view: InferenceModelView) -> Mapping[str, object]:
    return {
        "provider_id": str(view.provider_id),
        "model_id": str(view.model_id),
        "status": view.status.value,
        "revision": view.revision,
        "capabilities": {
            "complete": view.complete,
            "streaming": view.streaming,
        },
        "limits": {
            "max_messages": view.max_messages,
            "max_message_chars": view.max_message_chars,
            "max_total_input_chars": view.max_total_input_chars,
            "max_output_tokens": view.max_output_tokens,
            "max_response_chars": view.max_response_chars,
            "max_chunks": view.max_chunks,
            "max_chunk_chars": view.max_chunk_chars,
        },
        "schema_version": view.schema_version,
    }


def inference_provider_page_to_dict(page: InferenceProviderPage) -> Mapping[str, object]:
    return {
        "items": [inference_provider_view_to_dict(item) for item in page.items],
        "page": _page_info_to_dict(page.page),
    }


def inference_model_page_to_dict(page: InferenceModelPage) -> Mapping[str, object]:
    return {
        "items": [inference_model_view_to_dict(item) for item in page.items],
        "page": _page_info_to_dict(page.page),
    }


def inference_administration_snapshot_to_dict(
    snapshot: InferenceAdministrationSnapshot,
) -> Mapping[str, object]:
    runtime = snapshot.runtime
    return {
        "state": runtime.state.value,
        "accepting": runtime.accepting,
        "providers": {
            "providers": snapshot.providers,
            "enabled": snapshot.enabled_providers,
        },
        "models": {
            "models": snapshot.models,
            "enabled": snapshot.enabled_models,
        },
        "invocations": {
            "active": runtime.active,
            "started": runtime.started,
            "completed": runtime.completed,
            "rejected": runtime.rejected,
            "failed": runtime.failed,
            "cancelled": runtime.cancelled,
            "timed_out": runtime.timed_out,
            "forced_cancellations": runtime.forced_cancellations,
        },
        "last_started_at": (
            None if runtime.last_started_at is None else runtime.last_started_at.isoformat()
        ),
        "last_completed_at": (
            None if runtime.last_completed_at is None else runtime.last_completed_at.isoformat()
        ),
        "schema_version": snapshot.schema_version,
    }


def _page_info_to_dict(page: InferenceAdminPageInfo) -> Mapping[str, object]:
    return {
        "offset": page.offset,
        "limit": page.limit,
        "total": page.total,
        "returned": page.returned,
    }
