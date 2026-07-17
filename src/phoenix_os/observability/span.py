"""Asynchronous trace-span context manager."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextvars import Token
from datetime import UTC, datetime
from types import TracebackType
from typing import TYPE_CHECKING
from uuid import uuid4

from phoenix_os.observability.context import (
    current_span_context,
    reset_span_context,
    set_span_context,
)
from phoenix_os.observability.contracts import (
    ExportErrorPolicy,
    SpanContext,
    SpanRecord,
    SpanStatus,
)
from phoenix_os.observability.errors import SpanStateError

if TYPE_CHECKING:
    from phoenix_os.observability.hub import ObservabilityHub


class Span:
    """Record one completed operation and propagate its context to child tasks."""

    def __init__(
        self,
        hub: ObservabilityHub,
        *,
        name: str,
        source: str,
        attributes: Mapping[str, object],
        correlation_id: str | None,
        error_policy: ExportErrorPolicy,
    ) -> None:
        if not name.strip():
            raise ValueError("span name must not be blank")
        if not source.strip():
            raise ValueError("span source must not be blank")
        if correlation_id is not None and not correlation_id.strip():
            raise ValueError("correlation_id must not be blank")
        self._hub = hub
        self._name = name.strip()
        self._source = source.strip()
        self._attributes = dict(attributes)
        self._requested_correlation_id = correlation_id.strip() if correlation_id else None
        self._error_policy = error_policy
        self._context: SpanContext | None = None
        self._started_at: datetime | None = None
        self._token: Token[SpanContext | None] | None = None
        self._finished = False

    @property
    def context(self) -> SpanContext:
        if self._context is None:
            raise SpanStateError("span context is available only after the span is entered")
        return self._context

    async def __aenter__(self) -> Span:
        if self._started_at is not None or self._finished:
            raise SpanStateError("span instances cannot be entered more than once")

        parent = current_span_context()
        trace_id = parent.trace_id if parent is not None else uuid4()
        parent_span_id = parent.span_id if parent is not None else None
        correlation_id = self._requested_correlation_id
        if correlation_id is None and parent is not None:
            correlation_id = parent.correlation_id
        if correlation_id is None:
            correlation_id = str(trace_id)

        self._context = SpanContext(
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            correlation_id=correlation_id,
        )
        self._started_at = datetime.now(UTC)
        self._token = set_span_context(self._context)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc, traceback
        if self._context is None or self._started_at is None or self._token is None:
            raise SpanStateError("span was not entered")
        if self._finished:
            raise SpanStateError("span was already finished")

        self._finished = True
        status = SpanStatus.OK
        exception_type: str | None = None
        if exc_type is not None:
            exception_type = exc_type.__name__
            status = (
                SpanStatus.CANCELLED
                if issubclass(exc_type, asyncio.CancelledError)
                else SpanStatus.ERROR
            )

        record = SpanRecord(
            name=self._name,
            source=self._source,
            context=self._context,
            status=status,
            started_at=self._started_at,
            ended_at=datetime.now(UTC),
            attributes=self._attributes,
            exception_type=exception_type,
        )

        try:
            policy = self._error_policy if exc_type is None else ExportErrorPolicy.COLLECT
            await self._hub.emit(record, error_policy=policy)
        finally:
            reset_span_context(self._token)
