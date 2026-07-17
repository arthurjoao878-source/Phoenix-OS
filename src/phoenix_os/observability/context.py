"""Asynchronous trace-context propagation helpers."""

from __future__ import annotations

from contextvars import ContextVar, Token

from phoenix_os.observability.contracts import SpanContext

_ACTIVE_SPAN: ContextVar[SpanContext | None] = ContextVar("phoenix_active_span", default=None)


def current_span_context() -> SpanContext | None:
    """Return the active span context for the current asynchronous task."""

    return _ACTIVE_SPAN.get()


def set_span_context(context: SpanContext) -> Token[SpanContext | None]:
    return _ACTIVE_SPAN.set(context)


def reset_span_context(token: Token[SpanContext | None]) -> None:
    _ACTIVE_SPAN.reset(token)
