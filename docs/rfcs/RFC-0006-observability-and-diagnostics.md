# RFC-0006 — Observability and Diagnostics

- **Status:** Accepted
- **Version:** 0.6.0
- **Date:** 2026-07-17

## Summary

Phoenix OS already emits immutable lifecycle facts through the Event Bus, but applications still
need a safe and portable way to export logs, metrics, and traces without coupling the core to a
specific logging framework, telemetry vendor, broker, database, or file format. This RFC defines a
small structured observability boundary with deterministic sink delivery, asynchronous trace
context, bounded diagnostic storage, explicit failure policy, and recursive secret redaction.

## Goals

- Represent logs, numeric metrics, and completed trace spans as immutable records.
- Deliver records to sinks in deterministic priority and registration order.
- Isolate sink failures while preserving cancellation.
- Propagate trace and correlation context through asynchronous tasks.
- Redact structured secrets before records cross the sink boundary.
- Bridge Event Bus facts into structured log records without changing Event Bus semantics.
- Integrate observability ownership and the event bridge with `RuntimeAssembler`.
- Keep exporters and vendor-specific telemetry adapters outside the Phoenix core.

## Non-goals

- Replacing Python's standard logging module in existing applications.
- Implementing OpenTelemetry, OTLP, Prometheus, syslog, tracing backends, or remote collectors.
- Persisting records, rotating files, retrying exports, batching, sampling, or aggregation.
- Inspecting or rewriting arbitrary free-text log messages.
- Automatically capturing stack traces, local variables, request bodies, credentials, or prompts.
- Treating observability records as commands or control-plane messages.

## Signal contracts

Phoenix exposes three immutable record types:

- `LogRecord` for structured diagnostics with a portable `Severity`;
- `MetricRecord` for finite numeric counter and gauge samples;
- `SpanRecord` for one completed asynchronous operation.

All records have validated names and sources. Structured attributes are recursively frozen. Sets are
rejected because their iteration order is not deterministic. Timestamps must be timezone-aware.
Counter values cannot be negative, and metric values must be finite.

## Observability Hub

`ObservabilityHub` is the in-process export coordinator. Sinks are registered with an integer
priority and an opaque `SinkRegistration`. Records are exported serially in descending priority and
then registration order. This preserves deterministic behavior and avoids hidden background tasks.

A sink may be synchronous or asynchronous. Sink failures are collected while later sinks continue.
`ExportErrorPolicy.COLLECT` returns an `ExportReport`; `RAISE` raises `ObservationExportError` only
after all sinks have been attempted. `asyncio.CancelledError` is never translated or collected.

Closing the hub clears registrations and rejects future records. Closing does not implicitly close
sink objects because exporter ownership belongs to the host adapter. The reference `InMemorySink`
can be closed independently.

## Redaction

`RedactionPolicy` processes structured attributes immediately before export. It:

- redacts conventional credential keys such as passwords, tokens, API keys, cookies, authorization,
  private keys, and secrets;
- traverses nested mappings and sequences;
- converts portable values such as dates, UUIDs, and paths to strings;
- converts unknown objects to a type marker instead of calling arbitrary `repr()` or `str()`;
- recognizes Phoenix `SecretValue` wrappers without revealing their contents;
- enforces a maximum recursion depth.

Redaction applies only to structured attributes. Free-text messages are not parsed because broad
string scrubbing is unreliable and may either leak data or destroy useful diagnostics. Callers must
never place secrets in record names or messages.

## Trace context

`ObservabilityHub.span(...)` returns an asynchronous context manager. Entering a span creates a
`SpanContext` containing a trace ID, span ID, optional parent span ID, and correlation ID. Nested
spans inherit the trace and correlation IDs and reference the active span as their parent.

Context is stored in `contextvars`, so independent asynchronous tasks receive normal Python context
propagation semantics. Logs and metrics emitted inside a span inherit its correlation ID and use the
active span ID as their causation ID unless explicitly overridden.

A span exports exactly one `SpanRecord` when it exits. Normal completion is `OK`, ordinary
exceptions are `ERROR`, and cancellation is `CANCELLED`. Only the exception type is recorded; the
exception message and stack are not captured automatically. Application exceptions and
cancellation always propagate.

## Event Bus bridge

`EventObserver` is a lifecycle component that subscribes to the wildcard Event Bus channel and
converts every event into one structured `LogRecord`. The original event name, source, ID, payload,
metadata, correlation, and causation are retained as structured attributes and pass through the
redaction policy.

The default severity mapper classifies failure/error events as `ERROR`, denied/cancelled/rejected
facts as `WARNING`, and other facts as `INFO`. Applications may supply another mapper.

The bridge is observational only. It does not publish new Event Bus events, alter dispatch reports,
retry handlers, or turn telemetry into commands.

## Runtime integration

`RuntimeAssembler` accepts an optional `ObservabilityHub`. When present, it exposes the hub as the
named `observability` service and registers lifecycle components in this order:

1. observability hub;
2. Event Bus observer, unless disabled;
3. composed application lifecycle services.

Because shutdown is reversed, application services stop first, the observer unsubscribes next, and
the hub closes last. This captures application and most Runtime lifecycle facts while avoiding
exports after closure. Direct `PhoenixRuntime(...)` construction remains supported.

## Security and failure model

The observability subsystem is deliberately fail-soft under the default collection policy. Exporter
failure does not change Kernel, Capability Registry, Event Bus, or Runtime business behavior.
Strict callers may opt into aggregate export errors.

Structured redaction reduces accidental disclosure but is not a substitute for access control,
secret management, disk encryption, process isolation, or secure exporter configuration. Sinks are
trusted adapters and may transmit records outside the process.

## Compatibility

RFC-0006 adds a new package and optional `RuntimeAssembler` arguments. Existing Kernel, Event Bus,
Capability Registry, Runtime, Configuration, and direct construction APIs remain valid.

## Acceptance criteria

- Log, metric, span, registration, report, and snapshot contracts are immutable.
- Sink delivery order and failure behavior are deterministic.
- Cancellation propagates from sinks and spans.
- Trace context nests correctly and is reset after span exit.
- Structured attributes are redacted before every export.
- Event Bus facts can be observed without changing Event Bus behavior.
- Runtime composition exposes and owns the optional observability service.
- Ruff, Ruff Format, mypy strict, pytest, examples, build, and isolated installation pass.
