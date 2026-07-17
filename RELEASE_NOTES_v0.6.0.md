# Phoenix OS v0.6.0 — Observability and Diagnostics

Phoenix OS v0.6.0 implements RFC-0006 and introduces a deterministic, vendor-neutral boundary for
structured logs, numeric metrics, and asynchronous traces.

## Highlights

- Immutable `LogRecord`, `MetricRecord`, `SpanContext`, and completed `SpanRecord` contracts.
- Portable severities, counter and gauge metric semantics, and span terminal states.
- Deterministic priority and registration-order delivery to synchronous or asynchronous sinks.
- Failure collection and optional aggregate export errors after every sink is attempted.
- Cancellation propagation without translation.
- Recursive redaction of sensitive structured attributes and Phoenix `SecretValue` objects.
- Nested asynchronous spans using `contextvars`.
- Automatic correlation and causation inheritance for logs and metrics emitted inside spans.
- Wildcard Event Bus observer with conservative severity mapping.
- Bounded `InMemorySink` with deterministic oldest-record eviction.
- Optional `RuntimeAssembler` ownership of the hub and Event Bus bridge.
- RFC-0006, ADR-0012, ADR-0013, architecture updates, migration guidance, and executable example.

## Compatibility

Existing v0.5.0 Kernel, Event Bus, Capability Registry, Runtime, Configuration System, direct Runtime
construction, and RuntimeAssembler calls remain valid. Observability is optional and vendor-specific
exporters remain external adapters.

## Security

Structured attributes are redacted before export. Free-text record names and messages are not parsed
or rewritten, so callers must never place credentials or sensitive payloads in those fields. The
core does not automatically capture stack traces, exception messages, local variables, prompts, or
request bodies.

## Validation

- Ruff: passed
- Ruff Format: passed
- mypy strict: passed
- pytest: 202 tests passed
- Examples: passed
- Wheel build and isolated installation: passed
