# ADR-0013 — Explicit redaction and asynchronous context propagation

- **Status:** Accepted
- **Date:** 2026-07-17

Structured attributes are recursively redacted before they cross the observability sink boundary.
Conventional secret keys and Phoenix `SecretValue` objects are replaced without revealing their
contents. Arbitrary free-text messages are not parsed or rewritten. Trace context is propagated with
`contextvars`; nested spans inherit trace and correlation identity and logs or metrics emitted inside
a span inherit correlation and causation automatically. Span failures record only exception types by
default, never messages, stacks, locals, or payloads.
