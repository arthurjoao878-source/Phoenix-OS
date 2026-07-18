# ADR-0030 — Capability-only durable jobs and lease fencing

- Status: Accepted
- Date: 2026-07-18

## Context

Delayed work carries authority beyond the request that created it. Persisting Python callables, import
paths, shell commands, or unrestricted serialized objects would bypass the existing capability,
policy, confirmation, and redaction boundaries. Competing workers and process restarts also make an
ordinary status flag insufficient to prevent stale completion.

## Decision

A Phoenix job stores only a registered capability name, JSON-compatible arguments, a trusted
`CapabilityContext`, schedule, retry policy, deadline, and non-sensitive metadata. Execution always
passes through `CapabilityRegistry`. Repositories claim due work atomically with bounded opaque lease
tokens. Only the exact active token may complete or fail an attempt; expired or cancelled tokens are
rejected. Durable state is encoded through the provider-neutral `StateStore` boundary.

## Consequences

Jobs reuse capability authorization, confirmation, deadlines, event facts, and provider error
normalization without introducing arbitrary code execution. Lease fencing prevents stale repository
updates, but external effects remain at least once: a provider can perform a side effect before losing
its lease. Capability providers therefore need idempotency keys or equivalent duplicate tolerance.
