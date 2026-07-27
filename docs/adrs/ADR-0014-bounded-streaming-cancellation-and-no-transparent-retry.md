# ADR-0014: Bounded streaming, cancellation, and no transparent retry

- **Status:** Accepted
- **Date:** 2026-07-27
- **Related RFC:** [RFC-0026](../rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md)

## Context

Model providers can stream slowly, emit malformed or reordered frames, exceed
declared output, ignore cancellation, or charge for duplicate requests.
Unbounded buffers, ambiguous terminal state, and automatic retries would make
resource use and completion semantics unsafe.

## Decision

Inference applies finite global, provider, model, and request limits. Admission
occurs before credential leasing or provider execution. The most restrictive
applicable concurrency and content limit wins.

Complete execution returns one validated response. Streaming returns ordered,
bounded immutable chunks followed by exactly one terminal record. Missing,
duplicate, extra, out-of-order, mismatched, oversized, or over-budget output
fails closed. Partial output is not reported as complete.

Deadlines, first-byte timeout, total duration, output bytes, requested tokens,
response characters, chunk count, chunk characters, input size, and
cancellation grace are finite.

Cancellation is cooperative and bounded. Phoenix stops accepting output,
signals the adapter, bounds cleanup, revokes credential leases, and releases
admission capacity even when the provider cannot undo remote work.

There is no transparent retry after provider execution begins. Providers may
charge or produce different output, so caller retry is explicit and requires a
new authorization and admission decision.

## Consequences

Positive consequences:

- memory, time, token, byte, and concurrency use are bounded;
- successful streams have one unambiguous terminal state;
- malformed provider behavior cannot be reported as success;
- cancellation releases local authority and capacity within finite bounds;
- billable or nondeterministic work is not duplicated invisibly.

Costs and constraints:

- partial text may have been observed before a failed terminal outcome;
- cancellation cannot guarantee remote provider rollback;
- callers must implement explicit retry decisions;
- adapters must expose execution phase and cooperative cancellation without
  leaking provider internals;
- saturation may reject work instead of queueing indefinitely.

## Alternatives considered

### Buffer an entire stream and validate only at the end

Rejected because memory and first-byte behavior would be unbounded or misleading.

### Accept end-of-iterator as successful completion

Rejected because absence of a validated terminal record is ambiguous.

### Retry timeouts and transport failures automatically

Rejected because provider execution may already have started or become billable.

### Trust adapter output ordering and declared sizes

Rejected because adapters and remote responses are within the threat model.

### Wait indefinitely for cancellation cleanup

Rejected because shutdown and caller cancellation must remain finite.

## Supersession criteria

A future ADR may change streaming or retry semantics only if every dimension
remains finite, exactly one terminal record defines success, cancellation
releases local capacity within a bound, and provider work is never duplicated
transparently after execution begins.
