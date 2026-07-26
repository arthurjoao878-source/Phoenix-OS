# ADR-0009: Durable acceptance and at-least-once publication

- **Status:** Accepted
- **Date:** 2026-07-25
- **Related RFC:** [RFC-0025](../rfcs/RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md)

## Context

An inbound producer needs to know whether Phoenix durably accepted an event, not
whether every internal consumer has already completed. Publishing synchronously
before persistence would lose accepted work when the process stops and could
produce internal side effects before replay and idempotency state commits.

Networks, Event Bus handlers, and processes can fail after an internal event is
observed but before Phoenix records completion. Exactly-once delivery cannot be
guaranteed across that boundary without transactionally coupling every consumer.

## Decision

Phoenix separates durable acceptance from internal Event Bus publication.

After transport validation, authentication, policy, normalization, replay, and
idempotency checks, one atomic repository operation commits:

- replay reservations;
- the stable source-event digest index;
- one immutable accepted-event identity;
- the normalized canonical payload;
- safe source and correlation provenance;
- retry and scheduling metadata.

A success response and stable receipt are returned only after that durable
acceptance commits. No raw request body is published or persisted.

A Runtime-owned `InboundPublisher` later scans bounded due work, claims one
accepted event with optimistic revision checks, and publishes the exact
code-selected internal event type and normalized payload to the Event Bus.
Publication is asynchronous and at-least-once.

Each accepted event preserves one immutable ordered attempt history and one
finite global attempt budget. Outcomes are classified as succeeded, retryable,
or terminal. Retryable failures use deterministic bounded backoff. Exhausted or
terminal work reaches a dead-letter or discarded terminal state according to
the durable source and event facts.

Runtime startup recovers interrupted publishing in bounded batches. Because an
Event Bus consumer may already have observed the event, recovery consumes and
records the interrupted attempt rather than pretending it never began. It then
schedules another bounded attempt or reaches a terminal state.

Explicit redrive requires exact authorization and an eligible dead letter. It
preserves accepted-event identifier, normalized payload, source-event identity,
digest, and prior attempts. It never resets counters or rewrites history.

Internal Event Bus consumers must be idempotent with respect to the stable
accepted-event identity because at-least-once publication can repeat the same
business event.

## Consequences

Positive consequences:

- an HTTP success means durable acceptance, not volatile queueing;
- replay and source-event idempotency commit with accepted work;
- process restart cannot silently lose committed events;
- publication failures do not require external producers to resubmit blindly;
- retry, recovery, dead letter, and redrive retain one forensic history;
- internal consumers receive one stable event identity across attempts;
- admission and publisher work remain independently bounded.

Costs and constraints:

- Event Bus consumers must tolerate duplicate publication;
- accepted events consume durable storage before publication completes;
- a producer receipt does not mean every internal consumer has succeeded;
- recovery may publish again after an ambiguous interruption;
- exhausted work requires an explicit new business event or authorized redrive;
- repository corruption or incompatible schema state fails startup closed.

## Alternatives considered

### Publish synchronously before returning the HTTP response

Rejected because internal side effects could occur before replay and accepted
state commit, and process failure could leave no stable receipt.

### Persist only after successful Event Bus publication

Rejected because a crash after publication would allow the producer retry to
create another internal event without durable idempotency evidence.

### Promise exactly-once Event Bus delivery

Rejected because Phoenix cannot atomically commit every independent consumer's
side effects with the inbound repository.

### Reset attempt history during redrive

Rejected because it defeats finite safety limits and destroys operational and
security history.

### Re-normalize the raw request for every attempt

Rejected because raw bodies are not the durable trusted contract and code
changes could alter the meaning of one accepted event.

## Supersession criteria

A future publication ADR must preserve durable acceptance before success,
atomic replay and accepted-event identity, immutable trusted payloads, bounded
work, stable retry and redrive identity, explicit terminal states, and honest
delivery semantics for internal consumers.
