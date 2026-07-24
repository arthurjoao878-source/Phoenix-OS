# ADR-0001: Explicit webhook serializers and durable envelopes

- **Status:** Accepted
- **Date:** 2026-07-24
- **Related RFC:** [RFC-0024](../rfcs/RFC-0024-durable-signed-webhooks-and-event-subscriptions.md)

## Context

The Phoenix Event Bus carries internal events for many consumers. Its payloads
may contain fields that are useful inside the process but unsuitable for
external disclosure, unstable across releases, or too large for a bounded
outbound contract.

Sending Event Bus payloads directly would make every producer an accidental
public API and would allow new internal fields to cross the trust boundary
without an explicit review. Serializing only when an HTTP attempt begins would
also make retries dependent on mutable code and current application state.

Webhook delivery must instead remain deterministic across restart, retry, and
manual redrive.

## Decision

Phoenix exports an Event Bus event only when a
`WebhookPayloadSerializer` for its exact `WebhookEventType` has been registered
before the webhook Event Bus adapter starts.

The registry:

- rejects duplicate event-type registrations;
- verifies that a serializer returns the registered event type;
- canonicalizes the JSON-compatible payload;
- enforces the event type's payload-size bound;
- validates subscription resource filters against explicitly supported fields;
- ignores Event Bus events with no registered webhook event type.

For every matching active subscription, Phoenix creates at most one durable
delivery for the stable pair `(subscription_id, source_event_id)`. The delivery
stores the canonical body, payload digest, source identity, correlation facts,
signing-key version, retry policy facts, and lifecycle metadata before dispatch.

The delivery identifier, canonical body, payload digest, and deduplication
identity remain unchanged across automatic retries, restart recovery, and
explicit redrive.

## Consequences

Positive consequences:

- internal Event Bus payloads are not external contracts;
- every exported field passes a deliberate serializer review;
- retries do not re-run a potentially changed serializer;
- duplicate Event Bus handling cannot create duplicate business deliveries;
- resource filters operate only on declared serializer output;
- persisted delivery content can be validated for corruption.

Costs and constraints:

- every exported event requires maintained serializer code;
- changing payload semantics requires an explicit contract decision;
- canonical bodies consume durable storage;
- the system cannot retroactively add a subscription to an already processed
  source event without a separate replay design.

## Alternatives considered

### Send the raw Event Bus payload

Rejected because it creates an implicit public API, expands data exposure when
internal producers change, and bypasses payload-specific review.

### Serialize on every delivery attempt

Rejected because code changes could produce different signed bodies for the
same delivery and because retry would depend on mutable source data.

### Deduplicate only at the receiver

Rejected because Phoenix would still spend outbound capacity, create divergent
attempt histories, and require every receiver to compensate for scheduler races.

### Persist only a reference to the source event

Rejected because Event Bus retention is not the durable webhook contract and
the source event may be unavailable or semantically different after restart.

## Supersession criteria

A future ADR may replace this decision only if it preserves explicit field
allowlisting, stable delivery identity, deterministic retry bodies, and a
durable deduplication boundary.
