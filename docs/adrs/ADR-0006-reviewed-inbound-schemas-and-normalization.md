# ADR-0006: Reviewed inbound schemas and normalization

- **Status:** Accepted
- **Date:** 2026-07-25
- **Related RFC:** [RFC-0025](../rfcs/RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md)

## Context

External event producers control request bodies and may change fields, nesting,
types, and semantics independently from Phoenix. The internal Event Bus is a
trusted in-process contract whose event names and payloads may activate jobs,
workflows, plugins, or other privileged consumers.

Publishing external JSON directly would let callers choose an internal event
shape accidentally or deliberately. It would also allow newly added producer
fields to cross the trust boundary without code review and would make payload
bounds depend on generic parser behavior rather than one explicit event
contract.

Inbound event processing therefore needs a code-reviewed mapping between one
external event type and version and one bounded internal Event Bus event.

## Decision

Phoenix accepts an external event type only when exactly one
`InboundEventNormalizer` with an `InboundEventSchema` for that external type and
schema version has been registered before ingress routes become active.

The schema is the allowlisting boundary. It declares:

- the exact external event type and schema version;
- the exact internal Event Bus event type selected by Phoenix code;
- required and optional fields;
- whether unknown fields are rejected;
- maximum raw body and normalized payload sizes;
- maximum JSON depth, mapping width, sequence width, and string length.

The registry rejects duplicate event-type registrations. Runtime startup
validates every durable source against the registered schemas and fails closed
when a source references an unavailable or incompatible event type.

The transport performs bounded structural JSON parsing before normalization.
The normalizer receives only the parsed bounded mapping and returns a
JSON-compatible mapping. Phoenix then validates, canonicalizes, and bounds the
normalized result against the registered schema.

Raw request bodies are never published directly to the Event Bus. The external
caller cannot choose the internal Event Bus event name. Durable accepted-event
records contain the normalized canonical payload and safe provenance, not the
unrestricted raw body.

Changing a normalizer or schema is an external contract decision. Incompatible
changes require a new explicit event type or schema version rather than silently
changing the meaning of already accepted data.

## Consequences

Positive consequences:

- external producers never become implicit Event Bus publishers;
- every accepted field and internal event mapping receives code review;
- strict finite bounds apply before and after normalization;
- unknown fields can fail closed instead of expanding the trusted payload;
- durable normalized events remain deterministic across retry and restart;
- internal consumers receive a stable Phoenix-owned event contract.

Costs and constraints:

- every supported external event requires maintained schema and normalizer code;
- schema rollout must precede source enablement;
- incompatible producer changes require versioning or a new event type;
- generic pass-through integrations are intentionally unsupported;
- normalization failures reject the request rather than storing partially
  trusted data.

## Alternatives considered

### Publish the parsed external JSON directly

Rejected because caller-controlled fields and semantics would become an internal
Event Bus contract without review.

### Let the source choose the internal event name

Rejected because source administration is not permission to target arbitrary
internal consumers.

### Use one permissive schema for every producer

Rejected because limits and allowed fields must follow the business contract of
one event type, not the broadest producer Phoenix may ever support.

### Normalize only when the publisher worker runs

Rejected because durable acceptance must commit the exact trusted payload and
digest that idempotency and later publication will use.

### Store the raw body for future reprocessing

Rejected because unrestricted request bodies expand persistence exposure and
allow future code to reinterpret data that was not accepted under its current
contract.

## Supersession criteria

A future ADR may replace this decision only if external callers still cannot
select internal Event Bus contracts, every accepted field remains explicitly
reviewed and bounded, durable identity is based on deterministic trusted data,
and unrestricted raw bodies remain outside ordinary persistence.
