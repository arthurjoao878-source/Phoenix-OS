# ADR-0007: Per-source authentication, replay, and idempotency

- **Status:** Accepted
- **Date:** 2026-07-25
- **Related RFC:** [RFC-0025](../rfcs/RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md)

## Context

External event producers differ in credential custody and deployment model.
Some integrations can share an HMAC key, while Phoenix-managed automation may
already use RFC-0023 service accounts. Combining both proofs in one request or
using ambient browser credentials would blur trust boundaries and create
downgrade paths.

Network retries also mean the same business event can arrive more than once.
Phoenix must distinguish a safe retry from replay, nonce reuse, request
conflict, and a different event reusing the same producer identifier. These
decisions must survive process restart when durable repositories are configured.

## Decision

Every `InboundEventSource` selects exactly one authentication policy:

- `InboundHmacPolicy`, using `hmac-sha256-v1` and an exact versioned
  `SecretRef`; or
- `InboundServiceAccountPolicy`, using RFC-0023 authentication, replay
  protection, exact `inbound_event.submit` action, concrete resource, and
  central policy enforcement.

HMAC requests bind the signature to the source identifier, request identifier,
source event identifier, timestamp, nonce, and SHA-256 digest of the exact raw
body. Verification leases only the exact configured key version through
`SecretsManager`, compares in constant time, clears temporary key bytes, and
revokes the lease after verification. HMAC requests cannot contain
`Authorization`.

Service-account requests cannot contain HMAC signature or key-version headers.
They require a trusted transport context from the shared Control Plane listener,
API-token authentication, timestamp and nonce replay admission, exact request
target and body digest, the source policy resource, and central policy approval.

Both modes require bounded, canonical evidence:

- `X-Phoenix-Inbound-Request-Id`;
- `X-Phoenix-Inbound-Event-Id`;
- `X-Phoenix-Inbound-Timestamp`;
- `X-Phoenix-Inbound-Nonce`.

After authentication and normalization, Phoenix atomically reserves replay and
source-event identities with durable accepted-event persistence. The same source
event identifier and same normalized digest return the same stable receipt. The
same source event identifier with a different normalized digest returns a
generic conflict. Reused request identifiers, nonces, stale timestamps, future
timestamps, malformed credentials, and invalid proofs fail closed.

Authentication and replay failures expose generic public errors. They do not
reveal whether a source exists, which key version matched, which replay identity
collided, or which internal policy decision failed.

## Consequences

Positive consequences:

- each source has one unambiguous authentication contract;
- HMAC rotation uses explicit immutable key versions;
- RFC-0023 sources reuse reviewed token, replay, transport, and policy
  boundaries;
- replay and idempotency survive restart with State Store-backed repositories;
- producer retries can recover one stable receipt without duplicating business
  events;
- conflicting identifier reuse is rejected before publication;
- public errors resist source and credential enumeration.

Costs and constraints:

- producers must retain stable request and event identifiers correctly;
- clocks require a bounded operational tolerance;
- HMAC deployments must retain predecessor versions during rotation windows;
- service-account sources require the complete RFC-0023 security stack;
- atomic durability couples replay capacity and accepted-event capacity;
- a rejected replay record cannot be deleted merely to force the request
  through.

## Alternatives considered

### Accept HMAC and service-account proof in the same request

Rejected because ambiguous credentials create downgrade behavior and unclear
audit provenance.

### Reuse browser sessions or CSRF proofs for source submission

Rejected because browser identity, machine identity, replay evidence, and
transport trust have different threat models.

### Resolve an unversioned latest HMAC key

Rejected because retries and rotation would depend on mutable ambient key state.

### Keep replay evidence only in process memory

Rejected because restart would reopen the replay window for durable sources and
accepted events.

### Treat every repeated source event identifier as success

Rejected because a different normalized digest under the same identifier is a
producer conflict, not an idempotent retry.

### Deduplicate only after Event Bus publication

Rejected because duplicate external requests could create multiple durable work
items and observable internal side effects before detection.

## Supersession criteria

A replacement ADR must retain one explicit authentication mode per source,
versioned and bounded credential handling, trusted transport context for
service accounts, durable replay evidence, stable source-event idempotency,
generic public failures, and atomic conflict detection before publication.
