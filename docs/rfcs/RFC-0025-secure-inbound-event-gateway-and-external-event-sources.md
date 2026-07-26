# RFC-0025: Secure Inbound Event Gateway and External Event Sources

- Status: Accepted
- Target release: Phoenix OS v0.25.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0002, RFC-0007, RFC-0009, RFC-0011, RFC-0012, RFC-0022, RFC-0023, and RFC-0024

## Summary

RFC-0025 defines an optional secure inbound event gateway for external systems
that need to submit reviewed events into Phoenix OS.

Inbound events are authenticated, replay-resistant, schema-allowlisted, bounded,
durably accepted, auditable, and published asynchronously by the Phoenix
Runtime. External request bodies never become unrestricted Event Bus payloads.
Every accepted event is decoded by an explicitly registered schema, normalized
to an immutable safe record, persisted without authentication material, and
published under a reviewed internal event type.

The gateway is disabled by default. It creates no listener, route, source,
credential, schema registration, event, or remote exposure unless explicitly
configured.

## Motivation

RFC-0024 gives Phoenix OS a secure way to deliver selected internal events to
external receivers. Phoenix OS still lacks the inverse boundary: a supported way
for external systems to submit events without gaining command authority or
direct access to the Event Bus.

A generic HTTP endpoint would bypass source authentication, replay protection,
schema review, durable acceptance, idempotency, policy evaluation, request
limits, audit requirements, and Runtime lifecycle ownership. A dedicated ingress
subsystem must separate untrusted transport evidence from trusted internal event
facts and fail closed before publication.

## Goals

- Optional inbound sources disabled by default
- Explicit source registration and lifecycle state
- Explicit schema-versioned external event types
- Bounded JSON request bodies and exact media-type validation
- HMAC-SHA-256 authentication with exact versioned secret references
- Optional RFC-0023 service-account authentication
- Timestamp, nonce, request identifier, and body-digest replay evidence
- Durable replay reservations across Runtime restarts
- Stable source-event identifiers and idempotent duplicate handling
- Conflict rejection for identifier reuse with different content
- Safe normalization before persistence
- Durable asynchronous Event Bus publication
- At-least-once publication with stable event identity
- Bounded retry, recovery, dead-letter, and explicit redrive
- Per-source and global admission limits
- Safe audit facts, metrics, health snapshots, and receipts
- Maintainer-only administration and optional machine administration
- RuntimeAssembler lifecycle ownership
- Compatibility with Phoenix OS v0.24.0 deployments

## Non-goals

- Arbitrary public webhook compatibility
- General-purpose HTTP ingestion
- Caller-selected internal Event Bus names
- Arbitrary JSON transformation scripts
- Direct command, capability, job, or workflow execution
- Treating an external source as an operator or Maintainer
- Browser-cookie, CSRF, or human step-up authentication
- Exactly-once behavior across every failure boundary
- Raw authentication-header or plaintext-secret persistence
- Unrestricted raw request-body persistence
- Files, multipart forms, XML, compressed bodies, or unbounded streams
- Automatic Internet exposure
- Automatic source, key, schema, route, scope, or permission creation

## Threat model

The gateway treats clients, request bodies, headers, timestamps, nonces,
source-event identifiers, and network metadata as untrusted. The implementation
must address credential theft or revocation, replay across restart, nonce reuse,
identifier collisions, conflicting duplicates, malformed or deeply nested JSON,
content-type confusion, event-type confusion, internal-name injection, source
enumeration, authentication brute force, admission exhaustion, partial durable
writes, interrupted publication, state corruption, and secret or payload leakage.

## Security invariants

1. The gateway is disabled unless explicitly configured.
2. Enabling it does not change listener binding, TLS, trusted-proxy, CIDR, or public-origin configuration.
3. Every source has a stable server-side identifier and explicit active, disabled, or revoked state.
4. Source identity, authentication mode, event types, schemas, routes, and limits come from trusted configuration, not request bodies.
5. Every accepted event type has an explicitly registered schema-versioned normalizer.
6. Raw request bodies are never published directly to the Event Bus.
7. Callers cannot choose arbitrary internal Event Bus event names.
8. Normalizers return only bounded allowlisted JSON-compatible fields.
9. Authentication completes before schema-specific processing that could reveal source configuration.
10. HMAC sources use exact versioned Secrets Vault references resolved only during verification.
11. Plaintext HMAC secrets are never persisted in source, replay, submission, or event state.
12. Service-account sources retain RFC-0023 lifecycle, replay, throttling, scope, resource, transport, and policy checks.
13. Browser cookies, CSRF proofs, operator sessions, and human step-up proofs cannot authenticate sources.
14. The exact request-body bytes are hashed before JSON decoding.
15. HMAC verification covers scheme version, source ID, request ID, source-event ID, timestamp, nonce, and body digest.
16. Signature and digest comparisons use constant-time verification.
17. Timestamps are timezone-aware and inside a bounded acceptance window.
18. Nonces and request identifiers are bounded, source-scoped, single-use, and durably reserved.
19. Replay reservations survive Runtime and process restarts.
20. A repeated source-event ID with the same normalized digest is idempotent and returns the stable receipt.
21. A repeated source-event ID with a different normalized digest fails closed as a conflict.
22. Replay reservation, digest indexing, and accepted-event persistence are atomic.
23. A success response is not returned until durable acceptance commits.
24. Accepted records contain normalized payloads only, never raw authentication headers or unrestricted bodies.
25. Event publication is asynchronous and at-least-once.
26. Retry and recovery reuse the stable event ID and immutable normalized payload.
27. Payload, nesting, headers, timeout, replay, rate, queue, retry, retention, and concurrency limits are finite.
28. Disablement or revocation is checked before acceptance and redrive.
29. Generic authentication failures do not reveal source, key, token, replay, scope, resource, or policy details.
30. Secrets, authorization headers, signatures, raw bodies, internal exceptions, and sensitive network identities are excluded from safe output.
31. External source identity never implies operator, Maintainer, capability, command, job, or workflow authority.
32. Existing v0.24.0 behavior remains unchanged when inbound configuration is absent.

## Proposed contracts

- `InboundEventSource`
- `InboundEventSourceStatus`
- `InboundAuthenticationPolicy`
- `InboundHmacPolicy`
- `InboundServiceAccountPolicy`
- `InboundEventType`
- `InboundEventSchema`
- `InboundEventNormalizer`
- `InboundRequestEvidence`
- `InboundAcceptedEvent`
- `InboundPublicationAttempt`
- `InboundEventReceipt`
- `InboundReplayReservation`
- `InboundSourceRepository`
- `InboundEventRepository`
- `InboundReplayRepository`
- `InboundAuthenticationVerifier`
- `InboundSchemaRegistry`
- `InboundEventGateway`
- `InboundEventPublisher`
- `InboundEventManager`
- `InboundEventSnapshot`

## Source and schema model

A source binds a stable identifier, display name, lifecycle state, exactly one
authentication policy, allowed external event types, request limits, timestamp
and replay windows, admission limits, optional reviewed network restrictions,
retry policy, retention policy, and revision metadata. Sources do not contain
plaintext credentials, arbitrary normalizer code, dynamic Event Bus names, or
implicit network authority.

Every external event type registers a stable name, external schema version,
reviewed internal Event Bus event type, trusted normalizer, raw and normalized
size limits, structural JSON limits, required and optional fields, unknown-field
behavior, and compatibility policy.

The accepted event contains a schema version, stable accepted-event ID, source
ID, source-event ID, external event type and schema version, internal event type,
occurrence and acceptance timestamps, normalized payload, normalized digest, and
bounded Phoenix-approved correlation metadata.

## Ingress HTTP protocol

The initial transport uses an exact fixed POST route under the existing
control-plane HTTP server. Routes are registered only when the subsystem and the
specific source are enabled.

Requests use:

- `Content-Type: application/json`
- `X-Phoenix-Inbound-Request-Id`
- `X-Phoenix-Inbound-Event-Id`
- `X-Phoenix-Inbound-Timestamp`
- `X-Phoenix-Inbound-Nonce`
- either HMAC signature headers or the exact RFC-0023 authorization format
- an optional bounded correlation identifier

The JSON envelope contains `schema_version`, `event_type`,
`event_schema_version`, `occurred_at`, and `payload`. The source identifier comes
from the registered route and server configuration, not from the body.

Unsupported media types, content encodings, duplicate security headers,
ambiguous authorities, oversized headers, malformed transfer semantics, and
oversized bodies fail before JSON decoding.

## Authentication model

HMAC sources additionally use `X-Phoenix-Inbound-Signature` and
`X-Phoenix-Inbound-Key-Version`. The versioned canonical signature input covers
the scheme version, source ID, request ID, source-event ID, normalized aware
timestamp, nonce, and lowercase SHA-256 digest of the exact body bytes.

The initial algorithm is HMAC-SHA-256. Key material is leased through an exact
versioned Secrets Vault reference only during verification. Rotation is explicit
and may permit one bounded reviewed predecessor overlap.

A source may instead require RFC-0023 service-account authentication. The token
must satisfy the existing machine boundary plus the exact
`inbound_event.submit` action scope and a concrete resource grant for that
source. Successful authentication yields credential-free trusted machine
context. HMAC and service-account modes cannot be combined to weaken either
boundary.

## Replay, idempotency, and durable acceptance

Replay protection uses three source-scoped keys: request identifier, nonce, and
source-event identifier. Request identifiers and nonces are single-use inside
bounded retention windows.

The source-event identifier provides idempotency:

- first valid use creates the accepted event and stable receipt;
- the same normalized digest returns the same stable receipt;
- a different normalized digest returns a generic conflict;
- reused nonce or request evidence is rejected even when content matches.

The request path validates transport bounds, source state, authentication,
replay evidence, JSON structure, event schema, normalization, normalized size,
and policy before atomically reserving replay evidence and persisting the
accepted event. It returns success only after that durable commit.

Accepted states are pending, publishing, published, retrying, dead-letter, and
retention-discarded. A Runtime-owned publisher emits the reviewed immutable Event
Bus event. Interrupted publication is reconciled at startup through bounded
retry. Exactly-once Event Bus observation is not promised; consumers use the
stable accepted-event ID for idempotency.

## Response model

Responses are bounded JSON with `Cache-Control: no-store`.

- `202 Accepted`: new durable acceptance or idempotent repeat
- `400 Bad Request`: malformed bounded envelope
- `401 Unauthorized`: generic authentication failure
- `403 Forbidden`: generic authenticated policy denial
- `409 Conflict`: source-event ID reused with different normalized content
- `413 Content Too Large`: request body exceeds the source limit
- `415 Unsupported Media Type`: unsupported media type or encoding
- `422 Unprocessable Content`: authenticated but invalid registered schema
- `429 Too Many Requests`: admission or source throttling
- `503 Service Unavailable`: durable acceptance cannot complete safely

Receipts expose only stable identifiers, accepted or idempotent status, safe
timestamps, external type and schema version, and approved bounded correlation
metadata.

## Network exposure and limits

The gateway creates no second listener. It inherits the existing control-plane
listener, loopback or explicit remote exposure, TLS and optional mTLS, Host and
proxy checks, CIDR policy, admission limits, health, and shutdown behavior.
Enabling a source never changes listener binding or trusted-proxy configuration.

Finite limits are mandatory for request lines, headers, body bytes, JSON depth,
object fields, collection width, strings, normalized payloads, timestamp skew,
identifier lengths, replay retention, request rate, concurrency, queue depth,
publisher workers, retries, dead letters, history, and administration pages.
Configuration cannot remove a mandatory security bound.

## Persistence and recovery

In-memory repositories are deterministic references. State Store-backed
repositories persist safe source metadata, replay reservations, immutable
normalized events, source-event digest indexes, publication attempts, scheduling
metadata, terminal outcomes, dead-letter history, and retention metadata.

They never persist plaintext credentials, authorization headers, signatures,
Secrets Vault lease material, unrestricted raw request bodies, proxy chains, raw
TLS certificates, or internal exception text.

Startup recovery validates schema versions, checksums, source state,
registrations, retry bounds, and retention policy before publication resumes.
Malformed or incompatible records fail closed.

## Administration, observability, and audit

Maintainers may create, update, enable, disable, or revoke sources; select one
authentication mode; bind exact key references or service-account policy; choose
allowed event types; configure bounded limits; inspect safe metadata and history;
redrive eligible dead letters; rotate HMAC references; and inspect health.

Schema and normalizer registration is code-reviewed and not Dashboard-editable.
Optional machine administration requires fixed routes, exact
`inbound_event.*` scopes, concrete source resources, RFC-0023 replay protection,
and central policy approval. Human and machine administration remain separate.

Safe metrics cover source state, acceptance, idempotency, rejection, replay,
conflict, schema failures, admission, queue state, publication, retry, dead
letter, corruption, and saturation. Audit facts record lifecycle, key-reference,
event-type, policy, replay, conflict, redrive, retention, and recovery decisions
without raw bodies, credentials, signatures, nonces, protected digests, internal
exceptions, or sensitive network identities.

## RuntimeAssembler integration

Composition is optional. When enabled, `RuntimeAssembler` owns repositories,
schema registry, authentication verifier, gateway, publisher, recovery service,
manager, ingress routes, administration routes, Dashboard integration, and
explicitly enabled machine administration.

Startup order is repositories and schemas, authentication dependencies,
recovery validation, publisher workers, administration routes, then ingress
routes. Shutdown stops ingress first, bounds in-flight parsing, stops
administration producers, drains publisher work, persists interrupted state, and
closes repositories last.

## Compatibility and migration

Inbound sources are optional and begin empty. With composition omitted, Phoenix
OS preserves all v0.24.0 control-plane, webhook, service-account, session, jobs,
workflows, audit, secrets, Event Bus, Dashboard, network, TLS, and Runtime
behavior.

Existing webhook subscriptions are not converted into inbound sources. Existing
service accounts receive no inbound scopes or source resources automatically.
No source, route, schema, key, credential, replay record, event, or network
permission is created during upgrade.

The package version remained `0.24.0` during implementation slices and is
`0.25.0` in the final release slice. Migration must support staged disabled
configuration, reviewed schema registration, disabled source creation,
authentication testing, conservative enablement, observation, optional machine
administration, and state-preserving rollback.

## Slice plan

### Slice 1 — Contracts, schemas, and persistence

- [x] Immutable source, schema, accepted-event, attempt, receipt, and replay contracts
- [x] Strict schema-versioned codecs
- [x] In-memory source, event, and replay repositories
- [x] State Store-backed source, event, and replay repositories
- [x] Atomic replay reservation and accepted-event persistence
- [x] Repository equivalence and corruption tests

### Slice 2 — Authentication, replay, and idempotency

- [x] Versioned HMAC-SHA-256 verification
- [x] Exact Secrets Vault key-version resolution
- [x] RFC-0023 service-account authentication mode
- [x] Timestamp, nonce, and request-identifier validation
- [x] Durable replay protection across restart
- [x] Stable source-event idempotency and conflict rejection
- [x] Generic authentication and enumeration-resistance tests

### Slice 3 — HTTP ingress, limits, and normalization

- [x] Fixed opt-in inbound route
- [x] Exact media-type and security-header validation
- [x] Bounded body and structural JSON parsing
- [x] Explicit schema registry and normalizers
- [x] Policy-protected durable acceptance
- [x] Per-source and global admission limits
- [x] Safe receipts and HTTP error mapping
- [x] TLS, proxy, CIDR, smuggling, and malformed-input tests

### Slice 4 — Publication, recovery, audit, and observability

- [x] Runtime-owned asynchronous Event Bus publisher
- [x] Deterministic bounded retry and dead-letter handling
- [x] Interrupted-publication recovery
- [x] Explicit eligible redrive
- [x] Safe audit facts, metrics, and health snapshots
- [x] Retention and recovery workers
- [x] At-least-once and stable-identity regression tests

### Slice 5 — Administration and v0.25.0

- [x] Maintainer-only source and event administration
- [x] Dashboard source, receipt, history, and dead-letter administration
- [x] Optional scoped service-account administration
- [x] RuntimeAssembler integration and lifecycle ownership
- [x] Migration guidance
- [x] Architecture Decision Records
- [x] Regression, authentication, replay, admission, and packaging gate
- [x] Release notes and version 0.25.0

The dependency-free Dashboard now exposes inbound source lifecycle controls,
safe receipt inspection, bounded payload-free accepted-event history, health
summaries, and eligible dead-letter redrive. Every panel and action is gated by
its exact permission, mutations reuse durable-session CSRF protection, reviewed
sensitive actions require step-up authentication, and optional subsystem
failures degrade independently from the rest of the Dashboard.

Machine administration remains disabled by default and is exposed only
when the Runtime explicitly composes the fixed machine route set with an
`InboundManager` configured for machine administration. The route gateway
requires the exact RFC-0023 action scope and `inbound-machine` resource, then
the handler independently requires the concrete `inbound-source:<uuid>`,
`inbound-event:<uuid>`, or `inbound-receipt:<uuid>` resource before invoking
the manager. Aggregate inventory, creation, and health routes are intentionally
absent for service accounts; every request still passes token authentication,
timestamp and nonce replay protection, the central policy boundary, protected
audit, and credential-free request handling.

RuntimeAssembler now owns the optional inbound subsystem as one coherent
lifecycle boundary. It selects coordinated bounded in-memory repositories when
no default State Store exists and State Store-backed source, event, and replay
repositories otherwise. Reviewed normalizers register and durable interrupted
publication recovery completes before publisher and recovery workers start;
the existing Control Plane listener starts last and serves both exact ingress
routes and durable-session administration without creating another socket.

The Runtime exposes safe component services for diagnostics, binds RFC-0023
authentication, replay, and central policy only when service accounts are
explicitly enabled, and adds concrete machine-administration routes only behind
the separate opt-in flag and secure network policy. Shutdown stops the listener
first, then recovery and publication workers, removes ingress routes, and closes
the manager, recovery service, repositories, and admission state last.

The v0.24.0-to-v0.25.0 migration guide now defines the additive
disabled-by-default compatibility boundary, reviewed normalizer rollout,
coordinated repository durability, exact HMAC and RFC-0023 producer contracts,
disabled source staging, conservative canary enablement, human and machine
administration separation, health verification, and state-preserving rollback.
It explicitly prohibits automatic webhook conversion, automatic service-account
grants, plaintext credential persistence, and deletion of durable replay or
accepted-event records merely to make a rejected request succeed.

The accepted architecture records make the principal inbound decisions
durable beyond this release:

- [ADR-0006 — Reviewed inbound schemas and normalization](../adrs/ADR-0006-reviewed-inbound-schemas-and-normalization.md)
- [ADR-0007 — Per-source authentication, replay, and idempotency](../adrs/ADR-0007-per-source-authentication-replay-and-idempotency.md)
- [ADR-0008 — Shared Control Plane listener and exact inbound routes](../adrs/ADR-0008-shared-control-plane-listener-and-exact-inbound-routes.md)
- [ADR-0009 — Durable acceptance and at-least-once publication](../adrs/ADR-0009-durable-acceptance-and-at-least-once-publication.md)
- [ADR-0010 — Opt-in inbound Runtime and separated administration](../adrs/ADR-0010-opt-in-inbound-runtime-and-separated-administration.md)

Together they preserve the code-reviewed normalization boundary, exact
per-source credentials, durable replay and idempotency, shared listener and
exact-route model, stable asynchronous publication identity, and independent
source-submission, human-administration, and machine-administration authority.

The mandatory inbound release gate is implemented by
`scripts/check_inbound_release.py`. It reruns the load-bearing contracts, codec,
repository, authentication, replay, idempotency, admission, HTTP, secure
transport, publication, recovery, administration, service-account, and Runtime
integration suites. It builds and validates wheel and sdist metadata and
contents, rejects unsafe archive paths and secret-bearing file types, requires
the inbound package, Control Plane integration modules, Dashboard assets,
migration guide, and ADRs, and rebuilds a wheel from the validated sdist.

Both the direct wheel and the wheel rebuilt from the sdist are installed with
`--no-index` and `--no-deps` into isolated offline environments. Smoke tests remove
`PYTHONPATH`, disable the user site, use isolated Python mode, reject
source-tree imports, and exercise the packaged schema, source authentication,
retry, admission, canonical JSON, ingress-route, human-administration, and
machine-administration surfaces.

Phoenix OS 0.25.0 release notes are published at
[`docs/releases/v0.25.0.md`](../releases/v0.25.0.md), and the package,
changelog, migration, ADR, and release-gate metadata identify the same accepted
version and release date.

## Acceptance

RFC-0025 is accepted for Phoenix OS 0.25.0. Every slice is complete, the full
quality gate passes, wheel and sdist contents are validated, isolated offline
installation succeeds, authentication and replay protections fail closed, no
plaintext credential or unrestricted request body is persisted, and compatibility
without configured inbound sources is demonstrated.
