# RFC-0024: Durable Signed Webhooks and Event Subscriptions

- Status: Draft
- Target release: Phoenix OS v0.24.0
- Owners: Phoenix OS maintainers

## Summary

RFC-0024 introduces durable, explicitly allowlisted webhook subscriptions for
external systems that need to receive selected Phoenix OS events.

Webhook delivery is asynchronous, at-least-once, bounded, signed, auditable, and
owned by the Phoenix Runtime. Subscriptions never expose unrestricted Event Bus
payloads. Every outbound payload is produced by an explicit safe serializer,
persisted without secret material, delivered through a reviewed egress policy,
and authenticated with a versioned signing key referenced through the Secrets
Vault boundary.

## Motivation

Phoenix OS already provides an Event Bus, durable jobs, workflow orchestration,
State Store persistence, a Secrets Vault boundary, audit storage, a secure
control plane, and scoped machine identities.

External integrations still lack a supported way to receive selected operational
or security-safe events. Polling the control plane is inefficient, while direct
Event Bus exposure would bypass payload review, durability, egress restrictions,
retry policy, and audit requirements.

A dedicated webhook subsystem must therefore provide:

- explicit subscription contracts;
- allowlisted event types and safe payload serializers;
- durable delivery state;
- bounded retries and dead-letter handling;
- signed requests with replay evidence;
- strict outbound-network controls;
- safe administration and observability;
- compatibility with deployments that do not configure webhooks.

## Goals

- Durable webhook subscriptions
- Explicit event-type allowlisting
- Safe schema-versioned payload serializers
- At-least-once asynchronous delivery
- Persistent delivery attempts and terminal outcomes
- HMAC request signatures using versioned secret references
- Timestamp and delivery identifier replay evidence
- Bounded retry schedules with deterministic backoff
- Dead-letter state and explicit retry
- Idempotency support for receivers
- Strict endpoint validation and outbound-network policy
- Redirect rejection
- Bounded payload, header, response, and timeout limits
- Per-endpoint and global delivery concurrency limits
- Safe audit facts, metrics, and health snapshots
- Maintainer administration routes and Dashboard controls
- RuntimeAssembler lifecycle ownership
- Optional service-account attribution for management actions

## Non-goals

- General-purpose HTTP client functionality
- Arbitrary Event Bus forwarding
- Exactly-once delivery
- Receiver-side deduplication implementation
- OAuth, OIDC, or browser login for receivers
- Executing remote commands from webhook responses
- Following redirects
- Uploading files or streaming unbounded bodies
- Persisting plaintext signing secrets
- Delivering operator credentials, API tokens, cookies, CSRF values, secret
  material, request bodies, or unrestricted audit details
- Automatic public Internet exposure
- Replacing the existing jobs, workflows, audit, or service-account subsystems

## Security invariants

1. Webhooks are disabled unless explicitly configured.
2. Only explicitly registered event types may be subscribed to.
3. Every event type uses a reviewed, schema-versioned safe serializer.
4. Raw Event Bus payloads are never forwarded directly.
5. Plaintext signing secrets are never persisted in subscription or delivery state.
6. Signing keys are referenced through versioned secret references and resolved
   only for the duration of request signing.
7. Signature comparison guidance for receivers uses constant-time verification.
8. Each request carries a stable delivery identifier and an aware timestamp.
9. Retry attempts reuse the stable delivery identifier and payload digest.
10. Delivery is at-least-once; receivers are expected to deduplicate by delivery
    identifier.
11. Redirects are rejected and never followed.
12. Endpoint URLs must use HTTPS, except an explicitly enabled loopback-only
    development mode.
13. User information, fragments, ambiguous ports, and unsupported URL forms are
    rejected.
14. DNS resolution and destination addresses are validated against the active
    egress policy before every connection attempt.
15. Loopback, link-local, multicast, unspecified, private, carrier-grade NAT, and
    otherwise non-public destinations fail closed unless explicitly allowlisted.
16. Endpoint, payload, header, response, timeout, retry, retention, and concurrency
    limits are bounded.
17. Webhook responses are treated as untrusted data and never executed.
18. Response bodies are discarded or retained only as bounded, redacted metadata.
19. Secrets, credentials, authorization headers, signatures, unrestricted payloads,
    internal exceptions, and resolved private addresses are excluded from logs,
    errors, events, metrics, audit details, and snapshots.
20. Subscription disablement or revocation is checked before every attempt.
21. Signing-key rotation is explicit, versioned, and auditable.
22. Existing Phoenix OS v0.23.0 behavior remains unchanged when webhooks are absent.

## Proposed contracts

- `WebhookSubscription`
- `WebhookSubscriptionStatus`
- `WebhookEventType`
- `WebhookPayload`
- `WebhookPayloadSerializer`
- `WebhookEndpoint`
- `WebhookEgressPolicy`
- `WebhookSigningPolicy`
- `WebhookRetryPolicy`
- `WebhookDelivery`
- `WebhookDeliveryStatus`
- `WebhookAttempt`
- `WebhookSubscriptionRepository`
- `WebhookDeliveryRepository`
- `WebhookSigner`
- `WebhookTransport`
- `WebhookDispatcher`
- `WebhookManager`
- `WebhookSnapshot`

## Subscription model

A subscription binds:

- a stable subscription identifier;
- a display name;
- one or more explicitly supported event types;
- a validated HTTPS endpoint;
- a versioned signing-secret reference;
- an active, disabled, or revoked state;
- a bounded retry policy;
- optional resource filters supported by the selected event type;
- an explicit egress policy reference;
- creation, update, disablement, revocation, and revision metadata.

Subscriptions do not contain plaintext credentials or arbitrary serializer code.

## Event and payload model

Every deliverable event type is registered with:

- a stable event-type name;
- a schema version;
- a safe serializer;
- supported resource-filter fields;
- a maximum serialized size;
- a documented compatibility policy.

The serializer receives trusted internal event data and returns a bounded,
JSON-compatible payload containing only allowlisted fields.

The delivery envelope contains:

- `schema_version`;
- `event_schema_version`;
- `delivery_id`;
- `subscription_id`;
- `event_type`;
- `event_id` when a stable source identifier exists;
- `occurred_at`;
- `payload`.

The canonical serialized envelope is immutable for all attempts of the same
delivery. The one-based attempt number is bounded transport metadata and is
never embedded in or used to rebuild the canonical request body.

## Signing model

Each outbound request includes:

- `Content-Type: application/json`;
- `User-Agent: Phoenix-OS-Webhook/0.24`;
- `X-Phoenix-Webhook-Id`;
- `X-Phoenix-Webhook-Timestamp`;
- `X-Phoenix-Webhook-Signature`;
- `X-Phoenix-Webhook-Key-Version`;
- `X-Phoenix-Webhook-Attempt`;
- an optional correlation identifier.

The signature input is a canonical byte sequence containing the timestamp,
delivery identifier, attempt number, and SHA-256 digest of the exact request
body.

The initial signature scheme is versioned HMAC-SHA-256. The wire format includes
the scheme version so future algorithms can be introduced without ambiguous
verification.

Signing-key material is obtained from the Secrets Vault boundary by versioned
reference, used only in memory for signing, and excluded from durable delivery
state.

## Delivery semantics

Delivery is asynchronous and at-least-once.

A source event creates at most one durable delivery record per matching active
subscription and source-event identity. A stable deduplication key prevents
duplicate scheduling during Event Bus replay or Runtime recovery.

Each attempt records only safe bounded facts:

- attempt number;
- scheduled time;
- start and finish time;
- terminal classification;
- bounded status code class;
- retry decision;
- next-attempt time;
- safe error category.

The full signing secret, signature header, request authorization material,
unrestricted response body, and internal exception text are never persisted.

Successful 2xx responses mark a delivery complete. Other outcomes are classified
by explicit policy as retryable or terminal. Retry schedules are deterministic,
bounded, and include jitter derived without secret material.

After the retry budget is exhausted, the delivery enters dead-letter state.
Maintainers may explicitly retry an eligible dead-letter delivery after reviewing
the subscription and endpoint state.

## Outbound-network policy

Webhook transport is not a general-purpose HTTP client.

Before every connection attempt, Phoenix OS validates:

- URL scheme and normalized authority;
- explicit port policy;
- DNS results;
- destination address classes;
- configured allowlists and denylists;
- TLS requirements;
- certificate verification settings;
- connection and total timeout limits;
- response-header and response-body limits.

Redirects are disabled. A redirect response is classified as terminal unless a
future RFC defines a reviewed redirect policy.

DNS names are revalidated for every attempt so a previously valid subscription
cannot bypass current egress restrictions through DNS changes.

## Persistence and recovery

The in-memory repositories remain reference implementations.

State Store-backed repositories persist:

- subscription metadata and lifecycle state;
- immutable canonical delivery envelopes;
- attempt counters and scheduling metadata;
- terminal outcomes;
- bounded dead-letter history;
- safe retention metadata.

Runtime recovery reconstructs pending deliveries, rejects malformed or
incompatible records, and resumes only after subscription, key-reference, egress,
and retention validation.

No plaintext signing secret or unrestricted Event Bus payload is persisted.

## Administration

Maintainer-only administration supports:

- create and update subscription;
- enable and disable subscription;
- revoke subscription;
- inspect safe subscription metadata;
- inspect bounded delivery history;
- retry eligible dead-letter deliveries;
- rotate the referenced signing-key version;
- inspect safe health and metrics.

Dashboard views never display signing secrets or signature headers.

Machine administration may be added only through explicit service-account action
scopes and the existing machine-route security model.

## Observability and audit

Safe metrics include bounded counts and durations for:

- active and disabled subscriptions;
- queued, in-flight, successful, retrying, failed, and dead-letter deliveries;
- retry classifications;
- egress-policy rejections;
- signature-resolution failures;
- dispatcher saturation.

Audit facts record administrative lifecycle changes and delivery security
decisions without storing secret material, unrestricted payloads, raw response
bodies, or internal exception text.

## Slice plan

### Slice 1 — Contracts and persistence

- [ ] Immutable subscription, endpoint, signing, retry, delivery, and attempt contracts
- [ ] Explicit lifecycle and terminal states
- [ ] Safe schema-versioned codecs
- [ ] In-memory repositories
- [ ] State Store-backed repositories
- [ ] Corruption detection and repository equivalence tests
- [ ] Safe bounded snapshots and retention metadata

### Slice 2 — Event selection and durable scheduling

- [x] Explicit webhook event registry
- [x] Safe payload serializer protocol
- [x] Resource-filter validation
- [x] Canonical immutable delivery envelopes
- [x] Stable source-event deduplication
- [ ] Event Bus adapter
- [ ] Durable scheduling and Runtime recovery

### Slice 3 — Signing and outbound transport

- [ ] Versioned HMAC-SHA-256 signing
- [ ] Versioned secret-reference resolution
- [ ] Exact request headers and canonical signature input
- [ ] Strict HTTPS endpoint validation
- [ ] DNS and destination-address egress enforcement
- [ ] Redirect rejection
- [ ] Bounded timeouts, payloads, headers, and responses
- [ ] Safe transport error classification

### Slice 4 — Retry, dead-letter, audit, and observability

- [ ] Deterministic bounded retry policy
- [ ] Per-endpoint and global concurrency limits
- [ ] Dead-letter transition and explicit retry
- [ ] Subscription disablement and revocation enforcement
- [ ] Signing-key rotation behavior
- [ ] Protected audit facts
- [ ] Safe metrics and health snapshots
- [ ] Retention and recovery tests

### Slice 5 — Administration and v0.24.0

- [ ] Maintainer-only management routes
- [ ] Dashboard subscription and delivery administration
- [ ] Optional scoped service-account administration
- [ ] RuntimeAssembler integration and lifecycle ownership
- [ ] Migration guidance
- [ ] Architecture Decision Records
- [ ] Regression, security, SSRF, replay, and packaging tests
- [ ] Release notes and version 0.24.0

## Compatibility

Webhook subscriptions are optional and begin empty.

When no webhook subsystem is configured, Phoenix OS preserves all v0.23.0
control-plane, service-account, jobs, workflows, audit, secrets, Event Bus, and
Runtime behavior.

Existing Event Bus subscribers are not converted into webhook subscriptions.
Existing jobs are not reclassified as webhook deliveries. No signing key,
subscription, endpoint, or outbound-network permission is created automatically.

## Acceptance

RFC-0024 will be accepted for Phoenix OS 0.24.0 only when all slices are complete,
the full repository quality gate passes, wheel and sdist contents are validated,
isolated installation succeeds, SSRF and replay protections fail closed, no
plaintext signing secret is persisted, and compatibility without configured
webhooks is demonstrated.
