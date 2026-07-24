# ADR-0002: Versioned webhook signing keys

- **Status:** Accepted
- **Date:** 2026-07-24
- **Related RFC:** [RFC-0024](../rfcs/RFC-0024-durable-signed-webhooks-and-event-subscriptions.md)

## Context

Outbound webhook receivers need to authenticate Phoenix requests without giving
Phoenix authority over a receiver account. Signing material must not be stored
inside subscriptions, delivery records, ordinary configuration, logs, audit
facts, or administrative responses.

Retries and deliveries retained across rotation must remain verifiable with the
same exact key version originally selected for the subscription.

## Decision

Phoenix uses the versioned `hmac-sha256-v1` scheme for v0.24.0 webhook
deliveries.

A subscription contains an exact versioned `SecretRef`, never plaintext key
material and never an unversioned "latest" reference. For each attempt the
signer:

1. leases the exact secret version through `SecretsManager`;
2. builds a versioned canonical signature input from the timestamp, delivery
   identifier, attempt number, and SHA-256 digest of the immutable body;
3. computes HMAC-SHA-256;
4. sends the signature scheme, timestamp, delivery identifier, key version, and
   attempt number in fixed Phoenix headers;
5. clears the temporary key byte buffer;
6. revokes the secret lease after signing.

Signing-key rotation updates the subscription to a new exact secret version.
It does not rewrite existing delivery bodies or attempt history. Receivers keep
old key versions available while retained or retryable deliveries still refer
to them.

## Consequences

Positive consequences:

- subscription and delivery persistence contain no plaintext signing key;
- a retry resolves the same explicit key version rather than ambient "latest";
- rotation is auditable and does not invalidate historical delivery identity;
- receivers can select the correct verification key without trial-and-error;
- lease policy and secret-store adapters remain centralized in Phoenix.

Costs and constraints:

- deployments must retain old key versions for the delivery retention window;
- secret-policy mistakes fail delivery rather than falling back to another key;
- receiver and sender clocks require an operationally defined tolerance;
- HMAC uses shared secret custody on both sides.

## Alternatives considered

### Store the key directly in the subscription

Rejected because durable records, administrative inspection, backups, and
debugging paths would become secret-bearing.

### Resolve an unversioned latest key

Rejected because retry behavior would change after rotation and historical
requests could not identify the key used.

### Sign only the body

Rejected because the signature would not bind the delivery identity, attempt
number, or request time.

### Use asymmetric signatures in v0.24.0

Deferred. Asymmetric signing can reduce shared-secret custody at receivers, but
it requires a reviewed key-distribution and algorithm-agility design. A future
ADR may introduce another explicit scheme without weakening
`hmac-sha256-v1`.

### Reuse service-account API tokens

Rejected because outbound delivery authentication and inbound administrative
authorization are different trust boundaries and lifecycles.

## Supersession criteria

A future signing ADR must retain explicit algorithm versioning, exact key
selection, canonical input, bounded ephemeral key access, and compatibility for
deliveries signed under earlier accepted schemes.
