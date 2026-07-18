# RFC-0011 — Secrets Vault and Key Management

- Status: Accepted
- Target: Phoenix OS 0.11.0
- Authors: Phoenix contributors
- Updated: 2026-07-18

## Summary

Phoenix OS requires a trusted boundary for secret references, versioned secret material, temporary
access leases, revocation, rotation, authorization, and external key-management integration. This
RFC introduces that boundary without embedding a concrete cloud vault, HSM, encryption algorithm,
keyring, operating-system credential store, or network protocol in the core.

## Goals

- define immutable `SecretRef`, `KeyRef`, metadata, lease, snapshot, and store contracts;
- keep material wrapped in `SecretValue` and absent from representations and diagnostics;
- support immutable secret versions, rotation, exact-version lookup, and revocation;
- require authenticated identities for every manager operation;
- enforce central Policy Engine decisions or explicit local permissions;
- issue short-lived, principal-bound leases with configured maximum lifetimes;
- invalidate active leases when their secret version is revoked;
- expose an asynchronous provider-neutral `SecretStore` boundary;
- provide an in-memory backend for tests and ephemeral processes;
- define an external `SecretProtector` and `KeyRef` boundary without inventing cryptography;
- integrate secret references with typed Configuration;
- emit correlated events, metrics, logs, and spans without secret values;
- compose the manager through `RuntimeAssembler`.

## Non-goals

The core does not:

- implement AES, RSA, envelope encryption, key derivation, or key wrapping;
- manage HSM, TPM, cloud KMS, operating-system keychain, or remote vault credentials;
- claim that the in-memory backend is encrypted at rest;
- provide network transport, replication, backup, recovery, or quorum semantics;
- automatically inject secret material into arbitrary plugins or capabilities;
- erase immutable Python strings from process memory;
- replace TLS, process isolation, operating-system access control, or deployment hardening.

Those concerns belong to external `SecretStore`, `SecretProtector`, plugin, and deployment adapters.

## Contracts

### SecretRef

A `SecretRef` identifies a normalized namespace and name. An optional positive version selects one
immutable version. Unversioned references resolve to the latest active version. A reference never
contains secret material.

### KeyRef

A `KeyRef` identifies an external provider, key alias, and optional immutable key version. It is
metadata only. The Phoenix core never obtains or stores a raw wrapping key.

### SecretMetadata and StoredSecret

`SecretMetadata` contains only safe lifecycle facts: exact reference, creator, creation time,
rotation ancestry, status, revocation information, optional protection-key reference, and text
attributes. `StoredSecret` combines metadata with a redacted `SecretValue` at the store boundary.

### SecretLease

A lease is a short-lived, principal-bound grant for one exact active secret version. Material remains
inside `SecretValue`. A lease has an identifier, issue time, expiry time, status, correlation, and
causation. It may be resolved only by the same authenticated principal.

### SecretStore

A store implements asynchronous put, get, list, revoke, snapshot, and close operations. External
providers may encrypt, replicate, audit, or remotely resolve material as required, but those details
are not visible to the manager.

### SecretProtector

`SecretProtector` is an optional cryptographic provider boundary with `seal` and `open` operations
addressed by `KeyRef`. The core defines no default algorithm and does not claim cryptographic
protection unless a deployment supplies and validates an implementation.

## Authorization

`SecretsManager` requires an authenticated `SecurityContext`. When a Policy Engine is configured,
it evaluates normalized actions and resources:

- `secret.create`;
- `secret.rotate`;
- `secret.read`;
- `secret.describe`;
- `secret.list`;
- `secret.revoke`;
- `secret.lease.revoke`.

Resources use `secret:<namespace>/<name>` or `secret:<namespace>/*`. Policy denial and confirmation
requirements are translated to a secret-access failure. Without a Policy Engine, the context must
contain the exact action, `secret.*`, or `*` permission. This fallback remains deny-by-default.

## Versioning and rotation

Creation is allowed only for a name with no historical versions. Rotation appends the next positive
version and records `rotated_from`. Values are immutable after insertion. Exact-version references
remain stable until revoked. An unversioned lookup chooses the highest active version.

Revocation is idempotent. Revoking one version invalidates every active lease for that exact version.
Historical metadata remains available to authorized callers, but revoked material cannot be leased.

## Lease lifecycle

The default lease lifetime is five minutes and the default maximum is fifteen minutes. Hosts may
supply a different immutable `SecretLeasePolicy`. Requested lifetimes must be positive and cannot
exceed the maximum.

Leases are held only in manager memory. `resolve_lease` verifies owner, status, and expiry. Expired
leases can be purged. Manager shutdown clears all leases before closing the store.

## In-memory backend

`InMemorySecretStore` is deterministic and useful for tests, development, and ephemeral processes.
It never serializes material, but it is not encrypted at rest and cannot provide durable recovery.
Production deployments should provide an external store with appropriate encryption, access
control, audit, backup, and availability characteristics.

## Configuration integration

`parse_secret_ref` decodes `namespace/name` and `namespace/name#version` as a typed configuration
value. `SecretConfigResolver` leases the referenced value only when an authenticated and authorized
caller requests it. Configuration files therefore contain references rather than raw secrets.

## Events and diagnostics

The manager may emit:

- `secrets.created`;
- `secrets.rotated`;
- `secrets.lease.issued`;
- `secrets.lease.revoked`;
- `secrets.revoked`.

Signals may include namespace, name, version, principal, lease identifier, status, reason, and
expiry. They never include material, revealed values, wrapping keys, or provider credentials.

## Runtime composition

`RuntimeAssembler(secrets=manager)` exposes the reserved `secrets` service and owns its lifecycle.
State and Identity start before Secrets. Plugins start later and therefore may resolve the service
through approved host composition. Reverse shutdown stops plugins before Secrets and clears leases
before the Event Bus and Observability owners close.

## Compatibility

This RFC adds APIs without changing the public contracts of Kernel, Event Bus, Capability Registry,
Runtime, Configuration, Observability, State Store, Plugin System, Policy Engine, or Identity.

## Acceptance criteria

- public contracts are immutable and strictly typed;
- material is absent from representations, events, metrics, logs, and spans;
- create, rotate, exact lookup, latest lookup, list, revoke, and lifecycle are tested;
- authentication and deny-by-default authorization are tested;
- lease issue, ownership, expiry, revocation, purge, and shutdown are tested;
- configuration and Runtime integrations are tested;
- key references and cryptographic provider boundaries remain provider-neutral;
- Ruff, Ruff Format, mypy strict, pytest, examples, wheel build, and isolated installation pass.
