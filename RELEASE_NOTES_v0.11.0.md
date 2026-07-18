# Phoenix OS v0.11.0 — Secrets Vault and Key Management

Phoenix OS v0.11.0 implements RFC-0011 and introduces an identity-aware, policy-enforced boundary
for versioned secret material, temporary access leases, rotation, revocation, and external
key-management providers.

## Highlights

- immutable `SecretRef`, `KeyRef`, metadata, lease, store, and snapshot contracts;
- versioned creation and rotation with stable exact-version references;
- authenticated, deny-by-default secret access;
- Policy Engine integration for normalized secret actions and resources;
- bounded principal-owned leases with expiry, revocation, and purge;
- automatic lease invalidation when a secret version is revoked;
- deterministic in-memory backend for tests and ephemeral processes;
- provider-neutral `SecretStore` and `SecretProtector` boundaries;
- typed Configuration reference decoder and on-demand resolver;
- Runtime composition and deterministic lifecycle ownership;
- correlated events, metrics, logs, and spans without material disclosure.

## Security model

The Phoenix core does not implement encryption algorithms, wrapping-key storage, HSM, cloud KMS,
remote-vault authentication, transport security, or durable backup. `InMemorySecretStore` is not
encrypted at rest. Production deployments must supply reviewed external providers and retain normal
process, operating-system, network, and incident-response controls.

## Architecture records

- RFC-0011 — Secrets Vault and Key Management;
- ADR-0022 — Secret references and short-lived leases;
- ADR-0023 — External cryptographic and key-provider boundary.

## Validation

- Ruff approved;
- Ruff Format approved;
- mypy strict approved;
- 417 tests approved;
- eleven examples executed successfully;
- wheel built and installed in an isolated virtual environment;
- isolated create, rotate, lease, and revoke smoke test approved.

## Compatibility

This release preserves the public contracts introduced in RFC-0001 through RFC-0010 and requires
Python 3.12 or newer.
