# ADR-0023 — External cryptographic and key-provider boundary

- Status: Accepted
- Date: 2026-07-18

## Context

Encryption and key management are deployment-specific and easy to implement incorrectly. Cloud KMS,
HSM, TPM, operating-system keyrings, and remote vaults have different trust, latency, availability,
rotation, and audit models. Choosing an algorithm in the core would couple every deployment to one
security design and create a misleading security claim.

## Decision

Phoenix defines provider-neutral `KeyRef`, `SecretStore`, and `SecretProtector` protocols. The core
records only safe key references and never stores raw wrapping keys. It provides no default
cryptographic algorithm. `InMemorySecretStore` is explicitly documented as unencrypted and
non-durable.

Production encryption, envelope-key handling, authentication to external vaults, retries, audit,
backup, and disaster recovery are implemented and reviewed in deployment adapters.

## Consequences

- the core avoids home-grown cryptography and vendor lock-in;
- deployments can select independently reviewed providers;
- metadata can identify the protecting key version without exposing key material;
- the reference backend remains simple and deterministic for testing;
- using the in-memory backend does not constitute encryption at rest.
