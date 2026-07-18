# Phoenix OS v0.14.0 — Audit Retention, Rotation and Archival

Phoenix OS v0.14.0 implements RFC-0014 and adds portable, canonical audit archive segments to the
RFC-0012/RFC-0013 audit stack.

## Highlights

- New `AuditArchiveManager` for exact contiguous archive export.
- Canonical UTF-8 NDJSON with deterministic optional gzip.
- Dual SHA-256 payload and stored-artifact digests.
- Immutable manifests chained through prior manifest and record-head digests.
- Individual archive and complete directory-chain verification.
- Optional verification of persisted external record seals.
- Bounded rotation of not-yet-archived records with explicit partial-segment behavior.
- Atomic artifact/manifest publication and overwrite refusal.
- Non-destructive retention planning with protected archive identifiers.
- Exact digest confirmation, chain verification, and stale-plan checks before deletion.
- Prefix-only deletion to avoid holes in retained archive history.
- RFC-0014, ADR-0028, ADR-0029, executable example, and regression tests.

## Security model

Archive bundles preserve already-redacted audit facts and are tamper-evident. They are not encrypted,
WORM, independently timestamped, or protected against privileged replacement or rollback. Production
operators must protect archive directories, independently anchor important manifest digests, and
apply legal, privacy, backup, and incident-response controls before retention deletion.

## Compatibility

Version 0.14.0 is additive. Existing RFC-0001 through RFC-0013 APIs remain compatible. Live SQLite
records are not truncated or rewritten by archival rotation.
