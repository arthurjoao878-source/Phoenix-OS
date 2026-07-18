# RFC-0014 — Audit Retention, Rotation and Archival

- Status: Accepted
- Version: Phoenix OS 0.14.0
- Authors: Phoenix contributors
- Date: 2026-07-18

## Summary

RFC-0014 adds canonical, independently verifiable audit archive segments on top of the RFC-0012
ledger and RFC-0013 durable store. It introduces deterministic NDJSON payloads, optional deterministic
gzip encoding, cryptographic manifests, cross-segment continuity, bounded rotation, and conservative
retention plans that require exact digest confirmation before deletion.

The live `AuditStore` remains append-only. Archival does not silently truncate or rewrite the active
SQLite ledger. Deployments may retain the live database, copy it to protected backup storage, or use
an external store with stronger lifecycle guarantees.

## Goals

- Export exact contiguous audit sequence ranges.
- Preserve every redacted event field, digest link, correlation value, causation value, and seal.
- Produce deterministic, portable, newline-delimited JSON records.
- Detect payload, compressed artifact, manifest, record, and cross-segment tampering.
- Rotate unarchived history into bounded segments without duplicate publication.
- Build reviewable retention plans without deleting files.
- Require exact confirmation of the retention-plan digest before deletion.
- Preserve protected archives and delete only an oldest contiguous prefix.
- Keep all implementation dependencies in the Python standard library.

## Non-goals

- Mutating or truncating the live append-only SQLite database.
- Claiming WORM, legal-hold, regulatory, remote-replication, or object-lock guarantees.
- Encrypting archive contents.
- Providing cloud-vendor archive adapters.
- Replacing external signatures, protected timestamps, or independent anchors.

## Archive bundle

Each segment is published as two files:

```text
audit-00000000000000000001-00000000000000001000.records.ndjson.gz
audit-00000000000000000001-00000000000000001000.manifest.json
```

The payload contains one canonical JSON object per record and always ends each record with `\n`.
Canonical JSON uses sorted keys, compact separators, UTF-8, and rejects NaN. Gzip archives use a fixed
zero modification time so compression is deterministic for identical payload bytes.

The manifest records:

- schema version;
- archive identifier and creation time;
- first and last sequence;
- exact record count;
- anchor digest from the first record's `previous_digest`;
- final record digest;
- SHA-256 of canonical uncompressed payload bytes;
- SHA-256 of the stored artifact bytes;
- digest of the preceding manifest;
- compression and artifact file name;
- SHA-256 of the canonical manifest payload.

The manifest digest excludes only its own digest field. This avoids a circular representation while
covering every security-relevant manifest value.

## Segment continuity

Within a segment, records retain their RFC-0012 sequence and previous-digest links. Between adjacent
segments:

- the next `first_sequence` equals the prior `last_sequence + 1`;
- the next `anchor_digest` equals the prior `head_digest`;
- the next `previous_manifest_digest` equals the prior `manifest_digest`.

A retained suffix may begin after sequence one. Its first manifest keeps the external anchor and prior
manifest digest, allowing the retained history to be verified from that explicit checkpoint without
pretending the deleted prefix is still present.

## Export and rotation

`AuditArchiveManager.export_segment()` reads an exact range in bounded pages, rejects incomplete or
non-contiguous input, refuses overwrites, writes temporary files, flushes and fsyncs content, and then
publishes with atomic rename. The artifact is published before its manifest; a failed manifest write
removes the unpublished artifact.

`rotate()` starts after the latest archived sequence and exports complete segments of a configured
size. A final partial segment is exported only when `include_partial=True`. Rotation never deletes or
rewrites the source store.

## Verification

Individual verification checks:

1. manifest decoding and manifest digest;
2. stored artifact digest;
3. decompression;
4. canonical payload digest;
5. record count and sequence bounds;
6. every previous-digest link and record digest;
7. manifest head digest;
8. optional external signatures when a signer is supplied.

A signed archive without an available signer is invalid for full verification. Directory-chain
verification additionally checks sequence, head, and manifest continuity across every segment.

## Retention safety

`AuditRetentionPolicy` supports:

- minimum newest archives to keep;
- optional maximum age;
- protected archive identifiers.

`plan_retention()` is non-destructive and returns an immutable plan with candidate and retained archive
identifiers, estimated reclaimed bytes, generation time, and a canonical SHA-256 digest. Candidates
are always the oldest contiguous prefix. Encountering a protected, too-new, or required newest archive
stops deletion selection, preventing holes in retained history.

`apply_retention()` requires the exact plan digest as a separate confirmation, recomputes the plan
digest, verifies the complete current archive chain, rejects stale missing manifests, and only then
deletes the selected artifact/manifest pairs. This reduces accidental deletion but is not a substitute
for filesystem permissions, backups, object lock, or organizational approval.

## Security considerations

Archive files contain redacted security metadata and may still reveal actors, resources, timing, and
operational patterns. Protect directories with least privilege, encryption at rest, backup controls,
privacy policy, and incident-response procedures. SHA-256 chains are tamper-evident, not tamper-proof.
A privileged attacker may replace an entire archive set with an older internally valid set unless the
latest manifest digest is independently anchored or externally signed.

Retention destroys local evidence. Production deletion requires legal, privacy, regulatory, backup,
and incident-response review outside the Phoenix core.

## Compatibility

RFC-0014 is additive. Existing `AuditStore`, `AuditLedger`, `SQLiteAuditStore`, and RFC-0001 through
RFC-0013 contracts remain compatible. The public package version becomes 0.14.0.
