# ADR-0028 — Canonical NDJSON and dual-digest audit archives

- Status: Accepted
- Date: 2026-07-18

## Context

Audit archives must remain portable and independently verifiable after leaving a live store. Hashing
only compressed bytes makes record inspection format-dependent, while hashing only uncompressed data
cannot detect substitution of the published artifact representation.

## Decision

Phoenix exports one canonical UTF-8 JSON record per line and records both a payload digest over the
uncompressed bytes and an artifact digest over the exact stored bytes. Optional gzip uses `mtime=0`.
A canonical manifest covers range, anchors, both digests, encoding, file name, and prior manifest
digest; its own digest is stored separately.

## Consequences

The same records produce stable payload and compressed bytes. Verification can distinguish artifact
corruption from payload or record-chain corruption. Archive readers must preserve the published
canonical rules and schema version. The format is not encrypted and does not itself provide WORM.
