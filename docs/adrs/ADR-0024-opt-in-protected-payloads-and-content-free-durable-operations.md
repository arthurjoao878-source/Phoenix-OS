# ADR-0024: Opt-in protected payloads and content-free durable operations

- **Status:** Accepted
- **Date:** 2026-08-10
- **Related:** RFC-0028

## Context

Some resumable runs need continuation content, but persisting prompts, model
responses, arguments, or tool results creates a long-lived disclosure surface.
Encryption reduces disclosure risk but does not make persisted content trustworthy
or authorized.

Durable observability, administration, retention, and failure reporting can also
leak sensitive content if they expose payloads, storage paths, keys, evidence, or
raw exceptions.

## Decision

Phoenix OS uses `METADATA_ONLY` as the default durable payload profile. It stores
only reviewed content-free envelope metadata and permits resumption only when the
next context can be reconstructed through trusted reviewed components.

`PROTECTED_CONTENT` is explicit opt-in. It stores only the minimum bounded
Phoenix-owned continuation content required for recovery. Protected payloads use
authenticated encryption, versioned configured protection keys, strict plaintext
and ciphertext limits, opaque server-owned references, and associated data binding
the run, checkpoint, sequence, schema, and payload profile.

Protection keys are resolved through trusted secret composition for the minimum
operation and are not persisted in checkpoints. Decryption occurs only after
authorization, fenced lease acquisition, and checkpoint validation. Missing or
revoked keys, unknown versions, invalid authentication tags, incompatible codecs,
or ambiguous key selection fail closed. Encryption never replaces authorization,
approval, validation, or access control.

Audit, metrics, logs, health, Event Bus events, administration, public failures,
retention reports, and cleanup reports remain content-free. They exclude protected
plaintext and ciphertext, payload storage paths, credentials, secret references,
approval tokens, endpoint details, raw reconciliation evidence, external response
bodies, and raw exceptions.

Protected payload retention is finite and shorter than reviewed content-free
metadata retention. Cleanup deletes payload content before or atomically with its
references where supported and preserves terminal anti-resurrection metadata.

## Consequences

- Default durable operation does not create a content persistence surface.
- Deployments that need continuation content must opt in to keys and retention.
- Encryption failures pause or fail recovery rather than falling back to plaintext.
- Safe operations remain useful through bounded identifiers, categories, counts,
  ages, sizes, durations, and approved digests.
- Key destruction can intentionally make retained protected payloads unrecoverable.

## Alternatives considered

- **Persist all agent context by default.** Rejected because it creates unnecessary
  sensitive long-lived state.
- **Treat encryption as sufficient authorization.** Rejected because decrypted
  content remains untrusted data.
- **Put ciphertext or storage paths in logs for debugging.** Rejected because safe
  output must not become a payload exfiltration channel.
- **Fall back to plaintext when a key is unavailable.** Rejected because key
  failure must fail closed.

## Supersession criteria

Any replacement must keep metadata-only durability available by default, require
explicit protected-content configuration, use authenticated bounded protection
with versioned key references, preserve authorization-before-decryption, and keep
safe operational surfaces content-free.
