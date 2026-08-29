# ADR-0072: Recovery restores metadata, while routine operations remain content-free

- **Status:** Accepted
- **Date:** 2026-08-28
- **Related:** RFC-0036

## Context

Integrated orchestration needs durable recovery and operator visibility without turning
checkpoints, telemetry, health, or administration into a hidden content store or bearer
capability.

Metadata-only recovery also cannot reconstruct planning context that was never persisted.

## Decision

RFC-0036 projects only bounded orchestration metadata into RFC-0028 durability by
default. Checkpoints grant no authority and include exact task digest plus integrated
profile identity/generation so recovery can reject substitution.

Recovery requires exact persisted task/profile compatibility and fresh current
configuration, tool/downstream profiles, policy, authority, limits, deadline,
cancellation, approval when required, and subsystem freshness. Metadata-only state never
proves that planning context is reconstructable. Missing context enters an explicit
reviewed resupply/waiting path or terminates safely; Phoenix does not fabricate it.

Routine integrated logs, audit, events, metrics, health, and administration are
content-free. Separately authorized inspection is a distinct read-only boundary and
returns only explicitly reviewed bounded redacted metadata. Raw provenance bindings,
task/prompt/model/tool content, browser/network/memory/workspace/clipboard content,
credentials, approval evidence, policy internals, and raw exceptions are excluded.

## Consequences

- Persisted orchestration state cannot replay live authority.
- Consumed approvals and stale browser identities remain invalid after restart.
- Indeterminate effects remain subject to RFC-0028 reconciliation.
- Routine operations can be monitored without creating a secondary content disclosure
  channel.
- Health permission and run-inspection permission remain separate.

## Alternatives considered

- **Resume automatically from metadata-only checkpoints.** Rejected because required
  planning context may be absent.
- **Persist all orchestration content by default.** Rejected because it expands sensitive
  storage and conflicts with RFC-0028 protected-payload opt-in semantics.
- **Expose detailed content through routine administration.** Rejected because health and
  telemetry must not become a privileged content-exfiltration surface.

## Supersession criteria

A replacement must preserve checkpoint non-authority, fresh recovery validation,
fail-safe missing-context handling, explicit indeterminate-effect reconciliation,
content-free routine operational surfaces, and separately authorized bounded redacted
inspection.
