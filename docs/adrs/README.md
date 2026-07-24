# Phoenix OS Architecture Decision Records

Architecture Decision Records capture durable choices whose consequences extend
beyond one implementation detail or release. They complement RFCs: an RFC
describes a complete proposal and delivery plan, while an ADR records one
architectural choice, its trade-offs, and the conditions under which it may be
superseded.

## Status values

- **Proposed** — under review and not yet binding.
- **Accepted** — the current architectural decision.
- **Superseded** — replaced by another ADR.
- **Deprecated** — retained for history but no longer recommended.
- **Rejected** — considered and intentionally not adopted.

Accepted ADRs are immutable in intent. Clarifications may be added, but changing
the decision requires a new ADR that explicitly supersedes the previous one.

## Index

| ADR | Status | Decision |
| --- | --- | --- |
| [ADR-0001](ADR-0001-explicit-webhook-serializers-and-durable-envelopes.md) | Accepted | Export only reviewed Event Bus facts through explicit serializers and persist canonical delivery envelopes before dispatch. |
| [ADR-0002](ADR-0002-versioned-webhook-signing-keys.md) | Accepted | Sign immutable deliveries with versioned HMAC-SHA-256 keys resolved through exact secret references. |
| [ADR-0003](ADR-0003-fail-closed-webhook-egress.md) | Accepted | Resolve, admit, pin, and connect every destination attempt through a fail-closed egress boundary. |
| [ADR-0004](ADR-0004-bounded-webhook-retry-and-redrive.md) | Accepted | Preserve one global bounded attempt history across automatic retry, recovery, dead letter, and explicit redrive. |
| [ADR-0005](ADR-0005-opt-in-webhook-runtime-and-administration.md) | Accepted | Keep webhooks opt-in, Runtime-owned, and administratively separated between human and machine security models. |

## Related specification

These ADRs record the principal durable choices implemented by
[RFC-0024 — Durable Signed Webhooks and Event Subscriptions](../rfcs/RFC-0024-durable-signed-webhooks-and-event-subscriptions.md).
