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
| [ADR-0006](ADR-0006-reviewed-inbound-schemas-and-normalization.md) | Accepted | Accept external events only through reviewed bounded schemas and normalizers that choose the internal Event Bus contract. |
| [ADR-0007](ADR-0007-per-source-authentication-replay-and-idempotency.md) | Accepted | Require one exact authentication mode per source with durable replay evidence and atomic source-event idempotency. |
| [ADR-0008](ADR-0008-shared-control-plane-listener-and-exact-inbound-routes.md) | Accepted | Reuse the reviewed Control Plane listener and expose only exact active-source ingress routes with pre-read bounds. |
| [ADR-0009](ADR-0009-durable-acceptance-and-at-least-once-publication.md) | Accepted | Commit trusted accepted events before success and publish asynchronously with stable at-least-once identity and bounded history. |
| [ADR-0010](ADR-0010-opt-in-inbound-runtime-and-separated-administration.md) | Accepted | Keep inbound events opt-in, Runtime-owned, and separated across submission, human administration, and machine administration. |
| [ADR-0011](ADR-0011-provider-neutral-contracts-and-reviewed-inference-registry.md) | Accepted | Use Phoenix-owned provider-neutral contracts and a reviewed server-side registry as the provider/model allowlisting boundary. |
| [ADR-0012](ADR-0012-exact-inference-authorization-and-untrusted-model-output.md) | Accepted | Require exact model invocation policy and treat every model output as untrusted data without implicit Phoenix authority. |
| [ADR-0013](ADR-0013-exact-credential-leases-and-fail-closed-provider-endpoints.md) | Accepted | Lease exact credential versions only during execution and admit provider endpoints through fail-closed destination and TLS policy. |
| [ADR-0014](ADR-0014-bounded-streaming-cancellation-and-no-transparent-retry.md) | Accepted | Bound complete and streaming execution, require one terminal record, cancel cooperatively, and never retry provider work transparently. |
| [ADR-0015](ADR-0015-opt-in-inference-runtime-and-separated-administration.md) | Accepted | Keep inference opt-in, Runtime-owned, content-free in safe output, and separated across invocation, human, and machine authority. |
| [ADR-0016](ADR-0016-server-owned-tool-registry-and-strict-agent-schemas.md) | Accepted | Keep the tool inventory server-owned and validate every proposal and result through strict bounded Phoenix schemas. |
| [ADR-0017](ADR-0017-independent-agent-model-tool-authorization-and-exact-approvals.md) | Accepted | Require independent run, model, and tool policy decisions plus exact single-use approvals for sensitive effects. |
| [ADR-0018](ADR-0018-bounded-serial-agent-loop-and-no-transparent-retry.md) | Accepted | Execute a finite serial agent state machine and never retry model or tool work transparently. |
| [ADR-0019](ADR-0019-untrusted-tool-results-and-content-free-agent-observability.md) | Accepted | Treat tool results as untrusted and keep audit, health, administration, logs, metrics, and events content-free. |
| [ADR-0020](ADR-0020-opt-in-agent-runtime-and-bounded-lifecycle.md) | Accepted | Keep agent execution opt-in, Runtime-owned, deterministically rolled back, and bounded during cancellation and shutdown. |
| [ADR-0021](ADR-0021-untrusted-canonical-chained-durable-checkpoints.md) | Accepted | Treat checkpoints as untrusted canonical chained data that grant no authority and fail closed under corruption, rollback, substitution, or incompatibility. |
| [ADR-0022](ADR-0022-fenced-leases-and-conditional-durable-mutation.md) | Accepted | Require monotonic fencing generations and store-enforced conditional mutation so stale workers cannot commit durable progress. |
| [ADR-0023](ADR-0023-controlled-recovery-and-explicit-indeterminate-reconciliation.md) | Accepted | Resume only from reviewed safe boundaries with fresh authority and reconcile indeterminate external attempts explicitly without transparent retry. |
| [ADR-0024](ADR-0024-opt-in-protected-payloads-and-content-free-durable-operations.md) | Accepted | Keep metadata-only persistence as the default and make bounded authenticated protected content explicit while operational surfaces remain content-free. |
| [ADR-0025](ADR-0025-opt-in-runtime-owned-durable-lifecycle-retention-and-administration.md) | Accepted | Keep durability opt-in and Runtime-owned with bounded recovery, retention, cleanup, shutdown, and separated exact administration authority. |
| [ADR-0048](ADR-0048-delegation-creates-work-never-authority.md) | Accepted | Delegation creates reviewed child work but never transfers parent authority. |
| [ADR-0049](ADR-0049-monotonic-root-budget-reservation.md) | Accepted | Reserve root delegation budget and child capacity monotonically across completion and restart. |
| [ADR-0050](ADR-0050-phoenix-owned-delegation-lineage.md) | Accepted | Keep lineage Phoenix-owned and permanently bind one delegation identity to at most one child run. |
| [ADR-0051](ADR-0051-runtime-owned-child-lifecycle-and-recovery.md) | Accepted | Keep child lifecycle Runtime-owned, bounded, cancellation-linked, and fail closed on unknown restart state. |

## Related specifications

- ADR-0001 through ADR-0005 record the principal durable choices implemented by
  [RFC-0024 — Durable Signed Webhooks and Event Subscriptions](../rfcs/RFC-0024-durable-signed-webhooks-and-event-subscriptions.md).
- ADR-0006 through ADR-0010 record the principal durable choices implemented by
  [RFC-0025 — Secure Inbound Event Gateway and External Event Sources](../rfcs/RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md).
- ADR-0011 through ADR-0015 record the principal durable choices implemented by
  [RFC-0026 — Secure Model Providers and Inference Runtime](../rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md).

- ADR-0016 through ADR-0020 record the principal durable choices implemented by
  [RFC-0027 — Secure Agent Loop and Tool Calling Runtime](../rfcs/RFC-0027-secure-agent-loop-and-tool-calling.md).
- ADR-0021 through ADR-0025 record the principal durable choices implemented by
  [RFC-0028 — Durable Agent Runs, Checkpoints, and Controlled Resumption](../rfcs/RFC-0028-durable-agent-runs-and-controlled-resumption.md).
- ADR-0048 through ADR-0051 record the principal durable choices implemented by
  [RFC-0029 — Secure Multi-Agent Coordination and Delegation](../rfcs/RFC-0029-secure-multi-agent-coordination-and-delegation.md).
