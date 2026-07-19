# RFC-0018 — Dashboard Operations and Safe Command API

- Status: Accepted
- Target: Phoenix OS v0.18.0
- Date: 2026-07-19

## Summary

Phoenix OS will extend the loopback-only read control plane with a separate authenticated command
boundary for narrowly defined operational actions. This RFC does not permit arbitrary code execution,
capability registration, persistence editing, plugin mutation, shell commands, or unrestricted object
serialization.

## Initial command set

- create one capability-backed job;
- cancel one existing job;
- retry one dead-letter job;
- cancel one existing workflow.

Every action maps to one exact permission. Read access alone never grants command access. Cancellation
commands are classified as destructive and will require an explicit confirmation proof before HTTP
transport support is enabled.

## Idempotency model

Every command requires an opaque client idempotency key. The server retains only its SHA-256 digest.
The digest is bound to a fingerprint covering the action, target identifier, schema version, and a
SHA-256 digest of canonical command bytes. The original command payload is not retained in the
idempotency store.

Reusing the same key and fingerprint returns the original receipt. Reusing a key for another
fingerprint fails with a conflict. The built-in memory store has a fixed capacity, evicts only the
oldest terminal command, and rejects new reservations when all capacity is occupied by pending work.

## Command receipts

Receipts expose only command ID, action, target identifier, lifecycle status, timestamps, and a stable
allowlisted result code. They never contain submitted arguments, capability contexts, job outputs,
workflow outputs, exception messages, credentials, tokens, or secrets.

## Browser CSRF model

Browser command requests require a short-lived CSRF token issued only after bearer authentication.
The token is HMAC-SHA-256 signed and bound to the exact authenticated principal and canonical HTTP
origin. Origins must contain a literal IPv4 or IPv6 loopback address; hostnames, HTTPS downgrades,
userinfo, paths, queries, fragments, port zero, and non-loopback addresses are rejected. Verification
uses constant-time signature comparison, a bounded lifetime, and a small explicit future-clock-skew
allowance. Tokens are stateless, opaque, and redacted from ordinary representations.

## Destructive confirmation model

Job and workflow cancellation require a separate one-time confirmation proof. The proof is
HMAC-SHA-256 signed and bound to the principal, command UUID, action, target, command fingerprint, and
hashed idempotency key. The bounded in-memory confirmation service retains only proof digests,
binding digests, timestamps, and consumption state. It never retains command payloads, bearer tokens,
CSRF values, plaintext idempotency keys, arguments, outputs, or exception details.

Proofs expire after a short configurable lifetime and are consumed exactly once. Malformed, expired,
unknown, mismatched, and replayed proofs produce the same generic rejection. Capacity may evict only
expired or consumed entries; when every slot contains an active challenge, issuance fails rather than
overwriting an outstanding confirmation.

`ControlPlaneCommandProtector` centralizes ordering: exact-origin CSRF verification occurs before a
confirmation is issued or consumed, and every destructive command must present a valid one-time proof.
Non-destructive commands require CSRF but do not require confirmation.

## Job command handler model

`ControlPlaneCreateJobCommand` accepts only a registered capability name, a bounded schedule, a
bounded retry policy, an optional execution deadline, and recursively validated JSON-compatible
arguments. Caller-controlled capability contexts, confirmation flags, metadata, principals, request
identifiers, outputs, leases, and repository records are not accepted. Arguments are deep-frozen,
canonicalized with deterministic JSON, limited by depth, item count, collection size, string length,
and encoded byte size, and rejected when they contain secret wrappers, binary values, non-finite
numbers, unsupported objects, or control-character keys.

The handler derives `CapabilityContext` from the authenticated principal and command UUID. It verifies
the exact intent action, target, and payload digest before authorization, CSRF enforcement, and
idempotency reservation. Capability existence and required permissions are checked before scheduling.
Capabilities declared destructive or requiring capability-level confirmation are not schedulable by
this initial non-destructive `job.create` path.

The command UUID is also the scheduled job UUID. This deterministic identity lets concurrent or
recovered requests reconcile an already-created matching job without creating a duplicate. Existing
state with a different immutable `JobSpec` fails with a generic conflict receipt. Internal scheduler,
repository, provider, or exception details never enter command receipts.

Job cancellation validates the same binding, exact action permission, origin-bound CSRF token, and a
one-time destructive confirmation before reserving and mutating. Missing targets, terminal targets,
completed cancellations, and internal failures become stable allowlisted result codes. A cancellation
that committed before a transport or scheduler error is reconciled as successful.

## Recovery command handler model

Dead-letter retry never mutates or resurrects the original terminal job.
`ControlPlaneRetryDeadLetterJobCommand` identifies one exact dead-letter record, and the handler
creates a new one-time job whose UUID is the command UUID. The original arguments, retry policy, and
deadline are reused internally, while the execution context is rebuilt exclusively from the current
authenticated principal. Original metadata and security context are not copied. Capability existence,
current permissions, destructive risk, and confirmation requirements are revalidated before the new
job is scheduled.

Jobs owned by a workflow are not independently retryable through this command because creating an
orphan replacement would bypass workflow reconciliation. Missing, non-dead-letter, workflow-owned,
unauthorized, unsupported-risk, conflicting, and internally failed retries return stable generic result
codes. Partial scheduler success is reconciled through the deterministic replacement job UUID.

`ControlPlaneCancelWorkflowCommand` binds one workflow UUID to the `workflow.cancel` action. The
workflow handler requires the exact action permission, origin-bound CSRF token, one-time destructive
confirmation, and idempotency reservation before invoking the orchestrator. Already-cancelled
workflows reconcile as success; missing or other terminal workflows return stable result codes. If the
orchestrator commits cancellation before raising, the handler re-reads state and completes the command
as successful without exposing internal failure details.

## Planned slices

1. immutable contracts, action authorization, and bounded idempotency — completed;
2. CSRF and destructive-action confirmation proofs — completed;
3. job creation and cancellation command handlers — completed;
4. workflow cancellation and dead-letter retry handlers — completed;
5. HTTP endpoints, audit integration, Dashboard controls, documentation, and v0.18.0 release closure — completed.

## HTTP command transport

The accepted transport uses fixed authenticated POST routes under `/v1/control-plane/commands/` and a
separate authenticated CSRF issuance route. Requests require a singleton `Origin`, `Idempotency-Key`,
and `X-Phoenix-CSRF` header. Destructive execution also requires a singleton
`X-Phoenix-Confirmation` header returned by the preceding confirmation route. The origin must exactly
match the literal loopback address and bound port of the running server.

Command JSON bodies are size-bounded and parsed only as objects. The create-job route accepts an
allowlisted schema. Unknown fields, malformed UUIDs, non-finite numbers, duplicate protection headers,
unsupported media types, oversized bodies, and unsupported routes fail before handler execution.
Concurrent command work is bounded separately from total HTTP connections and reports HTTP 429 when
capacity is exhausted.

`GET /v1/control-plane/operations` reports only the intersection of action availability and the
current principal's exact permissions. It exposes no permission set, token state, handler object, or
service configuration.

## Audit integration

Every terminal command receipt emits one payload-free `control-plane.command.*` Event Bus fact with
only actor, action, command UUID, resource target, status, and stable result code. Confirmation
issuance and rejected command attempts emit similarly bounded facts. The Security Journal maps these
facts to the authorization category and redacts them through the existing Audit Ledger path. Bearer
values, CSRF values, confirmation proofs, plaintext idempotency keys, request bodies, job arguments,
outputs, workflow definitions, and exception messages never enter the event.

## Dashboard operations

The packaged dashboard requests operation availability after authentication and displays controls only
for actions both available and authorized. It obtains a tab-scoped CSRF token, generates a fresh
idempotency key for each operation, and uses a two-step browser confirmation flow for job and workflow
cancellation. Dynamic content continues to use DOM text nodes rather than `innerHTML`, and no external
scripts, styles, fonts, or network services are introduced.

## Resolution

RFC-0018 is accepted for Phoenix OS 0.18.0. The accepted implementation remains loopback-only,
single-administrator, allowlisted, capability-backed, bounded, idempotent, origin-protected, and fully
audited. Arbitrary code execution, shell access, remote management, generic persistence mutation,
plugin mutation, capability registration, and visual workflow editing remain outside the built-in
control plane.
