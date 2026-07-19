# Phoenix OS v0.18.0 — Dashboard Operations and Safe Command API

Phoenix OS 0.18.0 implements RFC-0018 and upgrades the local dashboard from an observation-only
surface to a narrowly scoped operational console. The built-in command boundary supports creating
capability-backed jobs, cancelling jobs and workflows, and retrying eligible dead-letter jobs without
permitting arbitrary code, shell commands, plugin mutation, capability registration, or direct
persistence edits.

## Highlights

- exact per-action permissions for every command;
- bounded in-memory idempotency keyed by SHA-256 digests;
- canonical command fingerprints without retained request payloads;
- origin-bound HMAC-SHA-256 CSRF tokens;
- one-time HMAC-SHA-256 confirmation proofs for destructive actions;
- safe job creation with deeply validated JSON arguments;
- deterministic command UUIDs for job creation and dead-letter retry recovery;
- safe job and workflow cancellation with post-failure reconciliation;
- fixed authenticated POST routes with bounded bodies and command concurrency;
- allowlisted receipts without arguments, outputs, contexts, tokens, or exception text;
- Event Bus facts for every completed, denied, or confirmation-issued command;
- Security Journal categorization for control-plane command events;
- Dashboard forms and action buttons driven by authenticated operation availability;
- Runtime-owned command API shutdown before Event Bus shutdown;
- accepted RFC-0018 and ADR-0036/0037.

## Command routes

```text
GET  /v1/control-plane/operations
POST /v1/control-plane/csrf
POST /v1/control-plane/commands/jobs/create
POST /v1/control-plane/commands/jobs/retry-dead-letter
POST /v1/control-plane/commands/jobs/cancel/confirmation
POST /v1/control-plane/commands/jobs/cancel
POST /v1/control-plane/commands/workflows/cancel/confirmation
POST /v1/control-plane/commands/workflows/cancel
```

## Safety model

Read permission never grants mutation permission. Each command requires an exact action permission,
a bearer-authenticated principal, the exact loopback browser origin, a valid CSRF token, and an
idempotency key. Job and workflow cancellation additionally require a short-lived proof that is bound
to the principal, command UUID, action, target, fingerprint, and hashed idempotency key and can be
consumed only once.

The transport accepts only fixed routes and JSON objects within configured limits. Create-job input
cannot supply a security context, principal, request ID, confirmation flag, metadata, provider,
callable, binary value, secret wrapper, output, lease, or repository record. Command receipts expose
only stable identifiers, timestamps, status, and result codes.

## Current boundaries

The built-in command API remains loopback-only and single-administrator. It does not provide remote
administration, TLS termination, multi-user identity, capability registration, plugin management,
workflow definition editing, arbitrary file access, shell execution, generic object mutation, or
unrestricted capability invocation. Destructive capabilities remain unavailable through job.create.
