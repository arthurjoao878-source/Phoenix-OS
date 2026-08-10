# ADR-0023: Controlled recovery and explicit indeterminate reconciliation

- **Status:** Accepted
- **Date:** 2026-08-10
- **Related:** RFC-0028

## Context

A process can disappear after a model provider or tool adapter accepted work but
before Phoenix persisted a terminal result. Repeating that operation can duplicate
billable model work, messages, purchases, writes, or other external side effects.

Restart must therefore distinguish reconstructable safe boundaries from external
attempts whose completion is unknown.

## Decision

Phoenix OS resumes durable runs only through reviewed safe checkpoint boundaries.
Startup examines bounded eligible pages, validates the checkpoint and retention
state, acquires a fenced lease, re-reads under that lease, verifies current
compatibility, obtains fresh exact `agent.resume` authorization, and then classifies
one recovery point.

Resume authorization grants only recovery orchestration. Every resumed model turn
still receives a fresh RFC-0026 `model.infer` decision and every resumed tool call
a fresh exact `tool.invoke` decision. Persisted authorization and approval evidence
never grants current execution authority.

Every external model turn and tool invocation has one stable attempt identity.
Phoenix durably records preparation and start boundaries before relying on an
external outcome. An attempt left active after process loss becomes indeterminate
unless a reviewed adapter-specific protocol proves an exact terminal outcome.

Indeterminate model or tool work is never retried automatically. Reconciliation is
an explicit separate action over the exact durable run and attempt. It requires
current exact authorization, reviewed evidence, and a fixed reviewed disposition.
Operator reconciliation cannot rewrite tool, resource, arguments, actor, or
attempt identity.

A confirmed not-started disposition permits only a later fresh attempt when
evidence proves that the original external operation was not accepted. Phoenix
does not claim exactly-once external side effects.

## Consequences

- Restart does not silently duplicate ambiguous external work.
- Recovery depends on fresh current policy and compatibility.
- Some runs remain paused until an operator or reviewed adapter can resolve them.
- Adapters may add exact status lookup protocols, but cannot invent completion.
- Idempotency keys reduce risk but do not prove exactly-once execution.

## Alternatives considered

- **Retry any incomplete attempt after restart.** Rejected because absence of a
  local success record is not proof that the external system did nothing.
- **Trust model-authored completion claims.** Rejected because model output is
  untrusted and cannot prove an external side effect.
- **Resume with persisted authorization.** Rejected because policy, principals,
  tools, schemas, and approvals may have changed.
- **Treat every started attempt as failed.** Rejected because the external system
  may have committed successfully.

## Supersession criteria

A replacement must preserve fresh resume/model/tool authorization, safe-boundary
recovery, stable attempt identity, no transparent retry after ambiguous execution,
explicit exact reconciliation, and no exactly-once claim without a stronger
reviewed external protocol.
