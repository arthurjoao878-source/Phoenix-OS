# ADR-0019: Untrusted tool results and content-free agent observability

- **Status:** Accepted
- **Date:** 2026-07-29
- **Related:** RFC-0027

## Context

Tool results can contain prompt injection, secrets, external response bodies,
malformed structured data, or instructions that attempt to influence later
model turns. Agent observability can also become a data-exfiltration path when it
records prompts, arguments, results, approval evidence, or raw exceptions.

## Decision

Tool output remains untrusted data. Phoenix validates it against the registered
output schema, applies finite byte and structure limits, and wraps it in a
Phoenix-owned tool message bound to the exact call identifier. Tool output cannot
create policy grants, approvals, credentials, registrations, limits, events, or
another tool invocation directly.

`AgentObserver`, audit facts, metrics, logs, health snapshots, administration,
and Event Bus events are content-free by default. They may expose only approved
metadata such as stable identifiers, operation and outcome categories, tool ID,
effect classification, normalized argument digest, resolved-resource category,
bounded counts, durations, queue state, and safe failure category.

They exclude prompts, model responses, raw arguments, tool results, credentials,
secret references, approval tokens, endpoint details, external response bodies,
and internal exceptions. Phoenix-owned Event Bus observations use fixed event
types and empty payloads.

Public failures remain generic and do not enumerate the registered tool
inventory or reveal whether a particular privileged tool exists.

## Consequences

- Prompt injection in tool output remains ordinary untrusted content.
- Operational monitoring can measure availability and limits without retaining
  model or tool content.
- Debugging content-sensitive failures requires an explicit future reviewed
  retention contract; raw content is not silently added to logs.
- Safe views and events are suitable for broader operational consumers than the
  underlying execution data.

## Alternatives considered

- **Log prompts and tool payloads for convenience.** Rejected because logs are a
  common secondary disclosure surface.
- **Trust read-only tool output.** Rejected because effect classification does
  not make external data trustworthy.
- **Publish tool results on the Event Bus.** Rejected because the Event Bus is
  not an implicit disclosure or authority channel.

## Supersession criteria

Any optional content retention must be introduced by a separate reviewed
contract with explicit consent, storage, access, retention, redaction, and audit
rules. Default content-free behavior must remain available.
