# ADR-0060: Host state is data; effects require fresh authority

- **Status:** Accepted
- **Date:** 2026-08-18
- **Related:** RFC-0032

## Context

Host automation observes operating-system state and can also change it. Process and
window metadata, application labels, window titles, clipboard text, model proposals,
tool results, prior enumeration, persisted execution metadata, and native adapter state
can all be stale, adversarial, or unrelated to the authority needed for a later host
operation.

Reusing authority from an agent run, model invocation, tool invocation, previous host
operation, prior approval, or observed desktop object would create a confused-deputy
path around Phoenix policy. Enabling the host-automation subsystem itself must not
create authority either.

## Decision

Desktop state is data; host effects require fresh authority.

Host automation is opt-in, and composing it grants no host permission automatically.
Every `host.*` operation requires fresh exact current-policy authorization for its own
reviewed action and server-owned resource. Authorization for one host action never
implies another host action.

When a model originates the operation, normal RFC-0027 `tool.invoke` authorization
remains independent from RFC-0032 host authorization. Neither decision implies the
other. Required host-specific or tool approval is additional evidence, not a
replacement for current policy.

Model text, tool arguments, process/window metadata, application labels, clipboard
contents, adapter results, prior enumeration, persisted execution state, and historical
approval cannot create, widen, replace, or mutate host authority. Current reviewed
Phoenix configuration and current policy always win.

Host effects are not transparently retried. If Phoenix loses certainty after an
external effect has been admitted, the outcome is reported as indeterminate rather
than replayed from stale or historical authority.

## Consequences

- Observing desktop state never becomes ambient permission to mutate the desktop.
- Model-originated host work crosses both the tool-policy and host-policy boundaries.
- Callers must request the exact host action they need instead of relying on broader
  agent, model, tool, workspace, memory, or prior host grants.
- Approval can constrain a reviewed sensitive effect but cannot manufacture current
  authorization.
- Recovery and retry logic must preserve the no-transparent-retry rule for uncertain
  external effects.

## Alternatives considered

- **Reuse `tool.invoke` as host authority.** Rejected because tool invocation and host
  effects are independent trust edges.
- **Let prior enumeration or approval authorize the later effect.** Rejected because
  desktop state and current policy can change between observation and effect.
- **Grant all `host.*` actions when host automation is enabled.** Rejected because
  configuration enables a capability boundary, not authority within it.
- **Retry uncertain effects automatically.** Rejected because replay can duplicate an
  external operating-system effect.

## Supersession criteria

A replacement must preserve explicit opt-in composition, fresh exact current-policy
authorization for every host operation, independent model-tool and host authorization,
the rule that desktop/model/tool data never grants Phoenix authority, current policy
winning over historical evidence, and no transparent replay of uncertain host effects.
