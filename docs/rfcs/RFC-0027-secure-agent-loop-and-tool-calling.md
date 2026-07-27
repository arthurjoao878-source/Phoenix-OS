# RFC-0027: Secure Agent Loop and Tool Calling Runtime

- Status: Draft
- Target release: Phoenix OS v0.27.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0002, RFC-0004, RFC-0005, RFC-0006, RFC-0009, RFC-0011, RFC-0012, RFC-0023, and RFC-0026

## Summary

RFC-0027 defines an optional Phoenix-owned agent Runtime that can perform
bounded model turns and explicitly authorized tool invocations.

The subsystem consumes the provider-neutral inference boundary introduced by
RFC-0026. A model may propose either final output or one structured tool call,
but the proposal has no authority by itself. Phoenix validates the proposal,
resolves a server-owned tool and concrete resource, performs a new central
policy decision, obtains action-bound human approval when required, and only
then invokes the reviewed tool adapter.

Agent execution is disabled by default. No tool, permission, approval, loop,
background worker, operating-system action, filesystem access, network access,
or persistent memory exists unless explicitly configured.

## Motivation

RFC-0026 establishes secure provider-neutral inference while intentionally
excluding agent planning, tool calling, and execution of model-produced
commands.

Applications that directly translate model output into function calls would
bypass Phoenix authorization, schema validation, audit, lifecycle, and resource
limits. They could also let prompt injection select tools, fabricate policy
resources, alter privileged arguments, leak secrets, create infinite loops, or
repeat side effects.

Phoenix therefore needs a dedicated orchestration boundary between untrusted
model output and reviewed system capabilities.

The agent Runtime must preserve the central rule that model output is data, not
authority. Each tool invocation must be independently validated and authorized,
even when the surrounding agent run was already authorized.

## Goals

- Optional agent execution disabled by default
- Provider-neutral agent contracts owned by Phoenix OS
- Explicit server-side tool registration with stable identifiers
- Strict bounded tool input and output schemas
- Canonical argument normalization before authorization
- Exact policy authorization for every individual tool invocation
- Server-side resolution of concrete policy resources
- Action-bound human approval for configured sensitive operations
- Finite model turns, tool calls, bytes, tokens, duration, and concurrency
- Deterministic agent state transitions
- Cooperative cancellation and bounded cleanup
- Stable run, step, proposal, and tool-call identifiers
- No implicit authority inherited from model output
- No implicit authority inherited from the surrounding agent run
- Content-free audit and observability by default
- Deterministic fake model and fake tools for network-free tests
- RuntimeAssembler lifecycle ownership
- Compatibility with Phoenix OS v0.26.0 when agent configuration is absent

## Non-goals

- Arbitrary shell or command execution
- A generic unrestricted HTTP-request tool
- Arbitrary filesystem access
- Arbitrary database queries
- Browser or desktop automation
- Operating-system control
- Dynamic installation of tools or plugins
- Loading executable code supplied by a model
- Model-created policy resources or authorization actions
- Model-selected credentials, endpoints, headers, or secret references
- Recursive agents or agents invoking other agents
- Parallel tool execution in the initial Runtime
- Transparent retries of model or tool execution
- Guaranteed exactly-once execution of external side effects
- Persistent conversation memory
- Semantic memory or retrieval-augmented generation
- Autonomous scheduled agents or background planning
- Restart-resumable agent runs
- Delegating Phoenix identity or policy authority to a model
- Treating tool output as trusted instructions
- Persisting prompts, model responses, arguments, or tool results by default
- A hostile-code sandbox for installed tool adapters

## Threat model

The subsystem treats all prompts, model messages, model responses, structured
tool proposals, tool names, argument values, tool results, external data,
finish reasons, usage metadata, and provider metadata as untrusted.

The implementation must address:

- prompt injection requesting privileged tools;
- fabricated or ambiguous tool identifiers;
- schema confusion and duplicate JSON keys;
- argument smuggling and unknown properties;
- path traversal and endpoint substitution;
- model-selected policy resources;
- authorization confused-deputy failures;
- approval replay or approval for altered arguments;
- credential or secret leakage;
- unbounded agent loops;
- token, byte, time, queue, and concurrency exhaustion;
- repeated or duplicate side effects;
- tool-result injection into later model turns;
- malformed model output;
- oversized tool results;
- cancellation races;
- partial tool execution;
- adapter exception leakage;
- cross-run state contamination;
- audit and logging disclosure;
- recursive or re-entrant agent execution;
- tools attempting to acquire ambient Phoenix authority.

Installed tool adapters are trusted Phoenix code, but model-controlled input and
all external data received by those adapters remain untrusted.

## Security invariants

1. Agent execution is disabled unless explicitly configured.
2. Enabling the subsystem creates no tool, permission, approval, run, worker, or
   external authority automatically.
3. Every tool has a stable server-side `ToolId` from trusted configuration.
4. Models select only registered tool identifiers exposed for the current run.
5. Models never select executable callbacks, module paths, classes, endpoints,
   credentials, policy actions, or raw policy resources.
6. A model tool proposal is untrusted data and has no execution authority.
7. Authorization for `agent.run` does not authorize any nested model or tool
   operation.
8. Every model turn still requires the RFC-0026 `model.infer` authorization.
9. Every tool call requires a new exact `tool.invoke` authorization.
10. The policy resource is resolved by trusted server-side code after argument
    validation.
11. Model-provided strings are never used directly as policy resource names.
12. Tool arguments are validated against a strict registered schema.
13. Unknown object properties are rejected by default.
14. Duplicate JSON keys, non-finite numbers, invalid Unicode, and malformed
    structured output fail closed.
15. Authorization evaluates canonical normalized arguments and resources.
16. Any required human approval is bound to one exact normalized invocation.
17. Approval tokens are single-use, short-lived, actor-bound, and cannot be
    created or modified by a model.
18. Altering the tool, resource, arguments, run, step, or call identifier
    invalidates approval.
19. Tool adapters receive only the validated arguments and dependencies required
    for one invocation.
20. Tool adapters receive no ambient model, policy, secrets, filesystem, shell,
    network, Runtime, or operating-system authority.
21. Generic shell, unrestricted HTTP, and unrestricted filesystem tools are not
    included.
22. The initial Runtime executes at most one tool invocation at a time per run.
23. Agent steps, model turns, tool calls, bytes, tokens, durations, queue depth,
    and global concurrency are finite.
24. The most restrictive applicable limit wins.
25. Tool output is untrusted data when returned to the model.
26. Tool output never authorizes another tool call.
27. Tool output is bounded and encoded through Phoenix-owned result contracts.
28. No model or tool execution is transparently retried.
29. Cancellation stops new work and bounds cleanup of active work.
30. A run succeeds only through one explicit terminal state.
31. Partial, malformed, duplicated, or out-of-order state transitions fail
    closed.
32. Agent runs cannot recursively invoke the agent Runtime.
33. Agent runs cannot persist prompts, arguments, or results by default.
34. Audit, logs, metrics, health, and events exclude model and tool content by
    default.
35. Public failures never expose registered-tool inventory, arguments, results,
    credentials, internal exceptions, or approval evidence.
36. Existing Phoenix OS v0.26.0 behavior remains unchanged when agent
    configuration is absent.

## Proposed contracts

- `AgentRunId`
- `AgentStepId`
- `ToolId`
- `ToolCallId`
- `ToolApprovalId`
- `ToolDescriptor`
- `ToolInputSchema`
- `ToolOutputSchema`
- `ToolEffect`
- `ToolAvailability`
- `ToolCallProposal`
- `ToolInvocationRequest`
- `ToolInvocationResult`
- `ToolResultStatus`
- `AgentMessage`
- `AgentRunRequest`
- `AgentRunResult`
- `AgentRunStatus`
- `AgentLimits`
- `AgentSnapshot`
- `ToolRegistry`
- `ToolResourceResolver`
- `ToolAuthorizer`
- `ToolApprovalGate`
- `ToolExecutor`
- `AgentRuntime`
- `AgentObserver`
- `AgentError`

All public contracts are immutable, bounded, serializable through strict
Phoenix-owned codecs, and free from provider SDK or tool-framework objects.

## Tool descriptors and registry

A `ToolDescriptor` declares:

- stable `ToolId`;
- human-readable bounded name and description;
- immutable input and output schemas;
- effect classification;
- whether human approval may be required;
- maximum input and output sizes;
- finite execution timeout;
- concrete resource resolver;
- adapter implementation identity;
- lifecycle availability;
- compatibility metadata.

Tools register before the Runtime accepts agent runs. Registration fails closed
for duplicate identifiers, invalid schemas, missing resource resolvers,
unbounded limits, unsupported effect classifications, or unavailable adapters.

The tool registry is server-owned. The model receives only the bounded
descriptors selected by trusted configuration for the current run.

A model cannot enumerate tools that were not admitted for that run.

## Strict schema subset

Phoenix defines a strict bounded schema subset for tool arguments and results.

The initial subset supports:

- objects;
- arrays;
- strings;
- integers;
- finite decimal numbers;
- booleans;
- null;
- required properties;
- bounded enums;
- minimum and maximum numeric values;
- minimum and maximum string lengths;
- minimum and maximum array lengths;
- nested depth limits.

Object schemas reject unknown properties by default. Recursive schemas,
unresolved references, executable validators, arbitrary regular expressions,
custom code, and provider-specific schema extensions are not accepted.

Structured model output is parsed with duplicate-key rejection, finite-number
validation, bounded depth, bounded width, bounded total bytes, and canonical
UTF-8 encoding.

## Model turn contract

Each agent model turn requests exactly one of two outcomes:

1. final bounded assistant output; or
2. one bounded `ToolCallProposal`.

A `ToolCallProposal` contains:

- stable proposal identifier;
- registered `ToolId`;
- structured bounded arguments;
- no executable callback;
- no policy action;
- no raw policy resource;
- no credential reference;
- no endpoint;
- no approval token;
- no trusted identity.

Provider-native tool-call formats may be translated by reviewed provider
adapters into the Phoenix contract. Raw provider SDK objects never cross the
inference boundary.

Malformed output, multiple terminal alternatives, multiple tool proposals,
unknown tools, unsupported schema versions, or mixed final-output and tool-call
content fail closed.

## Argument validation and canonicalization

The Runtime validates a proposal before authorization or tool execution.

Validation includes:

- exact tool lookup;
- strict schema validation;
- Unicode normalization where required by the tool contract;
- canonical JSON representation;
- bounded collection sizes;
- rejection of unknown fields;
- rejection of duplicate keys;
- rejection of non-finite numbers;
- tool-specific semantic validation;
- server-side canonical resource resolution.

The validated canonical argument representation receives a stable digest. That
digest is used for authorization evidence, approval binding, audit correlation,
and duplicate-call detection without exposing raw arguments.

The digest is not treated as authentication and never replaces policy
authorization.

## Authorization and authority separation

Starting an agent run requires the exact `agent.run` action against a concrete
configured agent resource.

That authorization permits only bounded orchestration. It does not authorize
model inference or tools.

Every model turn independently requires RFC-0026 authorization:

```text
action: model.infer
resource: model-provider:<provider-id>/model:<model-id>
```

Every tool invocation independently requires:

```text
action: tool.invoke
resource: tool:<tool-id>/<resolved-resource>
```

The concrete resource is produced by the registered
`ToolResourceResolver` after validation. The model cannot supply it directly.

Policy evaluation receives only approved metadata, including authenticated
Phoenix identity, tool identifier, resolved resource, effect classification,
run identifier, and normalized argument digest.

Model text, tool output, secrets, and unrestricted arguments are not policy
language and cannot modify the authorization decision.

## Human approval

Trusted configuration and central policy determine which invocations require
human approval.

An approval record is bound to:

- authenticated approving actor;
- agent run identifier;
- agent step identifier;
- tool call identifier;
- exact tool identifier;
- exact resolved resource;
- normalized argument digest;
- effect classification;
- expiration;
- single-use state.

Approval for one invocation cannot authorize another invocation, changed
arguments, a different resource, another user, or a later replay.

The model cannot request that approval checks be disabled and cannot provide an
approval token.

Runs waiting for approval consume finite time and bounded retained metadata.
Expiration, denial, cancellation, or altered invocation evidence fails closed.

## Tool effect classification

The initial design defines these effect classes:

- `READ_ONLY`
- `REVERSIBLE_WRITE`
- `IRREVERSIBLE_WRITE`
- `EXTERNAL_COMMUNICATION`

Effect classification is declared by trusted configuration and cannot be
downgraded by callers or models.

Classification is policy and approval input. It is not a substitute for exact
authorization.

A tool that can perform more than one effect must declare the strongest
applicable class or expose separate reviewed tool identifiers.

## Tool execution

After validation, authorization, and any required approval, the Runtime creates
one immutable `ToolInvocationRequest`.

The request contains only:

- run, step, and call identifiers;
- exact tool identifier;
- canonical validated arguments;
- resolved resource;
- finite deadline;
- bounded safe correlation metadata;
- adapter-specific trusted dependencies supplied by composition.

The adapter cannot receive the model provider credential or unrestricted
Phoenix Runtime access.

A `ToolInvocationResult` contains:

- stable identifiers;
- terminal status;
- bounded structured result or bounded safe failure;
- safe timing metadata;
- optional idempotency metadata;
- no raw exception;
- no credential;
- no unrestricted headers;
- no executable callback;
- no implicit authorization.

Tool results are validated against the registered output schema before returning
to the agent loop.

## Agent state machine

The Runtime uses explicit deterministic states:

```text
CREATED
INFERENCING
VALIDATING_PROPOSAL
AUTHORIZING_TOOL
AWAITING_APPROVAL
INVOKING_TOOL
VALIDATING_RESULT
COMPLETED
FAILED
CANCELLED
```

Only reviewed transitions are permitted.

A normal tool cycle is:

```text
CREATED
-> INFERENCING
-> VALIDATING_PROPOSAL
-> AUTHORIZING_TOOL
-> AWAITING_APPROVAL, when required
-> INVOKING_TOOL
-> VALIDATING_RESULT
-> INFERENCING
-> COMPLETED
```

Any invalid transition, duplicate terminal state, missing terminal state,
identifier mismatch, or work after termination fails closed.

The initial Runtime is in-memory and does not resume an interrupted run after
process restart.

## Limits, budgets, and admission

Global, configured-agent, provider, model, tool, and request limits are finite.
The most restrictive applicable limit wins.

Limits cover:

- maximum agent steps;
- maximum model turns;
- maximum total tool calls;
- one tool call per model turn;
- maximum prompt bytes;
- maximum accumulated model-output bytes;
- maximum accumulated tool-result bytes;
- maximum input and output tokens;
- maximum argument bytes;
- maximum result bytes;
- maximum structured-data depth and width;
- maximum queue depth;
- maximum concurrent runs;
- maximum concurrent model calls;
- maximum concurrent tool calls;
- per-model-turn timeout;
- per-tool-call timeout;
- approval wait timeout;
- total run duration;
- cancellation grace;
- shutdown grace.

Admission occurs before model execution, credential leasing, approval creation,
or tool execution.

The initial Runtime executes tool calls serially within one run. Global
concurrency remains separately bounded.

Limit exhaustion produces a safe terminal failure and never causes the Runtime
to continue with partial authority.

## Loop termination

A run terminates when:

- the model produces one valid final response;
- a configured limit is reached;
- authorization is denied;
- approval is denied or expires;
- validation fails;
- inference fails;
- tool execution fails;
- cancellation is requested;
- the total deadline expires;
- Runtime shutdown begins.

The Runtime never asks the model to ignore a failed security decision.

A denied or malformed tool call is not silently rewritten into a different tool
or resource.

## Retry and duplicate execution semantics

The initial Runtime performs no transparent retry of model turns or tool calls.

This rule applies even to apparently read-only tools because external systems
may be mutable, billable, rate-limited, or incorrectly classified.

Each tool call has a stable unique identifier. Reviewed adapters may use that
identifier as an idempotency key when supported, but Phoenix does not claim
exactly-once execution.

After ambiguous external failure, the Runtime returns a safe indeterminate
failure rather than automatically repeating the operation.

## Cancellation and shutdown

Cancellation is cooperative and bounded.

The Runtime:

1. rejects new model and tool work;
2. marks the run as cancelling;
3. signals active inference or tool execution;
4. stops accepting additional output;
5. waits only for the configured grace period;
6. releases admission capacity;
7. invalidates unused approvals;
8. records safe terminal metadata.

Shutdown rejects new runs, cancels or drains active runs within finite bounds,
closes tool adapters in reverse composition order, closes the agent Runtime,
and leaves RFC-0026 inference shutdown ordering intact.

Partial startup rolls back deterministically.

## Tool-result isolation

Tool results returned to the model are untrusted.

The Runtime wraps results in a Phoenix-owned message that identifies the exact
tool call and separates result data from system instructions.

Tool output cannot:

- alter the system prompt;
- create policy grants;
- create approvals;
- select credentials;
- register tools;
- change limits;
- modify run identity;
- invoke another tool directly;
- become executable code;
- become an Event Bus event automatically.

Prompt injection contained in tool output remains ordinary untrusted content for
the next bounded model turn.

## Secrets and sensitive data

A model cannot request a `SecretRef`, secret version, credential lease, or raw
credential.

Tools that require secrets declare exact versioned secret dependencies through
trusted configuration. The Runtime or tool composition layer leases only the
minimum required secret immediately before tool execution and revokes it after
completion, failure, timeout, or cancellation.

Plaintext credentials never enter:

- model prompts;
- tool proposals;
- tool results;
- policy resources;
- approval records;
- audit facts;
- metrics;
- health snapshots;
- Event Bus payloads;
- persisted agent state.

Tools must explicitly declare whether validated input may leave the local trust
boundary. Such egress remains subject to exact policy and endpoint controls.

## Audit, observability, and events

Safe audit facts cover:

- tool registration;
- tool lifecycle changes;
- agent-run admission;
- model-turn start and completion category;
- tool-proposal validation category;
- authorization decision;
- approval request, approval, denial, expiration, and consumption;
- tool invocation start and terminal category;
- cancellation;
- timeout;
- limit rejection;
- configuration failure;
- Runtime startup and shutdown.

Audit, logs, metrics, health, and Event Bus observations may contain approved
metadata such as:

- stable identifiers;
- tool identifier;
- effect classification;
- resolved-resource category;
- normalized argument digest;
- bounded duration;
- byte and token counts;
- queue and concurrency state;
- safe terminal category.

They exclude by default:

- prompts;
- model responses;
- raw arguments;
- tool results;
- credentials;
- secret references;
- approval tokens;
- endpoint details;
- external response bodies;
- internal exceptions.

Event Bus events use fixed Phoenix-owned event types with empty payloads and
approved content-free metadata.

## Configuration and RuntimeAssembler integration

Agent composition is optional.

Configuration declares:

- whether agent execution is enabled;
- admitted model provider and model;
- registered tools;
- tool schemas;
- effect classifications;
- resource resolvers;
- authorization dependencies;
- approval requirements;
- global and per-tool limits;
- execution timeouts;
- admission limits;
- shutdown limits;
- safe observability configuration.

When enabled, `RuntimeAssembler` validates configuration, resolves the inference
Runtime, composes the tool registry, authorizer, approval gate, executors,
admission state, and agent Runtime, and exposes only reviewed service names.

No background planner, scheduler, network listener, shell, filesystem watcher,
or autonomous run is started.

Startup validates all tools before exposing the service.

## Administration

Maintainer administration may expose:

- registered tool identifiers;
- safe descriptions;
- effect classifications;
- lifecycle availability;
- bounded health;
- active and queued run counts;
- safe failure categories;
- enable and disable operations.

Administration excludes:

- prompts;
- arguments;
- results;
- secrets;
- endpoint credentials;
- approval tokens;
- raw exceptions;
- unrestricted tool inventory details.

Tool registration and executable adapter installation remain deployment-time
operations in the initial release.

Machine administration is disabled by default and requires a later exact
service-account contract before exposure.

## Compatibility and migration

Agent configuration begins absent and disabled.

When agent composition is omitted, Phoenix OS preserves all v0.26.0 Runtime,
inference, Control Plane, Dashboard, service-account, webhook, inbound-event,
session, jobs, workflows, audit, secrets, Event Bus, network, TLS, and
persistence behavior.

Upgrade creates no tool, permission, approval, run, model call, endpoint,
credential lease, network access, filesystem access, or persistent agent state.

The package version remains `0.26.0` during implementation slices and changes to
`0.27.0` only in the final release slice.

Migration must support:

- disabled configuration;
- deterministic fake-agent validation;
- reviewed tool registration;
- conservative limits;
- policy setup;
- approval setup;
- canary enablement;
- content-free observation;
- immediate rollback by disabling agent execution.

Disabling the agent subsystem does not disable independently configured
RFC-0026 inference.

## Slice plan

### Slice 1 - Contracts, schemas, registry, and deterministic tools

- [x] Immutable agent, proposal, invocation, result, limit, and error contracts
- [x] Strict bounded schema subset and canonical codecs
- [x] Tool descriptors and duplicate-rejecting registry
- [x] Server-side concrete resource resolvers
- [x] Deterministic fake model-turn adapter
- [x] Deterministic read-only and side-effecting fake tools
- [x] Contract, schema, registry, and codec tests

### Slice 2 - Authorization, approval, and authority separation

- [x] Exact `agent.run` authorization
- [x] Independent RFC-0026 `model.infer` authorization per model turn
- [x] Exact `tool.invoke` authorization per tool call
- [x] Canonical argument digest and server-resolved policy resource
- [x] Action-bound single-use approval records
- [x] Effect classification and approval requirements
- [x] Default-deny, replay, mutation, and confused-deputy tests

### Slice 3 - Agent loop, limits, execution, and cancellation

- [ ] Deterministic bounded agent state machine
- [ ] One tool proposal per model turn
- [ ] Serial tool execution per run
- [ ] Model-turn, tool-call, byte, token, step, and duration limits
- [ ] Tool-result validation and untrusted-result isolation
- [ ] Cooperative cancellation and finite cleanup
- [ ] No-transparent-retry and ambiguous-failure semantics
- [ ] Saturation, timeout, malformed-output, and race tests

### Slice 4 - Configuration, Runtime, audit, and administration

- [ ] Typed optional agent and tool configuration
- [ ] RuntimeAssembler composition and deterministic rollback
- [ ] Safe Runtime service exposure and health snapshots
- [ ] Content-free audit, metrics, logs, and Event Bus events
- [ ] Maintainer tool lifecycle and agent health administration
- [ ] Bounded shutdown ordering
- [ ] Compatibility tests with agent configuration omitted

### Slice 5 - Migration, architecture decisions, and v0.27.0

- [ ] Migration guidance and rollback procedure
- [ ] Architecture Decision Records
- [ ] Threat-model and security-invariant review
- [ ] Agent and tool-calling release gate
- [ ] Wheel and sdist isolated offline installation tests
- [ ] Release notes and package version 0.27.0
- [ ] Tag, artifacts, and checksums

## Acceptance

RFC-0027 may be accepted for Phoenix OS v0.27.0 only when every slice is
complete and the full quality gate passes.

Acceptance additionally requires demonstrated evidence that:

- model output receives no direct tool authority;
- every model turn and tool call receives an independent policy decision;
- policy resources cannot be supplied by the model;
- tool arguments and results fail closed under strict schemas;
- approvals are exact, action-bound, short-lived, and replay-resistant;
- agent loops terminate under finite limits;
- cancellation and shutdown are bounded;
- no transparent retry duplicates tool side effects;
- prompts, arguments, results, credentials, and approval evidence remain absent
  from safe output;
- agent configuration omitted preserves Phoenix OS v0.26.0 behavior;
- package artifacts install and execute in isolated offline environments.
