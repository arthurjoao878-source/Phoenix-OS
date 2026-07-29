# RFC-0027 agent threat-model and security-invariant review

- **Reviewed:** 2026-07-29
- **Release:** Phoenix OS v0.27.0
- **Scope:** `phoenix_os.agent`, optional Runtime composition, safe administration,
  audit, metrics, logs, Event Bus observations, packaging, and migration
- **Result:** Accepted for the v0.27.0 release gate

## Review method

This review maps the RFC-0027 threat model and thirty-six security invariants to
implementation boundaries and executable regression suites. It does not treat a
passing test as proof that installed third-party adapters are benign. Tool
adapters remain trusted deployment code and must be reviewed for their own
network, filesystem, secret, and operating-system authority.

The review used four evidence classes:

1. immutable contracts, strict codecs, schemas, and registries;
2. independent policy and approval boundaries;
3. deterministic execution, limits, cancellation, shutdown, and no-retry tests;
4. content-free administration and observability plus isolated package tests.

## Trust boundaries

### Untrusted

- prompts, messages, model output, proposals, identifiers, arguments, tool
  results, external data, finish reasons, and provider metadata;
- all content returned by a tool, including a read-only tool;
- model attempts to name policy actions, resources, callbacks, endpoints,
  credentials, modules, classes, or executable code.

### Trusted but least-authority

- reviewed Phoenix configuration;
- server-owned tool descriptors, schemas, resource resolvers, and policy rules;
- installed model-turn and tool adapters;
- approval actors and trusted security contexts;
- Runtime lifecycle composition.

Trusted adapters receive only the validated arguments and dependencies required
for one invocation. RFC-0027 is not a hostile-code sandbox.

## Threat review

| Threat | Required control | Evidence |
| --- | --- | --- |
| Prompt injection selects privileged execution | A proposal is data only; exact registered `ToolId`, strict schema validation, trusted resource resolution, and independent `tool.invoke` policy | `test_agent_registry.py`, `test_agent_schemas.py`, `test_agent_authorization.py`, `test_agent_loop.py` |
| Fabricated tool or resource | Closed-world registry; generic lookup failure; model strings never become policy resources | `test_agent_registry.py`, `test_agent_authorization.py` |
| Schema confusion, duplicate keys, argument smuggling | Canonical strict codec, duplicate-key rejection, unknown-property rejection, finite depth/width/bytes | `test_agent_codec.py`, `test_agent_schemas.py` |
| Approval replay or mutation | Exact canonical digest; tool/resource/run/step/call/actor binding; finite expiry; single consumption | `test_agent_approval.py`, `test_agent_authorization.py` |
| Authority inherited from the outer run | Separate `agent.run`, per-turn `model.infer`, and per-call `tool.invoke` decisions | `test_agent_authorization.py`, `test_agent_loop.py` |
| Credential or secret leakage | Model cannot select secrets; safe contracts and observations omit credentials and secret references | `test_agent_configuration.py`, `test_agent_observer.py`, `test_agent_service.py` |
| Infinite loops and resource exhaustion | Finite steps, turns, calls, bytes, tokens, duration, queue, and concurrency; most restrictive limit wins | `test_agent_contracts.py`, `test_agent_admission.py`, `test_agent_state.py`, `test_agent_loop.py` |
| Duplicate side effects | One serial call per turn and no transparent retry; ambiguous failures are indeterminate | `test_agent_execution.py`, `test_agent_loop.py` |
| Tool-result prompt injection | Output-schema validation and Phoenix-owned tool messages; result remains untrusted | `test_agent_execution.py`, `test_agent_loop.py` |
| Cancellation and shutdown races | Cooperative cancellation, finite grace, admission release, reverse adapter close, preserved inference ordering | `test_agent_state.py`, `test_agent_service.py`, `test_agent_runtime_integration.py` |
| Cross-run contamination or recursion | Per-run state, explicit admission, no recursive agent Runtime call, no restart resume | `test_agent_state.py`, `test_agent_loop.py`, `test_agent_service.py` |
| Audit or logging disclosure | Content-free observations, fixed event types, empty payloads, safe categories only | `test_agent_observer.py`, `test_agent_service.py` |
| Ambient authority in tools | Exact composition of resolver and adapter identities; no default shell, unrestricted HTTP, filesystem, or OS tool | `test_agent_composition.py`, `test_agent_tools.py` |
| Upgrade changes existing behavior | Agent configuration omitted creates no services, events, state, tools, or work | `test_agent_runtime_integration.py`, `test_agent_configuration.py` |
| Source tree differs from shipped package | Wheel and sdist inspection, sdist rebuild, and offline isolated execution without `PYTHONPATH` | `scripts/check_agent_release.py`, `test_agent_release_gate.py` |

## Security-invariant review

### Invariants 1–6: opt-in and server-owned tools

**Result: satisfied.** Agent configuration is optional. No default tool or run is
created. `ToolRegistry` accepts only exact reviewed registrations, and model
proposals never carry executable callbacks or ambient dependencies.

### Invariants 7–11: independent authorization and trusted resources

**Result: satisfied.** The outer run, every model turn, and every tool call have
separate authorizers. Tool resources are resolved after validation through the
registered server-owned resolver. Model strings are never used directly as
policy resource names.

### Invariants 12–15: strict canonical data

**Result: satisfied.** Phoenix-owned codecs and schemas reject malformed or
ambiguous structured data, unknown properties, duplicate keys, non-finite
numbers, unsupported Unicode, and values beyond finite structure or byte
limits. Authorization sees canonical normalized arguments and the resolved
resource.

### Invariants 16–18: exact approval

**Result: satisfied.** Approval evidence is bound to one normalized invocation,
actor, run, step, call, tool, resource, digest, and expiry. It is single-use and
fails closed after mutation, replay, denial, expiration, or cancellation.

### Invariants 19–22: adapter authority and serial execution

**Result: satisfied.** Tool adapters receive one validated request and only
composition-supplied dependencies. The package supplies deterministic fake tools,
not a generic shell, unrestricted HTTP client, unrestricted filesystem tool, or
operating-system controller. Tool execution is serial within a run.

### Invariants 23–30: finite limits, no retry, cancellation, terminal state

**Result: satisfied.** Every operational dimension is finite, and the strictest
applicable limit wins. Model and tool execution are not retried transparently.
Cancellation stops new work and bounds cleanup. One explicit terminal state is
required for success or failure.

### Invariants 31–33: fail-closed transitions, recursion, persistence

**Result: satisfied.** Invalid, duplicated, out-of-order, or post-terminal work
fails closed. The initial Runtime does not recursively invoke itself and does not
persist prompts, arguments, results, or restart-resumable run state.

### Invariants 34–35: safe outputs and public failures

**Result: satisfied.** Audit, metrics, logs, health, administration, and Event Bus
observations exclude model and tool content, credentials, secret references,
approval evidence, endpoint details, and raw exceptions. Public failures are
safe categories and do not enumerate the tool inventory.

### Invariant 36: v0.26.0 compatibility

**Result: satisfied.** When agent configuration is absent, the Runtime preserves
v0.26.0 behavior and emits no agent services or events. Inference remains an
independently configured subsystem.

## Residual risks

- A malicious or defective installed tool adapter can abuse authority that the
  deployment itself granted to that adapter. Code review, process isolation, and
  operating-system controls remain deployment responsibilities.
- External systems may execute a side effect before returning an ambiguous
  failure. Phoenix avoids automatic repetition but cannot promise exactly-once
  execution without domain-specific idempotency or reconciliation.
- Prompt and tool-result injection can still influence later model output. The
  security boundary is that influence never bypasses schema, policy, approval,
  limits, or trusted resource resolution.
- A future content-retention feature could create new disclosure risk and
  requires a separate reviewed contract.
- Autonomous scheduling, remote machine administration, arbitrary shell,
  unrestricted HTTP, filesystem control, and persistent agent memory remain
  outside this release.

## Release conclusion

RFC-0027 is acceptable for Phoenix OS v0.27.0 only when the full project quality
gate and `python scripts/check_agent_release.py` pass against the final release
commit. The named gate must build and inspect wheel and sdist artifacts, rebuild
a wheel from the sdist, and execute both wheels in isolated offline environments
without source-tree imports.
