# RFC-0036 Secure Integrated Agent Execution Threat-Model and Security-Invariant Review

## Review method

This S7 hardening review maps the frozen RFC-0036 threat model and all 102 security
invariants to the S1-S7 implementation and executable regression surface.

The dominant rules are:

> Plan is data, not authority.

> Content is data, not authority.

> Composition never replaces the canonical authority boundary of the final protected
> operation.

> Data flow between capabilities is explicitly server-admitted.

RFC-0027 remains the authoritative agent-loop primitive, RFC-0028 remains the durable
run/recovery primitive, RFC-0016 remains the predefined workflow-DAG primitive, and
RFC-0033 plus each downstream RFC remains authoritative for protected operations.

## Trust boundaries

Trusted state includes Phoenix-owned task identity/digest binding, configured agent and
integrated profile ID/generation, exact integrated tool bindings, current RFC-0027
registry/schema state, exact downstream profiles/resources/scopes/freshness, current
authority subject and policy, current approvals when required, finite data-flow policy,
exact provenance atoms, authenticated result audience, current budget/deadline/
cancellation, and RFC-0028 durable metadata/safe-boundary state.

Untrusted data includes task text, model plans/output, tool proposals/arguments/results,
memory/workspace/browser/network/clipboard content, child-agent output, filenames,
checkpoint metadata as content, resupplied recovery context, provider metadata, adapter
responses, telemetry, health output, and historical ALLOW decisions.

## Protected-operation ordering

A model-originated protected operation is admitted in the frozen order: strict proposal
validation, canonical normalization, exact integrated binding/tool/resource resolution,
provenance propagation and sink derivation, fail-closed provenance overflow plus
data-flow admission, `tool.invoke`, downstream canonical authority, then final
freshness/profile/budget/deadline/cancellation revalidation before effect admission.

A denied data flow therefore consumes no downstream approval and produces no downstream
effect. A data-flow allow remains disclosure/input admission only and never replaces
`tool.invoke` or downstream authority.

## Invariant map

- Invariant 1: Integrated execution is disabled unless explicitly configured.
- Invariant 2: Enabling integrated execution grants no automatic authority or external capability.
- Invariant 3: Every task uses one stable Phoenix-owned IntegratedTaskId.
- Invariant 4: Each IntegratedTaskId is permanently bound to one canonical task digest.
- Invariant 5: Task-identity reuse with different bytes or reviewed inputs fails closed.
- Invariant 6: Each admitted attempt reuses an existing RFC-0027 AgentRunId.
- Invariant 7: RFC-0036 creates no second authoritative run identity.
- Invariant 8: RFC-0036 creates no second authoritative step identity.
- Invariant 9: Phoenix resolves the exact integrated profile before agent.run authorization.
- Invariant 10: agent.run intent binds task digest/profile ID and profile generation freshness.
- Invariant 11: Task/model text cannot replace the authoritative integrated profile binding.
- Invariant 12: Task input is untrusted data and grants no authority.
- Invariant 13: Task digest and profile binding are immutable for an admitted run.
- Invariant 14: Model planning is untrusted and grants no authority.
- Invariant 15: Model turns remain final output or one ToolCallProposal.
- Invariant 16: Plan updates use only the server-owned integrated.plan.update tool.
- Invariant 17: Plan update requires tool.invoke and mutates only bounded advisory state.
- Invariant 18: Normalized plan revisions remain data, not authority.
- Invariant 19: Plan revisions do not become RFC-0016 executable workflow graphs.
- Invariant 20: Starting a run does not authorize model inference.
- Invariant 21: Starting a run does not authorize tool invocation.
- Invariant 22: Starting a run does not authorize downstream protected operations.
- Invariant 23: Every model turn retains model.infer.
- Invariant 24: Every model-originated tool call retains tool.invoke.
- Invariant 25: Every downstream protected operation retains its canonical authority.
- Invariant 26: No upstream allow substitutes for a downstream allow.
- Invariant 27: The planner cannot create or modify AuthoritySubject.
- Invariant 28: The planner cannot choose arbitrary policy resources.
- Invariant 29: The planner cannot choose credentials or secret references.
- Invariant 30: The planner cannot create or widen integrated/downstream profiles.
- Invariant 31: Current configuration wins over planned or persisted state.
- Invariant 32: Current policy wins over prior decisions.
- Invariant 33: Current cancellation wins over prior admission.
- Invariant 34: Current deadline wins over prior admission.
- Invariant 35: Current remaining budget wins over planned budget.
- Invariant 36: No approval is inherited from a prior step.
- Invariant 37: No approval is inherited from the surrounding task/run.
- Invariant 38: No checkpoint approval is restored as live authority.
- Invariant 39: Arguments are normalized before protected-operation authorization.
- Invariant 40: Stale resource identities fail closed.
- Invariant 41: Tool results remain untrusted data.
- Invariant 42: Browser observations remain untrusted data.
- Invariant 43: Network responses remain untrusted data.
- Invariant 44: Memory contents remain untrusted data.
- Invariant 45: Workspace contents remain untrusted data.
- Invariant 46: Clipboard contents remain untrusted data.
- Invariant 47: Child-agent results remain untrusted data.
- Invariant 48: One content source cannot manufacture another subsystem's authority.
- Invariant 49: Provenance is a bounded set of exact Phoenix-owned atoms.
- Invariant 50: Provenance source bindings preserve exact reviewed identity/scope.
- Invariant 51: Provenance freshness bindings are descriptive and non-bearer.
- Invariant 52: Transformations conservatively union all input provenance plus output source.
- Invariant 53: No v0.36.0 transform can declassify, weaken, relabel, or coalesce provenance.
- Invariant 54: Provenance atom-count and encoded-byte limits are finite.
- Invariant 55: Provenance overflow fails closed before derived content is used.
- Invariant 56: Phoenix never truncates provenance silently.
- Invariant 57: Cross-subsystem flow requires an exact server-owned route.
- Invariant 58: Final disclosure is an explicit USER_RESULT sink.
- Invariant 59: USER_RESULT audience comes from trusted authenticated context.
- Invariant 60: Data-flow allow grants no protected-operation authority.
- Invariant 61: Data-flow deny occurs before approval consumption and effect admission.
- Invariant 62: The model cannot create or modify data-flow allow rules.
- Invariant 63: Every visible tool has exactly one server-owned IntegratedToolBinding.
- Invariant 64: Missing/duplicate/ambiguous/unsupported bindings fail validation.
- Invariant 65: Each integrated tool is exactly LOCAL_TRANSFORM or DOWNSTREAM_BRIDGE.
- Invariant 66: LOCAL_TRANSFORM has no ambient downstream/external authority.
- Invariant 67: Local transforms preserve provenance and mutate only reviewed advisory state.
- Invariant 68: DOWNSTREAM_BRIDGE binds one exact downstream boundary and identity.
- Invariant 69: Bridge adapters cannot substitute downstream profile/scope/resource/action.
- Invariant 70: v0.36.0 admits at most one effectful integrated step at a time.
- Invariant 71: Parallel effectful integrated execution is unsupported in v0.36.0.
- Invariant 72: No effectful integrated step is transparently retried.
- Invariant 73: A later proven-no-effect attempt is new and freshly authorized.
- Invariant 74: Possible started effects become indeterminate unless certainty is proven.
- Invariant 75: Indeterminate effects are never automatically repeated.
- Invariant 76: Cancellation prevents admission of new work.
- Invariant 77: Cancellation is not rollback.
- Invariant 78: Child deadlines never exceed remaining parent deadline.
- Invariant 79: The most restrictive applicable authoritative limit wins.
- Invariant 80: Integrated execution does not duplicate RFC-0027 authoritative counters.
- Invariant 81: Delegation cannot manufacture root budget.
- Invariant 82: Checkpoints grant no authority.
- Invariant 83: Durable metadata binds exact task digest and integrated profile generation.
- Invariant 84: Metadata-only recovery does not prove planning context is reconstructable.
- Invariant 85: Automatic replanning after restart requires sufficient reviewed context.
- Invariant 86: Missing context waits for explicit resupply or terminates safely.
- Invariant 87: Resupplied context is untrusted and cannot replace trusted execution identity/state.
- Invariant 88: Recovery requires exact persisted task identity/digest.
- Invariant 89: Recovery requires current configured agent/profile compatibility.
- Invariant 90: Recovery requires fresh current authorization.
- Invariant 91: Recovery requires current compatible configuration.
- Invariant 92: Consumed/expired/revoked/mismatched approvals are not restored.
- Invariant 93: Stale browser session/page/revision/element identities are not restored.
- Invariant 94: Recovery cannot assume an uncertain external effect did not occur.
- Invariant 95: Plan revisions cannot rewrite task/profile/completed history.
- Invariant 96: Completed step and attempt identities are immutable.
- Invariant 97: Derived orchestration phase cannot contradict authoritative run state.
- Invariant 98: Routine observability is content-free.
- Invariant 99: Public failures are bounded and redacted.
- Invariant 100: Integrated execution cannot recursively invoke itself without a future reviewed boundary.
- Invariant 101: Installed adapters are trusted code; model/external data remains untrusted.
- Invariant 102: Omitted integrated configuration preserves Phoenix OS v0.35.0 behavior.

## Adversarial release cases

Release-blocking coverage includes task-body substitution, integrated-profile
substitution, prompt injection that attempts to manufacture canonical resources,
credential/profile selection, authority laundering through plans, confused-deputy
bridges, bridge profile/scope/resource substitution, missing/duplicate tool bindings,
bypass of the one-ToolCallProposal model-turn contract, data-flow denial after rather
than before approval, cross-subsystem exfiltration, final-result leakage, provenance
loss/laundering/declassification/overflow, budget/deadline/cancellation races, stale
integrated and downstream profiles, duplicate or transparent effect retry,
indeterminate-effect replay, checkpoint authority replay, metadata-only recovery without
planning context, malicious context resupply, consumed approval reuse, stale browser
identity restoration, persisted-content injection, content leakage through operational
surfaces, unbounded replanning, recursion/re-entry, and lifecycle inconsistency.

`tests/test_integrated_agent_end_to_end.py` exercises deterministic network-free
IntegratedAgentRuntime -> AgentService -> AgentLoop completion and final USER_RESULT
denial. `tests/test_integrated_agent_security_adversarial.py` proves independent
downstream memory authority and memory-to-network exfiltration denial with zero network
service calls on denied flow. The broader `tests/test_integrated_agent_*.py` suite maps
the remaining contracts, composition, provenance, budget/effect, and durable recovery
invariants.

## Durability and recovery

RFC-0028 remains authoritative. Integrated checkpoints contain bounded orchestration
metadata and exact task/profile binding but grant no authority.

Recovery revalidates current agent/profile compatibility, tool/downstream configuration,
policy/authority, limits, deadline/cancellation, approvals when applicable, and subsystem
freshness. Metadata-only state is insufficient for automatic planning when the required
context cannot be reconstructed. Missing context must wait for explicit reviewed
resupply or terminate safely.

Indeterminate effects are never automatically replayed. Stale browser identities and
consumed approvals are never restored as usable authority.

## Observation and administration

Routine integrated telemetry and health are content-free and constructed from a closed
bounded observation/snapshot vocabulary. Event payloads are empty. Raw task/prompt/model/
tool/browser/network/memory/workspace/clipboard content, credentials, secrets, approval
evidence, policy internals, provenance source bindings, and raw exceptions are excluded.

Health and run inspection use separate permissions. Service-principal inspection is
bound to one exact run-scoped resource and exposes only reviewed bounded redacted
metadata.

## Package and publication boundary

S7e must add `python scripts/check_integrated_agent_release.py` and make it release
blocking. The gate must validate the exact integrated package surface, complete
integrated regression suite, RFC/migration/ADR/security documents, wheel/sdist safety,
matching metadata, rebuild-from-sdist behavior, isolated install/smoke, and deterministic
network-free E2E behavior.

S7d does not modify package version, `CHANGELOG.md`, release notes, tags, publication
metadata, or remote release state. Those operations remain S8 work after S7e and global
gates are green.

## Residual risks

RFC-0036 cannot make hostile model or remote content trustworthy, guarantee exactly-once
external effects, reconstruct content that was intentionally not persisted, revoke bytes
already disclosed to an external peer, or prove security properties of deployment
adapters outside reviewed Phoenix contracts. Operators who intentionally configure
broader profiles or data-flow routes expand trusted configuration scope and must review
that configuration.

## Review conclusion

The S1-S7d architecture is consistent with the frozen RFC-0036 threat model provided the
dedicated S7e integrated-agent release/package gate remains green and the final S8
canonical diff/adversarial review confirms that release metadata finalization does not
widen authority, disclosure, recovery, observability, package, or lifecycle semantics.

Tag creation, artifact/checksum publication, GitHub Release publication, remote
branch/PR operations, review, and merge remain separately authorized release operations.
