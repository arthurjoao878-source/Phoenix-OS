# RFC-0033: Effective Authority and Capability Non-Amplification

- Status: Accepted
- Target release: Phoenix OS v0.33.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0002, RFC-0003, RFC-0009, RFC-0010, RFC-0020, RFC-0026, RFC-0027, RFC-0028, RFC-0029, RFC-0030, RFC-0031, and RFC-0032

## Summary

RFC-0033 defines how Phoenix OS determines, preserves, and explains the effective
authority of an agent or caller across composed subsystem boundaries.

The security objective is not to claim that capability composition can never produce
new useful behavior. Composition necessarily creates workflows that individual
capabilities cannot produce alone.

The required property is narrower and security-relevant:

> **Every protected operation remains dominated by its canonical authority boundary,
> regardless of how that operation is reached.**

A capability or composition of capabilities must not bypass, weaken, substitute,
manufacture, replay, or inherit authority that the canonical boundary for the final
protected operation would otherwise require.

Phoenix therefore treats effective authority as a point-in-time result of current
trusted state, not as a transferable ambient grant.

## Principle

> **Composition may create new workflows; it may not create a path around the
> authority required by the final protected operation.**

For example, allowing application launch while denying filesystem write is meaningful
only if the launch capability does not expose model-controlled shell commands,
executable paths, arguments, working directories, environment variables, standard
input, scripting channels, or equivalent mechanisms that reconstruct the prohibited
filesystem effect.

RFC-0032 server-owned configured application profiles are the precedent for this
property.

## Security objective

Phoenix OS v0.33.0 must establish the following claim:

> A compromised model, prompt, workspace artifact, tool result, clipboard value, or
> agent decision process cannot cause a Phoenix-mediated protected operation outside the
> effective authority currently held by its bound authority subject.

The claim applies to Phoenix-mediated protected operations and reviewed Phoenix subsystem
boundaries.

It does not claim containment of arbitrary code execution inside the trusted Phoenix
process.

## Scope

RFC-0033 applies to the reviewed authority paths that can participate in Phoenix agent
execution or in the new authority-inspection surface for v0.33.0.

The normative in-scope operations are the operations listed in the canonical authority
inventory below. They cover configured agent execution, model inference, tool
invocation, agent delegation, durable resume/reconciliation, agent memory, agent
workspaces, RFC-0032 host automation, and RFC-0033 authority inspection/explanation.

Existing operator administration, authentication/session issuance, policy
administration, remote-control-plane, webhook, inbound-event, audit-maintenance, and
other non-agent control-plane operations remain governed by their existing RFCs and are
not re-specified by RFC-0033 merely because they are Phoenix-mediated.

If an in-scope agent path is later able to reach one of those or any other protected
operations, that reachable operation and its canonical boundary must be added to the
closed-world authority catalog before the path can claim RFC-0033 conformance.

RFC-0034 will separately define outbound Network Authority for agents. RFC-0035 will
separately define secure browser automation. Their future protected operations are not
implicitly granted or modeled by RFC-0033.

## Terminology

- **Protected operation:** a Phoenix-mediated action that requires authority because it
  may disclose sensitive data, consume security-relevant resources, cross a trust
  boundary, delegate work, invoke another subsystem, or change externally observable
  state.
- **Protected effect:** the state-changing or externally consequential result of a
  protected operation. A protected operation may be security-sensitive without being
  state-changing; sensitive reads and disclosures are the primary example.
- **Authority subject:** the trusted identity tuple to which an authorization applies.
- **Authority subject projection:** the exact subset of a bound authority subject that
  one boundary's contract requires. A projection may omit dimensions irrelevant to
  that boundary, but it cannot add, replace, or strengthen an identity dimension.
- **Authority intent:** the exact action, canonical resource, normalized parameters,
  and applicable freshness identity being authorized.
- **Canonical authority boundary:** the Phoenix-owned mediation point that must be
  crossed before one protected operation may be admitted.
- **Authority transition:** an explicit, narrow, separately authorized change from one
  authority subject to another, such as admission of a configured child agent. Mere
  internal service calls are not authority transitions.
- **Operation admission:** the point after final required validation at which Phoenix
  commits to invoking the protected downstream operation. For state-changing effects,
  this is also the effect-admission boundary used by existing indeterminate-effect
  semantics.

## Effective authority

Effective Authority is the set of Phoenix-mediated protected operations that a bound
authority subject can currently cause through admissible paths, subject to:

- current policy;
- current authenticated identity and live session when session-backed;
- exact configured agent identity;
- exact agent run identity;
- exact approval when required;
- canonical resource identity;
- current resource generation, version, epoch, or equivalent freshness identity;
- normalized operation parameters;
- delegation constraints;
- current cancellation state;
- current admission state; and
- the canonical authority boundary of every protected downstream operation.

Effective Authority is calculated from trusted current state.

It is not:

- a bearer token;
- a generic transferable capability object;
- a persisted authorization decision;
- an approval record;
- a policy snapshot;
- an inspection result;
- a model-visible credential; or
- authority manufactured from data.

## Authority subject

An agent-originated protected operation must be attributable to a bound subject containing
the relevant trusted identities:

```text
AuthoritySubject
    principal_type
    principal
    session_id?      # when session-backed
    agent_id?        # when agent-originated
    run_id?          # when run-bound
```

Optional fields indicate that not every non-agent or non-session caller uses every
identity dimension.

When a dimension is applicable, it is security-significant.

Changing an applicable principal, session, agent, or run creates a different authority
subject and invalidates pending authority bound to the previous subject.

Model output must never supply these trusted identity fields.

## Authority intent

Protected operations are authorized against an exact intent:

```text
AuthorityIntent
    action
    canonical_resource
    parameter_digest
    freshness_bindings[]
```

`freshness_bindings` is a bounded, server-derived set of zero or more
subsystem-specific freshness identities needed to reject stale state or resource
rebirth.

One operation may require more than one binding. Examples include:

- HostEpoch for host resource identity;
- workspace artifact version;
- memory record version;
- durable run/checkpoint version;
- durable lease generation; and
- equivalent finite identities defined by future subsystems.

Freshness bindings are intent data used for exact validation. They are not bearer
credentials and cannot create authority by themselves.

RFC-0033 does not require all subsystems to use the same freshness type or number of
bindings.

## Canonical authority boundary

A canonical authority boundary is the Phoenix-controlled mediation point that must be
crossed before a protected operation may be admitted.

Authorization at an upstream boundary does not replace authorization required by a
downstream canonical boundary.

Examples include:

| Protected operation | Canonical authority boundary |
| --- | --- |
| configured agent run | `agent.run` |
| model inference | `model.infer` |
| tool adapter invocation | `tool.invoke` |
| agent delegation | `agent.delegate` |
| durable resume | `agent.resume` |
| durable reconciliation | `agent.reconcile` |
| memory search | `memory.search` |
| memory read | `memory.read` |
| memory write | `memory.write` |
| memory delete | `memory.delete` |
| memory administration | `memory.admin` |
| workspace listing | `workspace.list` |
| workspace read | `workspace.read` |
| workspace write | `workspace.write` |
| workspace delete | `workspace.delete` |
| workspace import | `workspace.import` |
| workspace export | `workspace.export` |
| workspace administration | `workspace.admin` |
| host process listing | `host.process.list` |
| host window listing | `host.window.list` |
| configured application launch | `host.app.launch` |
| window focus | `host.window.focus` |
| configured application close | `host.app.close` |
| clipboard write | `host.clipboard.write` |
| clipboard read | `host.clipboard.read` |
| authority inspection | `authority.inspect` |
| authority explanation | `authority.explain` |

This table is the normative built-in protected-operation inventory for the v0.32.0
baseline plus the new RFC-0033 inspection surface. RFC-0033 acceptance requires it to
remain complete for every reviewed in-scope Phoenix-mediated protected operation.

The catalog is closed-world. A Phoenix-owned path to an in-scope protected operation
that is absent from the reviewed catalog is non-conformant and must fail closed in
authority inspection/explanation. Catalog entries describe required mediation; they
never grant authority.

## Canonical-boundary dominance

For every protected operation O with canonical authority boundary B:

1. every Phoenix-supported path capable of causing O must cross B;
2. absent an explicit authority transition, the authority path must retain the same full
   bound authority subject from the requesting path through operation admission;
3. each boundary receives the exact trusted authority-subject projection required by its
   contract;
4. a projection may omit a subject dimension that the boundary does not use, but it may
   not alter that dimension, manufacture a replacement identity, or imply that an
   upstream binding disappeared;
5. every subject dimension that is security-significant for the complete path must be
   bound by at least one non-bypassable authority boundary on that path;
6. after an explicit authority transition, later boundaries receive projections of the
   exact newly admitted subject and do not inherit authority from the previous subject
   implicitly;
7. B receives canonical trusted resource identity and normalized parameters;
8. upstream authorization or approval must not substitute for B;
9. observation or discovery must not substitute for B; and
10. an internal subsystem must not invoke O using a stronger authority subject than the
    requesting path unless an explicit, narrow, separately authorized authority
    transition permits that change.

A subsystem that can directly perform O while bypassing B violates RFC-0033.

A downstream boundary is not required to add identity fields that are irrelevant to
its own contract merely to mirror the complete path subject. For example, an
agent-originated host operation may require `tool.invoke` to bind agent/run identity
and a downstream `host.*` boundary to bind the host action and resource. The path is
admissible only if both boundaries allow; the downstream host authorizer does not erase
the upstream agent/run binding merely because its own request contract does not contain
those fields.

## Cumulative path authority

Authority along one concrete path composes by intersection, not union.

If a path requires boundaries B1, B2, ... Bn, the path is admissible only when every
required boundary allows its exact portion of the current subject and intent and every
required freshness/approval constraint is satisfied.

An ALLOW at one boundary cannot compensate for a DENY, stale binding, missing approval,
or missing canonical mediation at another boundary.

Consequently:

```text
agent -> tool -> host
```

does not mean that `tool.invoke` grants `host.*`, nor that `host.*` grants
`tool.invoke`. A model-originated host operation is reachable only through the
intersection of the required agent-tool and host-operation authority.

The same rule applies to memory, workspace, durable, delegation, and future reviewed
composition paths.

## Security invariants

### EA-1 — Default deny

Absence of current authority is denial.

Installing, enabling, registering, discovering, or observing a capability grants no
authority automatically.

### EA-2 — Canonical operation mediation

Every protected operation has a canonical Phoenix mediation boundary.

No supported internal composition may bypass that boundary.

### EA-3 — Bound authority subject

Every agent-originated protected operation is bound at the authority-path level to the
applicable principal, principal type, session, agent, and run identities.

Each boundary consumes only its declared trusted subject projection; no projection may
manufacture, replace, or strengthen an identity dimension.

Changing any applicable identity creates a different path subject and invalidates
pending authority bound to the old subject.

### EA-4 — Data is not authority

Prompts, model output, files, workspace artifacts, memory content, tool output,
clipboard text, process metadata, window metadata, labels, titles, external content,
and adapter-returned data cannot create, approve, widen, transfer, or substitute
authority.

### EA-5 — Fresh authority after the last untrusted wait

Every revocable authority source required for a protected operation must be revalidated
after the last attacker-controlled or user-controlled wait and before operation
admission.

An approval wait is such a wait.

### EA-6 — Exact intent binding

Authority and approval are bound to the exact action, canonical resource, normalized
parameter digest, and applicable resource generation/version/epoch.

Parameter mutation after authorization invalidates the authority.

### EA-7 — No confused deputy

A Phoenix subsystem handling a request for one authority subject must not silently
replace that subject with its own stronger authority when invoking a protected
downstream operation.

### EA-8 — Delegation is not protected-operation authority delegation

`agent.delegate` authorizes one bounded child delegation.

It does not automatically grant the child any `tool.invoke`, `workspace.*`, `host.*`,
or other protected-operation authority.

The child must satisfy the authority required for its own protected-operation path.

### EA-9 — Approval is not authorization

Approval records consent for one exact bound intent.

Approval cannot turn a current policy DENY into ALLOW and cannot replace fresh policy
authorization.

### EA-10 — Admission has a linearization boundary

Before operation admission, cancellation, revocation, expiry, stale identity, stale
resource generation, or failed reauthorization prevents the protected operation.

After operation admission, Phoenix must not claim that cancellation or revocation
retroactively prevented an operation that may already have started.

For state-changing operations, failures after admission remain subject to existing
indeterminate-effect semantics.

### EA-11 — Observation is not authority

Authority inspection, explanation, audit events, resource discovery, and diagnostic
output are point-in-time observations only.

Their outputs are never accepted as authorization credentials, approval evidence, or
bearer authority.

### EA-12 — Resource rebirth creates a distinct authority target

A resource that disappears and later reuses an operating-system identifier, handle,
path, slot, version position, or other implementation identity does not inherit
authority issued for its predecessor.

Phoenix-owned finite identities, epochs, versions, generations, or equivalent
freshness mechanisms must distinguish security-relevant rebirth.

## Freshness semantics

RFC-0033 does not require an impossible atomic transaction spanning policy state,
identity state, Phoenix runtime state, and the operating system.

Instead, Phoenix defines a practical admission rule:

1. resolve and validate the exact intent;
2. obtain required approval, if any;
3. after the final attacker-controlled or user-controlled wait, revalidate every
   revocable authority source;
4. validate the authority subject;
5. validate current resource identity/generation;
6. validate cancellation;
7. admit the protected operation without another untrusted blocking wait; and
8. execute through the canonical authority boundary.

The final validation sequence may await trusted Phoenix components, but it must not
contain an attacker-controlled or user-controlled wait after the final validation of a
revocable source.

RFC-0033 does not claim one atomic snapshot across all mutable authority stores. Its
freshness guarantee is source-specific: if a revocation or policy change linearizes
before that source's final revalidation, the protected operation must be denied. A
subsystem that requires a stronger cross-store guarantee must use an explicit revision,
generation, fencing token, or equivalent mechanism.

If a relevant change linearizes after operation admission, the operation has already
crossed the admission boundary and Phoenix must not report a fictitious rollback.

## Session freshness

RFC-0033 introduces an optional structural session-identity binding on
`SecurityContext` for session-backed contexts.

The trusted `Session` / identity boundary populates this structural session identity.
RFC-0033 authority code must not treat a caller-supplied
`SecurityContext.attributes["session_id"]`, request attribute, prompt field, model
field, or tool argument as proof of session binding.

A legacy `session_id` attribute may remain temporarily for compatibility or
diagnostics, but it is non-authoritative for RFC-0033 admission and approval binding.

A previously constructed `SecurityContext` is not sufficient proof that a
session-backed subject remains current.

Protected-operation admission must be able to validate the current session using
trusted Phoenix session identity without requiring or exposing the original bearer
token.

A session identifier is not itself authentication authority and must never become a
replacement bearer credential.

Revoked, expired, missing, or principal-mismatched sessions fail closed.

## Agent binding

Trusted tool invocations produced by the agent loop must preserve the server-owned
`agent_id` from the `AgentRunRequest`.

The model cannot choose or mutate this identity.

Agent identity participates in authority and approval binding for agent-originated
protected operations.

This prevents one configured agent from borrowing another agent's approval or
operation-specific authority merely because both execute under the same human principal.

## Approval binding

Tool approval binding for RFC-0033 must include at least:

- principal type;
- principal;
- session identity when applicable;
- agent identity;
- run identity;
- step identity;
- call identity;
- tool identity;
- effect class;
- canonical resource;
- normalized argument digest;
- reviewed resolver identity;
- reviewed adapter identity;
- approval expiry.

Approval remains short-lived and single-use.

Persisted older approval representations may be decoded for safe migration or
diagnostics, but an older schema that lacks required RFC-0033 subject binding must not
be silently upgraded into authority for a new protected operation.

## Policy attribute integrity

Identity-derived attributes and request-derived intent/resource attributes must not be
able to overwrite one another through an ambiguous shared namespace.

RFC-0033 implementations must either:

1. reject collisions between trusted context attributes and request attributes; or
2. introduce structurally separated namespaces with equivalent fail-closed behavior.

Request-controlled or subsystem-generated intent attributes must never impersonate
identity attributes.

## Ambient confirmation

A general ambient `confirmed=true` flag is insufficient proof of consent for an
RFC-0033 protected operation.

In-scope protected-operation paths requiring approval must use exact action/resource/subject/intent
binding.

Legacy confirmation behavior may remain for compatibility outside RFC-0033 protected-operation
paths until separately migrated.

## Composition and non-amplification

Authorization for capability A and capability B does not authorize protected operation C
when C's canonical boundary denies the bound subject.

If A and B can be composed into a workflow that causes C, the composed path must still
cross C's canonical authority boundary.

When a capability intentionally launches or invokes an external program capable of
many incidental side effects, Phoenix's claim is limited to agent-controllable
mediated effects.

Server-owned profiles must not expose an agent-controlled command, shell, argument,
environment, standard-input, scripting, automation, or equivalent channel that
reconstructs a denied Phoenix-mediated effect.

## Confused deputy resistance

Internal Phoenix services must preserve the requesting authority subject across
protected downstream calls.

Service identities used for implementation plumbing are not automatically authority
to perform the requested protected operation on behalf of a weaker subject.

Any intentional authority transition requires an explicit, narrow, independently
authorized contract.

## Multi-agent authority

A child agent may execute under the same authenticated human principal as its parent,
but it has a distinct configured `agent_id` and run identity.

Delegation therefore authorizes work routing, lineage, budgets, and child admission,
not all protected operations available to the parent agent.

Approval or authority bound to one agent/run cannot be consumed by another
agent/run.

## Adversarial conformance suite

RFC-0033 acceptance requires deterministic tests for at least:

1. protected operation attempted with no permission;
2. approval expiry during a wait;
3. policy ALLOW changing to DENY before final admission validation;
4. session revocation before admission;
5. principal substitution;
6. session substitution;
7. agent substitution;
8. run substitution;
9. resource mutation after approval;
10. argument mutation after authorization;
11. untrusted file content attempting to manufacture authority;
12. prompt content requesting that the agent obtain or fabricate a grant;
13. composition A+B attempting to reconstruct denied effect C;
14. an authorized subsystem attempting to call a higher-authority downstream service;
15. one agent attempting to borrow another agent's approval;
16. resource identity rebirth/reuse;
17. cancellation before operation admission;
18. cancellation after operation admission;
19. workspace-to-host composition attempting an indirectly prohibited host effect;
20. stale durable version/generation reuse;
21. spoofed `session_id` in context/request attributes attempting to create or preserve
    session-bound authority;
22. an in-scope protected operation missing from the authority catalog; and
23. unauthorized authority inspection/explanation of another subject.

Race tests must use deterministic barriers or hooks rather than timing sleeps.

## Authority inspection and explanation

Phoenix v0.33.0 must provide read-only authority inspection/explanation primitives.

Conceptually:

```text
phoenix authority inspect agent-42
phoenix authority explain agent-42 host.app.launch vscode
```

The implementation may expose the service API before the thin CLI surface.

An explanation should be able to report, where applicable:

- ALLOWED or DENIED;
- principal;
- session identity in safe form;
- agent;
- run;
- requested action;
- canonical resource;
- authority path;
- applicable constraints;
- denial reason; and
- blocked downstream alternatives.

Inspection and explanation must not expose:

- bearer session tokens;
- secret values;
- approval evidence suitable for replay;
- internal MAC/HMAC material;
- unrestricted environment values;
- hidden executable paths;
- credentials;
- native PID/HWND values as authority;
- sensitive resource content; or
- policy internals unnecessary to explain the result.

Inspection results are point-in-time observations and are never accepted as authority.

Inspection is itself a protected read operation. Phoenix v0.33.0 therefore defines
separate deny-by-default policy actions for this surface:

- `authority.inspect` for one exact server-resolved authority subject; and
- `authority.explain` for one exact server-resolved subject and authority intent.

The caller performing inspection is distinct from the subject being inspected. The
caller must be independently authorized to inspect or explain that target; possession
of an agent ID, run ID, session ID, label, or inspection result grants no such right.

`AuthorityService` must never mutate policy, sessions, approvals, delegation state, or
resource state while answering inspection/explanation requests.

## Architecture

RFC-0033 introduces an authority package as a composition and verification layer, not
as another policy engine:

```text
src/phoenix_os/authority/
    contracts.py
    catalog.py
    freshness.py
    admission.py
    service.py
    redaction.py
```

Responsibilities:

- `contracts.py`: authority subject, intent, boundary, path, decision, explanation;
- `catalog.py`: reviewed canonical protected-operation inventory and mediated paths;
- `freshness.py`: subject/session/resource freshness validation;
- `admission.py`: reusable final-validation contracts/helpers that cannot authorize or
  invoke a protected operation by themselves;
- `service.py`: read-only inspect/explain composition;
- `redaction.py`: safe diagnostic projections.

The existing `PolicyEngine` remains the policy decision engine.

Existing host, workspace, memory, agent, coordination, durable, inference, and other
subsystem-specific authorizers remain canonical subsystem boundaries.

Generic capability registration, discovery, local confirmation metadata, or a handler
permission declaration is not a substitute for the canonical downstream boundary of
a protected operation reached by that capability.

The authority layer must not become a super-authorizer capable of bypassing them.

`authority.admission` may validate bindings and freshness, but it must not own an
adapter, execute a tool, call Win32, mutate a workspace, resume a durable run, or return
a reusable bearer capability. Canonical subsystem authorizers and services remain the
only admission path to their protected operations.

## Required implementation changes

Phoenix OS v0.33.0 is expected to require at least:

1. trusted `agent_id` on `ToolInvocationRequest`, derived from `AgentRunRequest`;
2. agent identity in exact `tool.invoke` policy attributes;
3. optional structural `session_id` binding on `SecurityContext` for session-backed
   contexts, with RFC-0033 code refusing attribute-derived session identity;
4. current-session validation at protected-operation admission using the trusted
   structural session binding;
5. tool approval binding schema with session and agent identity;
6. fresh `tool.invoke` reauthorization after approval wait and immediately before tool
   admission;
7. exact cancellation and intent/resource freshness validation before admission;
8. fail-closed policy attribute collision handling;
9. prohibition of ambient confirmation as sufficient approval on RFC-0033 protected
   operation paths;
10. cross-subsystem non-amplification tests;
11. separately authorized, read-only, redacted authority inspection/explanation.

## Implementation slices

### Slice 1 — Authority model and operation inventory

- RFC normative model;
- canonical protected-operation inventory;
- behavior unchanged.

### Slice 2 — Subject binding

- structural authority subject;
- trusted agent identity preserved through tool invocation;
- session identity binding;
- approval binding upgrade;
- principal/session/agent/run substitution tests.

### Slice 3 — Fresh authority admission

- current session validation;
- fresh policy validation after approval wait;
- cancellation validation;
- final pre-admission semantics;
- deterministic revocation/expiry/policy-change tests.

### Slice 4 — Intent and resource freshness

- exact argument/parameter digests;
- host epoch;
- memory version;
- workspace version;
- durable version/generation;
- resource rebirth and mutation tests.

### Slice 5 — Composition and confused deputy

Test at least:

- agent -> tool;
- agent -> tool -> host;
- agent -> tool -> memory;
- agent -> tool -> workspace;
- parent -> child -> tool;
- durable resume -> agent -> tool;
- workspace -> host indirect path.

Prove that composed paths cannot bypass their final canonical authority boundary.

### Slice 6 — Inspect and explain

- `AuthorityService`;
- safe authority projections;
- redaction tests;
- operator-facing integration;
- thin CLI surface only after the service semantics are stable.

### Slice 7 — Security and release gates

Expected dedicated tests include:

```text
tests/test_authority_contracts.py
tests/test_authority_subject_binding.py
tests/test_authority_freshness.py
tests/test_authority_composition.py
tests/test_authority_adversarial.py
tests/test_authority_explain.py
tests/test_authority_redaction.py
tests/test_authority_security_review.py
tests/test_rfc_0033.py
tests/test_authority_release_gate.py
```

Expected dedicated release checker:

```text
scripts/check_authority_release.py
```

Acceptance requires the normal Phoenix quality suite on supported Python versions.

## Threat model

The adversary may control:

- model output;
- prompt content;
- conversation content;
- workspace and imported artifact content;
- memory content;
- tool-returned data;
- clipboard content;
- window/process labels and metadata;
- externally sourced data;
- agent reasoning and tool-selection behavior.

The adversary may attempt to:

- manufacture authority from data;
- replay stale authority;
- swap identities;
- mutate parameters after authorization;
- exploit resource rebirth;
- exploit approval waits;
- exploit policy/session TOCTOU;
- exploit a confused deputy;
- compose allowed capabilities to reconstruct a denied effect;
- borrow authority across agents or runs.

The trusted computing base includes Phoenix core authority/policy/identity logic,
reviewed configured resolvers and adapters, required secret/session stores, and the
underlying operating-system isolation boundary.

Arbitrary malicious Python code already executing inside the trusted Phoenix process,
or a malicious installed adapter that directly bypasses Phoenix mediation using native
APIs, is outside the containment claim of RFC-0033.

Containing hostile extension code requires process isolation or sandboxing and is not
part of Phoenix OS v0.33.0.

## Non-goals

- Network Authority; planned separately for RFC-0034
- Browser automation; planned separately for RFC-0035
- A generic transferable capability-grant token
- A second general-purpose policy engine
- Arbitrary plugin or Python-code sandboxing
- Kernel-level mandatory access control
- Proving that an arbitrary external application has no incidental side effects
- Exactly-once guarantees for external effects
- Retroactive rollback after effect admission
- Treating inspection/explanation output as authority
- Treating approval as a replacement for policy authorization
- Replacing existing subsystem-specific canonical authorizers
- Re-specifying unrelated non-agent control-plane operations already governed by prior RFCs

## Acceptance criteria

RFC-0033 may move to Accepted only when:

1. every reviewed in-scope Phoenix-mediated protected operation has an inventoried
   canonical authority boundary;
2. no reviewed supported composition bypasses that boundary;
3. subject binding covers every applicable principal/session/agent/run identity;
4. revocable authority is revalidated after the final untrusted wait;
5. exact approvals cannot be reused across subject, intent, or resource changes;
6. stale/reborn resource identities fail closed;
7. confused-deputy tests fail closed;
8. cross-agent authority borrowing fails closed;
9. authority inspection is separately authorized, redacted, and non-authoritative;
10. attribute-derived session identifiers cannot create or preserve session-bound
    authority;
11. unknown in-scope protected operations fail closed under the closed-world catalog;
12. the adversarial authority suite passes;
13. the dedicated RFC-0033 release gate passes; and
14. the complete Phoenix CI matrix is green.


## Release acceptance evidence

The v0.33.0 release candidate seals the RFC-0033 acceptance surface with the
following executable evidence:

- [x] Canonical protected-operation catalog is closed-world and inventoried.
- [x] Supported composition paths retain their final canonical boundary.
- [x] Principal/session/agent/run subject substitutions are covered.
- [x] Session and other revocable authority is revalidated after untrusted waits.
- [x] Approval evidence is exact-subject/exact-intent/exact-resource bound.
- [x] Stale and reborn resource identities fail closed.
- [x] Confused-deputy paths fail closed.
- [x] Cross-agent authority borrowing fails closed.
- [x] Authority inspect/explain is separately authorized, redacted, and non-authoritative.
- [x] Attribute-derived session identifiers do not create session-bound authority.
- [x] Unknown protected operations fail closed under the reviewed catalog.
- [x] Dedicated adversarial authority tests are part of the release suite.
- [x] Named authority release gate: `python scripts/check_authority_release.py`.
- [x] The normal Python 3.12/3.13 Phoenix CI matrix executes the named gate.

RFC-0033 is accepted for Phoenix OS 0.33.0. Tag publication and release artifact
upload remain separate release operations after the exact release commit has
passed the complete CI matrix.
