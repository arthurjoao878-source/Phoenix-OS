# ADR-0015: Opt-in inference Runtime and separated administration

- **Status:** Accepted
- **Date:** 2026-07-27
- **Related RFC:** [RFC-0026](../rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md)

## Context

Inference adds installed provider code, model registrations, policy decisions,
optional credential leases, endpoint admission, concurrency state, content-free
diagnostics, Dashboard controls, and optional machine administration. Existing
v0.25.0 deployments must not gain these behaviors merely by upgrading.

Human administration, machine administration, and model invocation also use
different identities and security evidence. Combining them would either grant
too much authority or force browser controls onto service accounts.

## Decision

Inference is disabled by default. `RuntimeAssembler` creates no inference
service, registry, provider, model, endpoint, credential lease, route, or network
permission unless `inference_enabled=True` and reviewed configuration,
providers, and central policy are supplied.

Supplying dormant inference options while the feature is disabled is rejected
rather than ignored.

When enabled, one Runtime-owned stack composes the registry, authorization,
credential broker, endpoint policy, admission state, execution Runtime,
administration, safe health, audit, observability, and lifecycle owner. It
creates no second Phoenix listener and no background network listener.

Startup validates exact provider/configuration identity and model compatibility
before exposing the service. Shutdown rejects new requests, drains active work,
performs cooperative bounded cancellation, revokes remaining credential leases,
releases admission capacity, and closes adapters in reverse order. Partial
startup rolls back deterministically.

Human administration is available only through durable operator mode. It uses
exact inference permissions, durable-session CSRF, no-store responses,
action-bound step-up for enable operations, optimistic revisions, and
content-free inventory and health.

Machine administration is a separate optional flag. It reuses RFC-0023 token
authentication, nonce and timestamp replay protection, central policy, exact
actions, gateway resource `inference-machine`, and one concrete runtime,
provider, or model resource. Aggregate inventories and configuration or
credential management are intentionally absent.

Invocation authority is independent from administration. `model.infer` grants
neither lifecycle management nor Dashboard access, and administration grants no
model invocation.

Provider and model lifecycle state is runtime-local in RFC-0026. Prompts and
responses are not persisted by default. Rollback removes policy grants and
disables registrations before removing Runtime composition while preserving
unrelated Phoenix state and exact secret versions.

## Consequences

Positive consequences:

- unchanged v0.25.0 assemblies add no inference behavior;
- provider execution, limits, administration, and shutdown have one owner;
- no additional inbound listener or externally reachable socket is created;
- human, machine, and invocation authority remain separate;
- content-free administration can stop providers and models without disclosing
  requests, responses, endpoints, or credentials;
- inference can be enabled, tested, and rolled back independently.

Costs and constraints:

- configuration is explicit;
- every provider and model must exist before Runtime startup;
- human administration requires durable operator mode;
- machine administration requires service accounts, policy, replay, and secure
  network configuration;
- lifecycle disablement is not provider registration persistence;
- feature-disabled rollback removes inference services rather than converting
  them into another subsystem.

## Alternatives considered

### Enable inference automatically when providers are supplied

Rejected because a configuration refactor could accidentally introduce
credential use, provider quota, cost, or network authority.

### Always register empty inference services

Rejected because compatibility includes absence from the service map, component
graph, Control Plane routes, and diagnostics.

### Let each provider own independent Runtime lifecycle

Rejected because startup rollback, admission, credential cleanup, cancellation,
and reverse shutdown would become nondeterministic.

### Use browser administration routes for service accounts

Rejected because cookies, CSRF, step-up, token replay, scopes, resources, and
transport identity have different threat models.

### Enable machine routes whenever service accounts are enabled

Rejected because machine administration is a separate grant of authority and
must remain absent by default.

### Persist prompts and responses for convenience

Rejected because content retention requires a separate reviewed privacy,
security, retention, and access-control contract.

## Supersession criteria

A future ADR may change Runtime composition only if disabled deployments remain
behaviorally absent, startup and reverse shutdown stay deterministic and
bounded, safe output remains content-free by default, no extra listener is
created implicitly, and invocation, human administration, and machine
administration retain independent authorization models.
