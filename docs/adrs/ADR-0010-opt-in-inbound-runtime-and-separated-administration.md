# ADR-0010: Opt-in inbound Runtime and separated administration

- **Status:** Accepted
- **Date:** 2026-07-25
- **Related RFC:** [RFC-0025](../rfcs/RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md)

## Context

Inbound events add external network authority, durable repositories, schema
registration, secret access, authentication, replay protection, background
publisher and recovery workers, Dashboard controls, and optional machine
administration. Existing Phoenix OS v0.24.0 deployments must not gain any of
these behaviors merely by upgrading.

Source submission, human administration, and non-human administration also use
different identities and evidence. Treating them as one permission model would
let producer credentials manage sources or force browser-only CSRF and step-up
controls onto service accounts.

## Decision

The complete inbound subsystem is disabled by default. `RuntimeAssembler`
creates no inbound repository, service, component, worker, route, source,
credential grant, or network permission unless `inbound_events_enabled=True`
and the required `SecretsManager`, `PolicyEngine`, reviewed normalizers, and
Control Plane listener are supplied.

Supplying dormant inbound security options while the feature is disabled is
rejected rather than ignored.

When enabled, one Runtime-owned bundle composes:

- a coordinated source, accepted-event, and replay repository trio;
- schema registry and reviewed normalizers;
- authentication and service-account late-binding boundary;
- replay and idempotency service;
- admission policy and limiter;
- gateway and dynamic exact-route ingress;
- publisher and publisher worker;
- recovery service and recovery worker;
- human and optional machine administration manager.

With a default State Store, all three repositories are State Store-backed.
Without one, Phoenix creates one coordinated bounded in-memory trio. Custom
composition must supply all three repositories together.

Startup order is explicit:

1. bind repositories and register reviewed schemas;
2. validate durable sources;
3. synchronize active exact routes;
4. recover interrupted publication;
5. start the publisher worker;
6. start the recovery worker;
7. start the shared Control Plane listener last.

Runtime reverse shutdown stops the listener and ingress first, then recovery and
publisher workers, then the manager, admission state, recovery service, and
repositories. Partial startup failure closes already created inbound resources.

Human administration is available only in durable operator mode. It uses
authenticated operator sessions, exact inbound permissions, same-origin CSRF,
no-store responses, and action-bound recent step-up for reviewed sensitive
mutations.

Machine administration is a separate optional flag. It reuses RFC-0023 token
authentication, nonce and timestamp replay protection, central policy, exact
`inbound_event.*` action scopes, gateway resource `inbound-machine`, and one
concrete source, event, or receipt resource. Aggregate source inventory, source
creation, aggregate event inventory, and health routes are intentionally absent.

Source submission authority is independent from administration. A source may
use `inbound_event.submit` without receiving any management action, and enabling
service accounts does not automatically grant either source submission or
machine administration.

## Consequences

Positive consequences:

- upgrading an unchanged v0.24.0 assembly adds no inbound behavior;
- repositories, workers, routes, and network authority have one clear owner;
- startup recovery completes before the listener can accept new work;
- shutdown removes producers before shared state closes;
- human, machine, and source credentials remain in separate security models;
- State Store and in-memory composition follow the same coherent repository
  contract;
- optional surfaces can be enabled, tested, and rolled back independently.

Costs and constraints:

- configuration is explicit and more verbose;
- inbound events require the Control Plane listener even when human
  administration is not enabled;
- human administration requires durable operator mode;
- machine administration requires service accounts, policy, replay, and secure
  network configuration;
- source schemas must be available before durable source startup;
- custom repositories must share lifecycle and atomicity expectations;
- disabling the Runtime removes routes but does not delete durable state.

## Alternatives considered

### Enable inbound automatically when normalizers are supplied

Rejected because a configuration refactor could accidentally create external
network authority.

### Always register empty inbound services and repositories

Rejected because compatibility includes absence from the service map, component
graph, route table, persistence, and listener behavior.

### Let each worker and repository own its lifecycle independently

Rejected because startup rollback, route visibility, shutdown order, and shared
repository closure would become nondeterministic.

### Use producer credentials for source administration

Rejected because event submission is not permission to change authentication,
limits, schemas, routes, or dead-letter state.

### Use browser management routes for service accounts

Rejected because cookies, CSRF, step-up, token replay, scopes, resources, and
transport identity have different threat models.

### Enable machine routes whenever service accounts are enabled

Rejected because machine administration is a separate grant of authority and
must remain absent by default.

## Supersession criteria

A future ADR may change Runtime composition only if disabled deployments remain
behaviorally absent, repository and worker ownership stays deterministic,
startup and reverse shutdown remain fail-closed, durable state survives
feature rollback, and source submission, human administration, and machine
administration retain independent authorization models.
