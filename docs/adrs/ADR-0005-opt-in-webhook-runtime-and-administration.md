# ADR-0005: Opt-in webhook Runtime and administration

- **Status:** Accepted
- **Date:** 2026-07-24
- **Related RFC:** [RFC-0024](../rfcs/RFC-0024-durable-signed-webhooks-and-event-subscriptions.md)

## Context

Webhooks add durable state, background workers, secret access, outbound network
authority, and administrative routes. Existing Phoenix OS v0.23.0 deployments
must not gain any of those behaviors merely by upgrading.

Human browser administration and non-human API administration also have
different authentication evidence and replay risks. Combining them into one
route model would either weaken machine security or force browser-only controls
onto service accounts.

## Decision

The complete webhook subsystem is disabled by default. `RuntimeAssembler`
creates no webhook repository, service, component, Event Bus subscription,
worker, route, or outbound authority unless `webhooks_enabled=True` and the
required serializers, egress policies, and `SecretsManager` are supplied.

When enabled, one Runtime-owned bundle composes the repositories, registry,
scheduler, Event Bus adapter, signer, transport, dispatcher worker, recovery
service, and manager.

Startup order is explicit:

1. register reviewed serializers;
2. recover interrupted deliveries;
3. start the dispatcher worker;
4. subscribe the adapter to the Event Bus.

Runtime reverse shutdown therefore stops Event Bus selection first, waits for
the dispatcher worker, and closes shared services and repositories last.
Partial startup failure closes already created webhook resources.

Human administration is exposed only through durable operator mode and reuses
the browser Control Plane security boundary: authenticated operator sessions,
exact webhook permissions, same-origin CSRF, no-store responses, and recent
step-up proof for sensitive changes.

Machine administration is a separate optional flag. It reuses the service
account boundary: fixed machine routes, replay-protected API tokens, exact
`webhook.*` action scopes, the concrete `webhooks` resource grant, central
default-deny policy, and secure network admission. Browser cookies, CSRF
headers, and human step-up proofs are rejected on machine routes.

Enabling outbound webhook delivery does not implicitly enable either Control
Plane mode or machine administration.

## Consequences

Positive consequences:

- upgrading an unchanged v0.23.0 assembly adds no webhook behavior;
- lifecycle ownership and shutdown ordering are deterministic;
- shared repositories are not closed while producers still use them;
- browser and machine credentials remain in their reviewed security models;
- outbound delivery authority is independent from inbound administrative
  authority;
- optional surfaces can be tested and disabled separately.

Costs and constraints:

- configuration is explicit and more verbose;
- machine administration requires service accounts, policy, replay protection,
  and secure network configuration;
- human administration requires durable operator mode;
- custom repository ownership must follow the Runtime contract;
- supplying dormant webhook options while disabled is rejected rather than
  ignored.

## Alternatives considered

### Enable webhooks automatically when serializers are supplied

Rejected because a configuration refactor could accidentally create outbound
network authority.

### Always register empty webhook services

Rejected because v0.23.0 compatibility includes the service and component
surface, not only absence of deliveries.

### Let each component manage its own background task independently

Rejected because startup rollback, shutdown order, and repository ownership
would become nondeterministic.

### Use the browser management adapter for service accounts

Rejected because cookies, CSRF, step-up, token replay, and resource grants have
different evidence and threat models.

### Enable machine routes whenever service accounts and webhooks are enabled

Rejected because outbound delivery and inbound machine administration are
separate grants of authority.

### Close shared repositories from each dependent service

Rejected because double ownership and premature closure would race with
producers and other management paths.

## Supersession criteria

A future ADR may change composition boundaries only if disabled deployments
remain behaviorally absent, lifecycle ordering remains deterministic, resources
have one clear owner, and human and machine administration retain independent
fail-closed security models.
