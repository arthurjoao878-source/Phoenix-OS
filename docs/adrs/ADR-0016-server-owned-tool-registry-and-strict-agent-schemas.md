# ADR-0016: Server-owned tool registry and strict agent schemas

- **Status:** Accepted
- **Date:** 2026-07-29
- **Related:** RFC-0027

## Context

Agent models can emit text that resembles a function call, but model output is
untrusted. Allowing a proposal to choose Python callbacks, module paths,
endpoints, credentials, policy resources, or unrestricted argument shapes would
turn prompt injection into execution authority.

Phoenix OS therefore needs a closed-world boundary that determines which tools
exist for one configured agent and how every input and output is represented.

## Decision

Phoenix OS uses a server-owned `ToolRegistry` as the only tool allowlisting
boundary. Every tool is installed through trusted composition with a stable
`ToolId`, immutable `ToolDescriptor`, exact adapter identity, server-owned
resource resolver, finite limits, effect classification, and strict input and
output schemas.

Models may select only a registered identifier exposed for the current run. They
cannot supply an executable callback, import path, endpoint, credential,
resolver, action, policy resource, or schema.

Tool proposals are decoded through Phoenix-owned canonical codecs. Duplicate JSON keys, unknown object properties, malformed Unicode, non-finite numbers,
unsupported schema constructs, oversized structures, and values outside the
registered bounds fail closed. Inputs are normalized before authorization and
outputs are validated again before they re-enter the agent loop.

The deterministic fake model adapter and fake tools are the first validation
path because they exercise the same contracts without network, provider SDK, or
external side effects.

## Consequences

- Tool availability is explicit, reviewable, and deterministic.
- Dynamic model-selected code loading is impossible through the agent contract.
- Schema evolution requires a reviewed descriptor or codec change.
- Installed adapters remain trusted code and are not sandboxed from their own
  process authority; composition must still supply least-authority dependencies.
- A tool that needs broad shell, filesystem, HTTP, or operating-system access is
  outside RFC-0027 and must not be registered as a shortcut around policy.

## Alternatives considered

- **Reflect Python functions automatically.** Rejected because signatures are
  not a complete security schema and reflection exposes implementation details.
- **Let the model emit arbitrary JSON-RPC methods.** Rejected because method and
  resource selection would be model-controlled.
- **Trust provider-native tool schemas.** Rejected because provider formats do
  not replace Phoenix validation, canonicalization, or authorization.

## Supersession criteria

A later ADR may replace this decision only if it preserves server-owned
allowlisting, strict fail-closed validation, deterministic resource resolution,
and the rule that model output never chooses executable code or authority.
