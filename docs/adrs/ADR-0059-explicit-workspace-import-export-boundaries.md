# ADR-0059: Explicit independently authorized workspace transfer boundaries

- **Status:** Accepted
- **Date:** 2026-08-14
- **Related:** RFC-0031

## Context

Moving bytes between a workspace and an external system crosses a different trust
boundary from reading or writing an existing artifact. If an import reference could
select arbitrary host or network authority, or artifact content could choose its own
export destination, workspace storage would become a confused-deputy path to external
effects.

Provider SDK objects, sockets, file handles, credentials, response bodies, and
provider-specific exceptions also cannot become stable Phoenix public contracts.

## Decision

Import and export are explicit server-mediated transfers with independent exact
authorization.

Import requires fresh `workspace.import` authorization for the exact workspace scope
and `ArtifactId`; export requires fresh `workspace.export` authorization for the
exact artifact. Neither action is implied by `workspace.read`, `workspace.write`, the
other transfer action, agent/model/tool/delegation/memory authority, or artifact
content.

A source or destination transfer reference is bounded untrusted data interpreted only
by an explicitly installed reviewed `WorkspaceTransferAdapter`. Import cannot widen
the server-owned workspace scope or choose a native destination path. Export
destinations are explicit request data and are never reconstructed from stored
artifact instructions. The Phoenix core performs no implicit remote network fetch as
a workspace read.

Transfer adapters expose provider-neutral bounded import/export results and receipts.
Provider SDK objects, open file handles, sockets, credentials, raw provider bodies,
and raw provider exceptions remain behind the adapter boundary.

Runtime owns optional transfer workers, finite queues, operation deadlines,
cancellation, settlement bounds, and reverse-order shutdown. Transfer availability
does not change the authoritative workspace store: imported bytes still pass normal
write admission, and exported bytes still come from a freshly authorized
authoritative read path.

## Consequences

- Workspace read/write permission cannot silently become external transfer authority.
- External providers can be integrated without leaking provider-specific objects into
  Phoenix contracts.
- A configured transfer adapter receives only the bounded references and bytes needed
  by its reviewed interface; it does not inherit generic network or filesystem
  authority from RFC-0031.
- Queue exhaustion, timeout, cancellation, or adapter failure is bounded and fails
  through sanitized Phoenix errors.
- Deployments can omit transfer adapters entirely.

## Alternatives considered

- **Treat imports as ordinary writes and exports as ordinary reads.** Rejected because
  crossing an external boundary needs independent authority.
- **Allow artifact content to name an export destination.** Rejected because untrusted
  data would control an external side effect.
- **Fetch URLs automatically during workspace reads.** Rejected because read authority
  must not imply network authority.
- **Expose cloud SDK objects in public contracts.** Rejected because provider code
  would define core semantics and leak privileged handles across the boundary.

## Supersession criteria

A replacement must preserve explicit server-mediated transfers, independent
`workspace.import` and `workspace.export` authorization, provider-neutral bounded
adapter contracts, no implicit remote fetch, no content-selected external authority,
and Runtime-owned bounded transfer lifecycle.
