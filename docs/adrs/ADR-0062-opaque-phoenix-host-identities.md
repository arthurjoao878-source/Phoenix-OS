# ADR-0062: Opaque Phoenix host identities and adapter-private native identities

- **Status:** Accepted
- **Date:** 2026-08-18
- **Related:** RFC-0032

## Context

Native process IDs and window handles are convenient implementation identifiers, but
they are platform-specific, reusable, and insufficient to establish current Phoenix
authority. Exposing PID/HWND values or other native objects through public contracts
would couple callers to Windows and invite stale-identity substitution.

Phoenix needs public identities that remain portable while allowing the Windows
adapter to correlate a reviewed process or window with native state safely.

## Decision

Public host contracts use opaque Phoenix-owned process and window identities, never
native PID/HWND authority.

`HostId`, `HostApplicationId`, `HostProcessId`, `HostWindowId`, and `HostEpoch` are
Phoenix-owned identities. Public process/window resources and results use those
identities rather than Win32 handles, PID contracts, COM objects, process objects,
clipboard handles, native structures, SDK types, or raw operating-system error
objects.

Native PID/HWND values remain adapter-private implementation details. The adapter may
maintain private correlations required to perform Windows operations, but those values
do not become public policy resource names and cannot be supplied by a model as
authority.

Process and window identities are bound to one configured host and finite host epoch.
Sensitive operations revalidate the current native target and expected ownership or
identity relationship before effect admission. Reused, vanished, substituted, stale,
or otherwise unverifiable native identities fail closed rather than being treated as
the previously observed Phoenix object.

## Consequences

- Public host contracts remain operating-system-neutral even though v0.32.0 implements
  Windows first.
- A raw PID or HWND cannot be replayed through the public API as a capability.
- Adapter restart or identity invalidation can make old process/window references stale
  without exposing native replacement identifiers.
- Policy names stable Phoenix resources instead of platform-specific native handles.
- Additional platform adapters can preserve the public identity model while using
  different native correlation mechanisms internally.

## Alternatives considered

- **Expose PID/HWND directly.** Rejected because they are Windows-specific, reusable,
  and do not establish current identity or authority.
- **Treat native identifiers as policy resources.** Rejected because native reuse and
  model-controlled numbers would create substitution and stale-reference hazards.
- **Expose native process or window objects.** Rejected because provider objects and
  handles leak implementation authority across the adapter boundary.
- **Keep opaque IDs but skip native revalidation.** Rejected because opacity alone does
  not prevent the native target from changing after enumeration.

## Supersession criteria

A replacement must preserve operating-system-neutral public contracts, opaque
Phoenix-owned host/process/window identities, adapter-private native identifiers,
host/epoch binding, no raw native identifier as policy or model authority, and
fail-closed revalidation of sensitive targets.
