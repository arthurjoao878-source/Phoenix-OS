# ADR-0057: Phoenix-owned logical paths and fail-closed host confinement

- **Status:** Accepted
- **Date:** 2026-08-14
- **Related:** RFC-0031

## Context

Agent-visible filenames are useful for organization, but native host paths are an
operating-system authority surface. Accepting model-selected absolute paths,
traversal, drive or UNC syntax, device forms, aliases, links, or special filesystem
objects could turn a workspace feature into arbitrary host-filesystem access.

Portable logical paths also need deterministic collision rules. Case, separator, and
Unicode aliases that resolve differently across platforms cannot be allowed to map
multiple logical artifacts onto one unsafe or ambiguous backing location.

## Decision

Artifact logical paths are canonical Phoenix-owned portable relative identifiers, not
native host filesystem paths.

Phoenix validates path length, segment count, segment length, traversal, dot/empty
segments, absolute forms, drive/UNC/device forms, NUL and reserved escape forms before
the path can participate in workspace state. Canonicalization provides deterministic
case, separator, Unicode, and alias collision handling.

Logical paths do not select backing locations. Backing adapters receive opaque
Phoenix-derived backing keys. The local reference adapter is confined to one explicit
absolute Phoenix-owned root and fails closed if any parent or target object can escape
that root or violates the reviewed object type.

Symlinks, hardlinks, reparse points, FIFOs, sockets, device nodes, and other special
filesystem objects are not valid artifact payload entries. A model cannot mount or
select a home directory, Downloads, Desktop, project tree, arbitrary native path, or
other host location merely by proposing artifact text.

## Consequences

- The same logical artifact namespace has deterministic semantics across supported
  host platforms.
- A logical path can be displayed or organized without becoming a host path
  capability.
- Local backing may use implementation-specific opaque locations while the public
  workspace contract remains provider-neutral.
- Host confinement violations, link substitution, ambiguous aliases, and unexpected
  filesystem object types fail closed instead of degrading into best-effort access.
- Applications that require broad host-filesystem access need a separate reviewed
  capability outside RFC-0031.

## Alternatives considered

- **Expose native paths as artifact identifiers.** Rejected because identifier choice
  would become ambient host-filesystem authority.
- **Join a user/model path under a configured root and normalize afterward.** Rejected
  because traversal, aliases, links, and platform-specific path semantics can escape
  or ambiguously reinterpret the root.
- **Permit links when their current target appears safe.** Rejected because mutable
  indirection introduces substitution and race surfaces.
- **Use logical paths directly as backing keys.** Rejected because public organization
  names should not control physical storage layout.

## Supersession criteria

A replacement must preserve canonical bounded Phoenix-owned logical identifiers,
deterministic collision handling, separation from native backing locations, one
reviewed confinement root for the local adapter, and fail-closed rejection of escape,
link, and special-object paths.
