# ADR-0065: Server-owned browser profiles and navigation targets

- **Status:** Accepted
- **Date:** 2026-08-26
- **Related:** RFC-0035

## Context

Generic browser APIs commonly accept URLs, proxy settings, executable flags, selectors,
and other caller-controlled routing material. In an agent runtime those fields would
turn untrusted model/tool data into destination or host authority and create direct SSRF
and escape paths.

Phoenix needs browser navigation that remains reviewable and bounded before any remote
effect occurs.

## Decision

Browser profiles and initial navigation targets are immutable server-owned configuration.

A profile has a stable Phoenix-owned ID and positive generation. It fixes the adapter,
finite exact allowed origins, initial target IDs, network policy, and bounded limits.
Callers select only reviewed IDs; they cannot supply arbitrary URLs, schemes, hosts,
ports, proxies, executable paths, browser flags, cookies, credentials, or host paths.

Initial navigation uses a server-owned target. Redirects and click-derived top-level
requests may derive a next exact request only under the frozen RFC rules, and every
destination must remain inside the current profile origin set and pass current DNS/IP
admission.

Hosted destinations require verified HTTPS. Plain HTTP exists only for explicitly
configured loopback mode. Ambient proxy configuration is ignored.

Profile changes require a new generation. Existing sessions do not silently inherit a
wider profile.

## Consequences

- Destination scope is reviewable in configuration rather than chosen by the model.
- Arbitrary URL fetching is not a browser primitive.
- Redirects cannot widen origin authority.
- DNS rebinding and mixed answer sets are handled by fail-closed destination admission.
- A profile generation is part of freshness and intent binding.

## Alternatives considered

- **Accept arbitrary URLs with a runtime allow/deny callback.** Rejected because URL
  parsing and caller-controlled destination selection would become an ambient authority
  surface.
- **Allow wildcard origins.** Rejected because wildcard scope is not a finite exact
  authority boundary.
- **Inherit environment proxies.** Rejected because ambient process configuration would
  silently alter the reviewed destination path.

## Supersession criteria

A replacement must keep destination and adapter selection server-owned, preserve finite
exact origin scope and generation freshness, prevent arbitrary URL/proxy/executable
selection, and require current destination admission for every top-level remote request.
