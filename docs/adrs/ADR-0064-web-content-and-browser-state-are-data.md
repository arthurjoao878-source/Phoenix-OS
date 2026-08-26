# ADR-0064: Web content and browser state are data, never authority

- **Status:** Accepted
- **Date:** 2026-08-26
- **Related:** RFC-0035

## Context

Browser automation crosses a hostile-content boundary. Page text, labels, links, form
metadata, redirect locations, cookies, and browser state can all be influenced by a
remote origin. Treating any of that material as permission would let untrusted web data
amplify itself into Phoenix authority.

Model output and tool results are already treated as data by the agent architecture.
Browser automation needs the same rule at every page and state boundary.

## Decision

Phoenix treats all web content and browser state as untrusted data.

Page snapshots, element labels, link/form information, redirect locations, cookies, and
other browser observations may inform a later request, but they never grant a browser,
network, tool, host, workspace, memory, model, or delegation action.

Every protected browser operation must cross its own fresh canonical browser authority
boundary. Page disclosure separately requires fresh `browser.page.read` authority.
Remote content cannot manufacture a follow-on operation, origin grant, tool approval,
or reusable capability.

Routine browser observability and health are content-free and are also non-authoritative.
A successful observation, health snapshot, prior ALLOW result, session ID, page ID, or
element ID cannot be replayed as permission.

## Consequences

- Browser content can guide work but cannot authorize it.
- Content-derived destinations still require exact current origin and destination
  admission.
- A page read never implies click, fill, navigate, tool, or network authority.
- Cookies and browser state remain internal bounded state rather than ambient capability.
- Telemetry and administration can be designed without exporting page content.

## Alternatives considered

- **Treat same-origin page data as trusted authority.** Rejected because a trusted
  transport does not make remote content a Phoenix principal.
- **Allow page links/forms to create implicit navigation permission.** Rejected because
  remote content could widen its own destination scope.
- **Reuse prior ALLOW or health state as a capability.** Rejected because revocable
  authority must be current at the protected boundary.

## Supersession criteria

A replacement must preserve the rule that web content and browser state are data only,
require fresh independent authority for protected browser actions and disclosure, and
prevent observations, cookies, remote content, or historical decisions from becoming
bearer authority.
