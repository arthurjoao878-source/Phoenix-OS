# Phoenix OS v0.17.0 — Dashboard Control Plane and Read-Only API

Phoenix OS 0.17.0 implements RFC-0017 and introduces the first visual administrative surface for
observing Runtime, durable jobs, workflows, capabilities, plugins, audit counters, and recent events.

## Highlights

- versioned, allowlisted `ControlPlaneSnapshot` contracts;
- authenticated loopback-only HTTP/1.1 transport with no external web framework;
- SHA-256 administrator-token digests and constant-time bearer comparison;
- paginated read models for jobs, workflows, capabilities, and plugins;
- bounded audit summaries without record bodies or chain digests;
- cursor-based Event Bus long polling with fixed retention and backpressure;
- packaged HTML, CSS, JavaScript, and SVG dashboard assets;
- strict Content Security Policy and same-origin browser protections;
- browser-tab-only token retention through `sessionStorage`;
- RuntimeAssembler ownership of the event stream and HTTP server;
- public control-plane API, executable dashboard example, RFC, ADRs, migration guidance, and tests.

## Dashboard

Run:

```powershell
python .\examples\control_plane_dashboard.py
```

Open the printed loopback address and enter the generated administrator token. Static assets contain
no operational data and can load without authentication. Every `/v1/control-plane/*` request still
requires a principal with `control-plane.read`.

## Safety model

The dashboard is an observation surface, not a remote execution console. It exposes no POST, PUT,
PATCH, or DELETE operation. Explicit serializers omit job arguments and outputs, capability contexts,
workflow definitions and step data, plugin metadata, audit record bodies and digests, Event Bus
payloads and metadata, credentials, tokens, and secrets.

The HTTP server accepts only literal IPv4 or IPv6 loopback addresses. Requests, responses,
connections, long-poll waits, retained events, and page sizes are bounded. Static asset paths are a
fixed package manifest rather than client-controlled filesystem paths.

## Validation

- Ruff checks passed;
- Ruff formatting passed;
- mypy strict passed;
- 688 tests passed;
- wheel and source distribution include the packaged dashboard assets;
- package and plugin compatibility version updated to 0.17.0.

## Current boundaries

This release does not provide remote administration, TLS termination, multi-user identity, role
management, write operations, WebSockets, arbitrary file serving, external asset CDNs, charting
libraries, hosted deployment, or a visual workflow editor. Production remote access must remain
behind a reviewed reverse proxy, transport-security boundary, and organization-specific identity
adapter rather than widening the built-in loopback listener.
