# ADR-0035 — Packaged dashboard assets and bounded long polling

- Status: Accepted
- Date: 2026-07-18

## Context

The first dashboard should remain installable with the Phoenix package, avoid a JavaScript build
pipeline and third-party CDN supply chain, and receive timely updates without introducing unbounded
per-client queues or a WebSocket implementation into the core.

## Decision

Phoenix OS ships a fixed manifest of HTML, CSS, JavaScript, and SVG resources inside the Python
package. The HTTP server maps exact `/dashboard/` paths to package resources and never resolves a
client path against the filesystem. Assets use no external scripts, fonts, styles, or images.

The page stores the administrator token only in tab-scoped `sessionStorage`, sends it in an
Authorization header, constructs dynamic content through DOM text nodes, and operates under a strict
Content Security Policy.

Live updates use authenticated bounded long polling over the existing Event Bus observer. One shared
ring buffer retains only event headers. Cursor gaps and dropped counts inform slow clients, waiter
capacity produces HTTP 429 backpressure, and Runtime shutdown wakes pending readers.

`RuntimeAssembler` owns the event stream before job and workflow workers and owns the HTTP server as
the final component. Reverse shutdown therefore stops new dashboard requests first and unsubscribes
the event stream after workers stop.

## Consequences

The dashboard remains dependency-free and deterministic, but advanced charts, offline caching,
WebSockets, remote hosting, and write controls are outside this release. Browser code must continue
to avoid inline execution, external dependencies, `innerHTML`, and unbounded client retention.
