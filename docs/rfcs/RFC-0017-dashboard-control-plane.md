# RFC-0017 — Dashboard Control Plane and Read-Only API

- Status: Accepted
- Target release: Phoenix OS v0.17.0

## Summary

Phoenix OS needs a bounded administrative observation surface before a web dashboard can be
introduced safely. This RFC defines a local control plane that reads immutable snapshots from the
Runtime, durable job scheduler, and workflow repository without exposing executable capabilities,
provider objects, job arguments, workflow definitions, outputs, secrets, or audit payloads.

## Slice 1 — contracts and snapshot query API

The first slice introduces:

- a versioned `ControlPlaneSnapshot` contract;
- coarse `healthy`, `degraded`, and `stopped` states;
- aggregate workflow lifecycle counts;
- optional job and workflow worker diagnostics;
- a protocol-based read boundary compatible with existing Runtime and repository objects;
- deterministic JSON-safe serialization containing only approved fields;
- tests proving that workflow arguments, outputs, metadata, and capability names are omitted.

No socket is opened in this slice. The control plane is a Python read API only.

## Slice 2 — authenticated loopback HTTP transport

The second slice adds a dependency-free HTTP/1.1 transport with a deliberately small surface:

- literal IPv4 or IPv6 loopback binding only;
- a public liveness probe at `GET /health/live`;
- authenticated health at `GET /v1/control-plane/health`;
- authenticated safe snapshots at `GET /v1/control-plane/snapshot`;
- SHA-256 token digests and constant-time bearer-token comparison;
- a principal requiring the `control-plane.read` permission;
- bounded request headers, response bodies, connection concurrency, and request time;
- one request per connection, `Cache-Control: no-store`, and no body support;
- generic client errors that never expose exception messages or credentials.

The transport is lifecycle-compatible but is not yet assembled into the Runtime automatically.


## Slice 3 — paginated administrative read models

The third slice adds authenticated detail queries for the first dashboard screens:

- bounded offset pagination with a default of 50 and a hard limit of 200 items;
- safe job views containing identity, capability name, lifecycle state, retry counters, and dates;
- workflow progress views containing identity, revision, lifecycle state, and per-step status;
- capability catalog views containing static descriptor and policy requirement fields;
- plugin catalog views containing identity, lifecycle state, dependency IDs, permissions, and export counts;
- an audit summary containing only counters and the current head sequence;
- authenticated HTTP routes under `/v1/control-plane` for all five read models;
- strict pagination parsing and rejection of duplicate, unknown, negative, blank, or oversized values;
- deterministic ordering and JSON serialization with explicit allowlists.

Job arguments, capability contexts, workflow definitions, step arguments, outputs, metadata, exception
messages, plugin metadata, audit record bodies, and audit chain digests remain excluded.

## Slice 4 — bounded Event Bus feed and backpressure

The fourth slice adds a safe cursor-based event feed for live dashboard updates:

- a lifecycle-owned wildcard Event Bus observer;
- monotonically increasing local cursors and deterministic ordering;
- a bounded shared ring buffer with configurable retention;
- event headers containing only ID, name, source, timestamp, correlation, and causation IDs;
- explicit omission of every Event Bus payload and metadata field;
- authenticated `GET /v1/control-plane/events` reads;
- bounded batches, long-poll wait time, connection count, and waiter capacity;
- gap and dropped-count signals when a slow consumer falls behind retention;
- HTTP 429 with `Retry-After` when waiter capacity is exhausted;
- lifecycle shutdown that unsubscribes and wakes outstanding readers.

The feed intentionally uses bounded long polling rather than WebSockets. It preserves the minimal
dependency-free HTTP transport while still allowing the dashboard to refresh immediately after new
events arrive. A slow or disconnected client owns no unbounded queue.

## Health derivation

A running Runtime with no worker infrastructure failures, dead-letter jobs, or failed workflows is
reported as healthy. Transitional or failed Runtime states, dead-letter jobs, failed workflows, and
worker loop failures are reported as degraded. A Runtime that has not started or has stopped is
reported as stopped.

Health is intentionally coarse. It is an operator signal, not a replacement for individual job or
workflow lifecycle states.

## Security boundaries

The serializer uses an explicit allowlist. It does not recursively serialize Runtime services,
capability registries, workflow definitions, arguments, outputs, metadata, exception objects, or
provider configuration.

The HTTP transport authenticates and authorizes an administrative principal before invoking the
reader. It accepts only literal loopback addresses, uses bounded request and response sizes, applies
connection and time limits, and preserves the same allowlist rather than serializing internal
objects directly. The bearer token is hashed at construction time and is never exposed through
transport snapshots or responses.

## Slice 5 — packaged dashboard and Runtime lifecycle integration

The fifth slice completes the first dashboard release with:

- a fixed package manifest containing HTML, CSS, JavaScript, and SVG assets;
- public static routes at `/dashboard/` with no operational data;
- authenticated browser reads for every `/v1/control-plane/*` API;
- tab-scoped bearer retention through `sessionStorage`;
- a strict Content Security Policy and same-origin browser headers;
- DOM text-node rendering without `innerHTML`, inline scripts, external assets, or CDN dependencies;
- RuntimeAssembler creation and ownership of the reader, Event Bus stream, and HTTP server;
- startup before job/workflow activity observation and reverse shutdown that closes HTTP first;
- empty safe sources when jobs or workflows are not configured;
- an executable local dashboard example and package-data build validation.

## Acceptance

RFC-0017 is accepted for Phoenix OS 0.17.0. The accepted scope is a local, read-only, bounded
administrative observation plane. Remote exposure, write operations, multi-user administration,
WebSockets, hosted deployment, and visual workflow editing remain outside this RFC.
