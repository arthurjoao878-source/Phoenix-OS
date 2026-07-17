# RFC-0001 — Phoenix Kernel

- Status: **Accepted**
- Accepted: 2026-07-17

## Decision

Phoenix Kernel is an asynchronous, headless request orchestrator exposed through
`await kernel.handle(request)`. It separates immutable contracts, routing,
authorization, confirmation, handlers, responses, lifecycle events, deadlines,
cancellation, and safe error translation.

## Boundaries

The Kernel contains no AI, memory, database, tools, interface, operating-system code,
or Nova-specific logic. Nova 3.x migrates only through adapters.

## Lifecycle

1. Receive and validate request.
2. Resolve route.
3. Authorize.
4. Require explicit confirmation when applicable.
5. Invoke handler under the caller's cancellation/deadline scope.
6. Normalize response.
7. Publish lifecycle facts.
8. Translate trusted errors without leaking internals.
