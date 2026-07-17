# Changelog

## [0.4.0] - 2026-07-17

### Added
- Accepted RFC-0004 and ADR-0008/0009.
- One-shot Phoenix Runtime composition root and immutable named services.
- Deterministic component startup, reverse shutdown, and startup rollback.
- Graceful request rejection and draining during shutdown.
- Retryable aggregate shutdown failures with active-component snapshots.
- Lifecycle deadlines, cancellation propagation, and async context management.
- Correlated Runtime lifecycle events and final core-service ownership.
- Nova 3.x lifecycle-component migration guidance and Runtime example.

## [0.3.0] - 2026-07-17

### Added
- Accepted RFC-0003 and ADR-0006/0007.
- Immutable capability descriptors, contexts, invocations, results, and registrations.
- Deterministic Capability Registry with discovery and safe unregistration.
- Default required-permissions and descriptor-confirmation policies.
- Synchronous and asynchronous provider support with deadlines and cancellation.
- Safe policy/provider error translation and registry lifecycle management.
- Correlated capability lifecycle events through the Event Bus.
- `CapabilityHandler` adapter for Kernel integration without Kernel coupling.
- Nova 3.x provider migration guidance and capability example.

## [0.2.0] - 2026-07-17

### Added
- Accepted RFC-0002 and ADR-0004/0005.
- Deterministic asynchronous in-process Event Bus.
- Immutable event, subscription, dispatch, and failure contracts.
- Exact and wildcard subscriptions, priorities, one-shot handlers, safe unsubscription.
- Failure collection and strict aggregate-error policy.
- Kernel lifecycle integration through the Event Bus.
- Event Bus and Kernel examples and expanded test suite.

## [0.1.0] - 2026-07-17

### Added
- Repository bootstrap, MIT license, governance, Python 3.12 tooling and CI.
- Accepted RFC-0001 and ADR-0001 through ADR-0003.
- First asynchronous headless Phoenix Kernel.
