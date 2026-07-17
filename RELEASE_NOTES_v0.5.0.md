# Phoenix OS v0.5.0 — Configuration System

Phoenix OS v0.5.0 implements RFC-0005 and introduces deterministic typed configuration and secure
singleton dependency composition.

## Highlights

- Immutable schemas, fields, origins, and resolved configuration.
- Strict decoders and validators for common deployment values.
- Ordered mapping, JSON, and environment sources.
- Explicit source provenance and strict unknown-key handling.
- Redacted `SecretValue` with explicit reveal operations.
- Deterministic asynchronous dependency composition.
- Missing-dependency and cycle detection before Runtime startup.
- Automatic Runtime lifecycle adaptation for declared services.
- `RuntimeAssembler` integration with Kernel, Event Bus, Capability Registry, and configuration.
- RFC-0005, ADR-0010, ADR-0011, migration guidance, and executable example.

## Compatibility

Existing v0.4.0 construction APIs remain available. Applications may continue creating
`PhoenixRuntime` directly or adopt `RuntimeAssembler` incrementally.

## Validation

- Ruff: passed
- Ruff Format: passed
- mypy strict: passed
- pytest: 161 tests passed
- Examples: passed
- Wheel build and isolated installation: passed
