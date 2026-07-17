# ADR-0011 — Explicit secret access and dependency declarations

- **Status:** Accepted
- **Date:** 2026-07-17

Secret values use a redacted wrapper and cannot be read through the ordinary configuration API.
Reveal operations must be explicit. Services declare dependencies by stable names and are composed
without reflection or global lookup. Cycles and missing dependencies fail before Runtime startup.
Lifecycle participation is explicit on each service definition.
