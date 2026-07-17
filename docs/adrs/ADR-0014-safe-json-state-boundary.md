# ADR-0014 — Safe JSON state boundary

- **Status:** Accepted
- **Date:** 2026-07-17

Phoenix state values cross the core persistence boundary through an explicit `StateCodec`. The
default codec uses deterministic UTF-8 JSON and rejects executable or ambiguous object formats,
non-string mapping keys, non-finite numbers, byte strings, arbitrary classes, and wrapped
`SecretValue` instances. Reads decode a fresh value from stored bytes so callers cannot mutate the
stored copy through object aliasing. Pickle and automatic Python object reconstruction are forbidden
inside the core because they couple data to code and can execute attacker-controlled payloads.
