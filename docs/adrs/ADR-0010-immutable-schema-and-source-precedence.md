# ADR-0010 — Immutable schema and ordered source precedence

- **Status:** Accepted
- **Date:** 2026-07-17

Phoenix configuration is resolved once from an immutable schema. Sources are evaluated in explicit
registration order and later values override earlier values. Every resolved value records its
winning origin. Unknown keys are rejected by default. Running configuration is never mutated in
place; a changed configuration requires constructing a new composition root.
