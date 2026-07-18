# ADR-0029 — Confirmed prefix-only audit retention

- Status: Accepted
- Date: 2026-07-18

## Context

Automatic retention can erase security evidence, create gaps, or apply a stale policy after archive
contents change. A simple age-based delete loop is too easy to invoke accidentally.

## Decision

Phoenix separates planning from deletion. A retention plan is immutable, reviewable, canonically
hashed, and must be confirmed by supplying its exact digest. Before deletion the manager recomputes
the plan digest and verifies the current archive chain. Only the oldest contiguous eligible prefix may
be selected; protected, too-new, or required newest archives stop candidate selection.

## Consequences

Deletion requires an explicit second step and cannot create intentional middle gaps through the core
policy. Retained suffixes preserve their external digest anchors. Filesystem administrators can still
remove files outside Phoenix, so deployment permissions, backups, legal hold, and object lock remain
external responsibilities.
