"""Retention and tombstone capability boundary for durable agent storage."""

from __future__ import annotations

from collections.abc import Awaitable
from datetime import datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.durable_contracts import (
    DurableAgentRunId,
    DurableLease,
    DurableRunStore,
    DurableRunTombstone,
    RetentionPolicy,
)


@runtime_checkable
class DurableRetentionStore(DurableRunStore, Protocol):
    """Bounded terminal retention, cleanup, and anti-resurrection storage."""

    def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> Awaitable[tuple[DurableAgentRunId, ...]]: ...

    def get_tombstone(
        self,
        run_id: DurableAgentRunId,
    ) -> Awaitable[DurableRunTombstone | None]: ...

    def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> Awaitable[bool]: ...

    def tombstone_terminal_run(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> Awaitable[DurableRunTombstone]: ...

    def purge_expired_tombstone(
        self,
        run_id: DurableAgentRunId,
        *,
        lease: DurableLease,
        now: datetime,
    ) -> Awaitable[bool]: ...
