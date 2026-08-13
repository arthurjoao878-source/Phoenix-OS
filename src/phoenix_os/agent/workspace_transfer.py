"""Provider-neutral transfer boundary for secure Phoenix workspaces."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from phoenix_os.agent.workspace_contracts import (
    WorkspaceExportPayload,
    WorkspaceExportResult,
    WorkspaceImportResult,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
)


@runtime_checkable
class WorkspaceTransferAdapter(Protocol):
    """Server-owned bounded import/export adapter.

    References select data only inside this already configured adapter; they never
    select an adapter, credential, network permission, host root, or policy.

    ``max_bytes`` is a positive globally bounded Phoenix-owned configured limit,
    never request/provider authority. An import adapter should stop before
    materializing more bytes, while the service still revalidates its result.

    Cancellation may propagate before an external side effect is committed. An
    export implementation that has committed its side effect must finish returning
    ``WorkspaceExportResult`` instead of converting that success into cancellation.
    The service performs no automatic retry, so an adapter must not raise
    cancellation after a committed side effect with an available completion result.
    A malformed result returned after a side effect is a server-owned adapter
    contract failure; it fails closed and is not retried automatically in this slice.
    """

    @property
    def adapter_id(self) -> WorkspaceTransferAdapterId: ...

    @property
    def closed(self) -> bool: ...

    async def import_artifact(
        self,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult: ...

    async def export_artifact(
        self,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult: ...
