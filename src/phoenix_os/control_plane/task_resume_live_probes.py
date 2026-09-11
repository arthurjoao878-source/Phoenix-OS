"""Production live probes for the bounded RFC-0039 task-resume path."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_LIST_TOOL_ID,
    CHECKOUT_READ_TOOL_ID,
    CheckoutToolAdapter,
)
from phoenix_os.agent.checkout_workspace import checkout_path_resource, checkout_prefix_resource
from phoenix_os.agent.contracts import AgentRunId, AgentRunRequest
from phoenix_os.agent.durable_cancellation import durable_cancellation_requested
from phoenix_os.agent.durable_contracts import (
    CheckpointNextOperation,
    DurableRunStatus,
    DurableRunStore,
)
from phoenix_os.agent.errors import AgentError
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskRuntime,
)
from phoenix_os.integrated_agent.composition import IntegratedAgentToolComposition
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSourceKind,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.durable_live_revalidation import (
    IntegratedDurableRecoveryLiveProbes,
)
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedExecutionProfile,
)

_CHECKOUT_LIST_FRESHNESS_KEYS = frozenset(
    {
        "tool-call",
        "registration-generation",
        "root-identity",
        "operation",
        "list-limit",
        "listing-digest",
    }
)

_CHECKOUT_READ_FRESHNESS_KEYS = frozenset(
    {
        "tool-call",
        "registration-generation",
        "root-identity",
        "operation",
        "file-identity",
        "content-digest",
        "byte-length",
    }
)


@dataclass(frozen=True, slots=True)
class _ServerOwnedTaskResumeLiveProbeOwner:
    store: DurableRunStore

    profile: IntegratedExecutionProfile

    task: IntegratedTaskRequest

    request: AgentRunRequest

    list_adapter: CheckoutToolAdapter

    read_adapter: CheckoutToolAdapter

    async def cancellation_probe(self, run_id: AgentRunId) -> bool:
        """Fail closed unless the exact resumable durable run is still uncancelled."""

        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")

        if run_id != self.request.run_id:
            return True

        durable_run_id = integrated_durable_run_id(run_id)

        try:
            current = await self.store.get_current(durable_run_id)

        except Exception:
            return True

        if (
            current is None
            or current.agent_run_id != run_id
            or current.durable_run_id != durable_run_id
            or current.status is not DurableRunStatus.PAUSED_OPERATOR
            or current.status.terminal
            or current.status.indeterminate
            or current.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
            or current.metadata.active_attempt is not None
        ):
            return True

        try:
            return durable_cancellation_requested(current)

        except (TypeError, ValueError):
            return True

    async def context_freshness_probe(self, provenance: IntegratedDataProvenance) -> bool:
        """Revalidate only provenance whose currentness has an explicit production owner."""

        if not isinstance(provenance, IntegratedDataProvenance):
            raise TypeError("provenance must be IntegratedDataProvenance")

        user_task_atoms = 0

        for atom in provenance.atoms:
            if atom.source_kind is IntegratedDataSourceKind.USER_TASK:
                user_task_atoms += 1

                if not self._user_task_atom_current(atom):
                    return False

                continue

            if atom.source_kind is IntegratedDataSourceKind.MODEL_OUTPUT:
                if not self._model_output_atom_current(atom):
                    return False

                continue

            if atom.source_kind is IntegratedDataSourceKind.TOOL_RESULT:
                if not self._tool_result_atom_current(atom):
                    return False

                continue

            if atom.source_kind is IntegratedDataSourceKind.WORKSPACE:
                if not await self._checkout_workspace_atom_current(atom):
                    return False

                continue

            return False

        return user_task_atoms == 1

    def _user_task_atom_current(self, atom: IntegratedDataProvenanceAtom) -> bool:

        return (
            atom.source_binding == f"integrated-task:{self.task.task_id}"
            and atom.freshness_bindings == (f"task-digest:{self.task.digest}",)
        )

    def _model_output_atom_current(self, atom: IntegratedDataProvenanceAtom) -> bool:

        prefix = f"agent-run:{self.request.run_id}/step:"

        if not atom.source_binding.startswith(prefix):
            return False

        step_id = atom.source_binding[len(prefix) :]

        return _is_canonical_uuid(step_id) and atom.freshness_bindings == (
            f"integrated-profile:{self.profile.profile_id}:{self.profile.generation}",
        )

    def _tool_result_atom_current(self, atom: IntegratedDataProvenanceAtom) -> bool:

        parts = atom.source_binding.split("/")

        if len(parts) != 4 or parts[0] != f"agent-run:{self.request.run_id}":
            return False

        step_id = _segment(parts[1], "step:")

        tool_id = _segment(parts[2], "tool:")

        call_id = _segment(parts[3], "call:")

        if step_id is None or tool_id is None or call_id is None:
            return False

        current_tool_ids = {str(item) for item in self.profile.tool_ids}

        return (
            _is_canonical_uuid(step_id)
            and _is_canonical_uuid(call_id)
            and tool_id in current_tool_ids
            and atom.freshness_bindings == (f"tool:{tool_id}",)
        )

    async def _checkout_workspace_atom_current(
        self,
        atom: IntegratedDataProvenanceAtom,
    ) -> bool:

        bindings = _freshness_map(atom)

        if bindings is None:
            return False

        operation = bindings.get("operation")

        if operation == "list":
            return await self._checkout_list_atom_current(atom, bindings)

        if operation == "read":
            return await self._checkout_read_atom_current(atom, bindings)

        return False

    async def _checkout_list_atom_current(
        self,
        atom: IntegratedDataProvenanceAtom,
        bindings: dict[str, str],
    ) -> bool:

        if frozenset(bindings) != _CHECKOUT_LIST_FRESHNESS_KEYS:
            return False

        adapter = self.list_adapter

        registration = adapter.registration

        prefix_marker = f"development-checkout:{registration.workspace_id}/prefix:"

        if not atom.source_binding.startswith(prefix_marker):
            return False

        prefix = atom.source_binding[len(prefix_marker) :]

        limit = _canonical_int(bindings["list-limit"], minimum=1)

        if (
            limit is None
            or not _is_canonical_uuid(bindings["tool-call"])
            or bindings["registration-generation"] != str(registration.generation)
            or bindings["root-identity"] != registration.root_identity
            or not _is_digest(bindings["listing-digest"])
        ):
            return False

        try:
            if checkout_prefix_resource(registration, prefix) != atom.source_binding:
                return False

        except (AgentError, TypeError, ValueError):
            return False

        return await adapter.is_list_result_current(
            prefix=prefix,
            max_entries=limit,
            registration_generation=registration.generation,
            root_identity=registration.root_identity,
            listing_digest=bindings["listing-digest"],
        )

    async def _checkout_read_atom_current(
        self,
        atom: IntegratedDataProvenanceAtom,
        bindings: dict[str, str],
    ) -> bool:

        if frozenset(bindings) != _CHECKOUT_READ_FRESHNESS_KEYS:
            return False

        adapter = self.read_adapter

        registration = adapter.registration

        path_marker = f"development-checkout:{registration.workspace_id}/path:"

        if not atom.source_binding.startswith(path_marker):
            return False

        logical_path = atom.source_binding[len(path_marker) :]

        byte_length = _canonical_int(bindings["byte-length"], minimum=0)

        if (
            byte_length is None
            or not _is_canonical_uuid(bindings["tool-call"])
            or bindings["registration-generation"] != str(registration.generation)
            or bindings["root-identity"] != registration.root_identity
            or not _is_digest(bindings["file-identity"])
            or not _is_digest(bindings["content-digest"])
        ):
            return False

        try:
            if checkout_path_resource(registration, logical_path) != atom.source_binding:
                return False

        except (AgentError, TypeError, ValueError):
            return False

        return await adapter.is_read_result_current(
            logical_path=logical_path,
            run_id=self.request.run_id,
            registration_generation=registration.generation,
            root_identity=registration.root_identity,
            file_identity=bindings["file-identity"],
            content_digest=bindings["content-digest"],
            byte_length=byte_length,
        )


def compose_server_owned_task_resume_live_probes(
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    *,
    task: IntegratedTaskRequest,
    request: AgentRunRequest,
) -> IntegratedDurableRecoveryLiveProbes:
    """Bind recovery probes to the exact server-owned durable/checkout surface."""

    if not isinstance(owner, ServerOwnedDurableIntegratedTaskRuntime):
        raise TypeError("owner must be ServerOwnedDurableIntegratedTaskRuntime")

    if not isinstance(task, IntegratedTaskRequest):
        raise TypeError("task must be IntegratedTaskRequest")

    if not isinstance(request, AgentRunRequest):
        raise TypeError("request must be AgentRunRequest")

    profile = owner.profile

    composition = owner.composition

    if not isinstance(composition, IntegratedAgentToolComposition):
        raise IntegratedAgentConfigurationError()

    if composition.profile is not profile or request.agent_id != profile.agent_id:
        raise IntegratedAgentConfigurationError()

    expected_tools = frozenset(
        {
            INTEGRATED_PLAN_UPDATE_TOOL_ID,
            CHECKOUT_LIST_TOOL_ID,
            CHECKOUT_READ_TOOL_ID,
        }
    )

    if (
        frozenset(profile.tool_ids) != expected_tools
        or frozenset(composition.tool_ids) != expected_tools
    ):
        raise IntegratedAgentConfigurationError()

    registrations = {
        registration.tool_id: registration for registration in composition.registrations
    }

    list_adapter = registrations[CHECKOUT_LIST_TOOL_ID].adapter

    read_adapter = registrations[CHECKOUT_READ_TOOL_ID].adapter

    if not isinstance(list_adapter, CheckoutToolAdapter) or not isinstance(
        read_adapter,
        CheckoutToolAdapter,
    ):
        raise IntegratedAgentConfigurationError()

    if (
        list_adapter.tool_id != CHECKOUT_LIST_TOOL_ID
        or read_adapter.tool_id != CHECKOUT_READ_TOOL_ID
        or list_adapter.registration is not read_adapter.registration
    ):
        raise IntegratedAgentConfigurationError()

    probe_owner = _ServerOwnedTaskResumeLiveProbeOwner(
        store=owner.durable_stack.store,
        profile=profile,
        task=task,
        request=request,
        list_adapter=list_adapter,
        read_adapter=read_adapter,
    )

    return IntegratedDurableRecoveryLiveProbes(
        cancellation_probe=probe_owner.cancellation_probe,
        context_freshness_probe=probe_owner.context_freshness_probe,
    )


def _freshness_map(atom: IntegratedDataProvenanceAtom) -> dict[str, str] | None:

    values: dict[str, str] = {}

    for binding in atom.freshness_bindings:
        key, separator, value = binding.partition(":")

        if not separator or not key or not value or key in values:
            return None

        values[key] = value

    return values


def _segment(value: str, prefix: str) -> str | None:

    if not value.startswith(prefix):
        return None

    suffix = value[len(prefix) :]

    return suffix or None


def _canonical_int(value: str, *, minimum: int) -> int | None:

    if not value or (len(value) > 1 and value.startswith("0")):
        return None

    try:
        parsed = int(value, 10)

    except ValueError:
        return None

    if parsed < minimum or str(parsed) != value:
        return None

    return parsed


def _is_canonical_uuid(value: str) -> bool:

    try:
        return str(UUID(value)) == value

    except (ValueError, AttributeError):
        return False


def _is_digest(value: str) -> bool:

    if not value.startswith("sha256:"):
        return False

    digest = value[7:]

    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)
