"""Closed-world canonical authority catalog for RFC-0033."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from phoenix_os.authority.contracts import AuthorityIntent, AuthorityPathObservation

AUTHORITY_INSPECT_ACTION: Final = "authority.inspect"
AUTHORITY_EXPLAIN_ACTION: Final = "authority.explain"
NETWORK_HTTP_REQUEST_ACTION: Final = "network.http.request"

_ID = r"[a-z0-9][a-z0-9._-]{0,127}"
_SCOPE_ID = r"[a-z0-9][a-z0-9._-]{0,191}"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_SHA256 = r"sha256:[0-9a-f]{64}"
_RESOLVED_TOOL_RESOURCE = r"[a-z0-9](?:[a-z0-9._:/-]{0,1023})"
_MEMORY_SCOPE = rf"agent-memory:{_ID}/scope:(?:run|agent|principal):{_SCOPE_ID}"
_WORKSPACE_SCOPE = rf"agent-workspace:{_ID}/scope:(?:run|agent|principal):{_SCOPE_ID}"
_HOST_ROOT = rf"host-automation:host:{_ID}"
_POSITIVE_INT32 = (
    r"(?:[1-9][0-9]{0,8}|1[0-9]{9}|20[0-9]{8}|21[0-3][0-9]{7}|"
    r"214[0-6][0-9]{6}|2147[0-3][0-9]{5}|21474[0-7][0-9]{4}|"
    r"214748[0-2][0-9]{3}|2147483[0-5][0-9]{2}|21474836[0-3][0-9]|214748364[0-7])"
)
_NETWORK_EGRESS_RESOURCE = rf"network-egress:{_ID}/generation:{_POSITIVE_INT32}/operation:{_ID}"


class UnknownAuthorityOperationError(RuntimeError):
    """An in-scope protected operation is absent from the reviewed catalog."""


class InvalidAuthorityObservationError(RuntimeError):
    """A trusted observation does not match the reviewed canonical catalog."""


@dataclass(frozen=True, slots=True)
class AuthorityCatalogEntry:
    """Reviewed canonical boundary and exact safe resource grammar for one action."""

    action: str
    canonical_boundary: str
    resource_pattern: str

    def __post_init__(self) -> None:
        action = self.action.strip().lower()
        boundary = self.canonical_boundary.strip().lower()
        pattern = self.resource_pattern.strip().lower()
        if not action or not boundary or not pattern:
            raise ValueError("authority catalog entry fields must not be blank")
        re.compile(pattern)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "canonical_boundary", boundary)
        object.__setattr__(self, "resource_pattern", pattern)

    def accepts_resource(self, resource: str) -> bool:
        if not isinstance(resource, str):
            raise TypeError("resource must be a string")
        return re.fullmatch(self.resource_pattern, resource.strip().lower()) is not None


_BUILTIN_ENTRIES = (
    AuthorityCatalogEntry("agent.run", "agent.run", rf"agent:{_ID}"),
    AuthorityCatalogEntry(
        "model.infer",
        "model.infer",
        rf"model-provider:{_ID}/model:{_ID}",
    ),
    AuthorityCatalogEntry(
        "tool.invoke",
        "tool.invoke",
        rf"tool:{_ID}/{_RESOLVED_TOOL_RESOURCE}",
    ),
    AuthorityCatalogEntry(
        "agent.delegate",
        "agent.delegate",
        rf"agent-delegation:{_ID}/parent:{_ID}/child:{_ID}",
    ),
    AuthorityCatalogEntry("agent.resume", "agent.resume", rf"durable-agent-run:{_UUID}"),
    AuthorityCatalogEntry(
        "agent.reconcile",
        "agent.reconcile",
        rf"durable-agent-run:{_UUID}/attempt:{_UUID}",
    ),
    AuthorityCatalogEntry("memory.search", "memory.search", _MEMORY_SCOPE),
    AuthorityCatalogEntry("memory.read", "memory.read", rf"{_MEMORY_SCOPE}/record:{_UUID}"),
    AuthorityCatalogEntry("memory.write", "memory.write", rf"{_MEMORY_SCOPE}/record:{_UUID}"),
    AuthorityCatalogEntry("memory.delete", "memory.delete", rf"{_MEMORY_SCOPE}/record:{_UUID}"),
    AuthorityCatalogEntry("memory.admin", "memory.admin", _MEMORY_SCOPE),
    AuthorityCatalogEntry("workspace.list", "workspace.list", _WORKSPACE_SCOPE),
    AuthorityCatalogEntry(
        "workspace.read",
        "workspace.read",
        rf"{_WORKSPACE_SCOPE}/artifact:{_UUID}",
    ),
    AuthorityCatalogEntry(
        "workspace.write",
        "workspace.write",
        rf"{_WORKSPACE_SCOPE}/artifact:{_UUID}",
    ),
    AuthorityCatalogEntry(
        "workspace.delete",
        "workspace.delete",
        rf"{_WORKSPACE_SCOPE}/artifact:{_UUID}",
    ),
    AuthorityCatalogEntry(
        "workspace.import",
        "workspace.import",
        rf"{_WORKSPACE_SCOPE}/artifact:{_UUID}",
    ),
    AuthorityCatalogEntry(
        "workspace.export",
        "workspace.export",
        rf"{_WORKSPACE_SCOPE}/artifact:{_UUID}",
    ),
    AuthorityCatalogEntry("workspace.admin", "workspace.admin", _WORKSPACE_SCOPE),
    AuthorityCatalogEntry(
        "host.process.list",
        "host.process.list",
        rf"{_HOST_ROOT}/processes",
    ),
    AuthorityCatalogEntry(
        "host.window.list",
        "host.window.list",
        rf"{_HOST_ROOT}/windows",
    ),
    AuthorityCatalogEntry(
        "host.app.launch",
        "host.app.launch",
        rf"{_HOST_ROOT}/application:{_ID}",
    ),
    AuthorityCatalogEntry(
        "host.window.focus",
        "host.window.focus",
        rf"{_HOST_ROOT}/window:{_UUID}",
    ),
    AuthorityCatalogEntry(
        "host.app.close",
        "host.app.close",
        rf"{_HOST_ROOT}/process:{_UUID}",
    ),
    AuthorityCatalogEntry(
        "host.clipboard.write",
        "host.clipboard.write",
        rf"{_HOST_ROOT}/clipboard:text",
    ),
    AuthorityCatalogEntry(
        "host.clipboard.read",
        "host.clipboard.read",
        rf"{_HOST_ROOT}/clipboard:text",
    ),
    AuthorityCatalogEntry(
        NETWORK_HTTP_REQUEST_ACTION,
        NETWORK_HTTP_REQUEST_ACTION,
        _NETWORK_EGRESS_RESOURCE,
    ),
    AuthorityCatalogEntry(
        AUTHORITY_INSPECT_ACTION,
        AUTHORITY_INSPECT_ACTION,
        rf"authority-subject:{_SHA256}",
    ),
    AuthorityCatalogEntry(
        AUTHORITY_EXPLAIN_ACTION,
        AUTHORITY_EXPLAIN_ACTION,
        rf"authority-intent:{_SHA256}/{_SHA256}",
    ),
)

_BUILTIN_MEDIATED_TRANSITIONS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("agent.delegate", "agent.run"),
        ("agent.resume", "agent.run"),
        ("agent.run", "model.infer"),
        ("agent.run", "tool.invoke"),
        ("agent.run", "memory.search"),
        ("agent.run", "workspace.read"),
        ("tool.invoke", "memory.write"),
        ("tool.invoke", "workspace.write"),
        ("tool.invoke", "host.process.list"),
        ("tool.invoke", "host.window.list"),
        ("tool.invoke", "host.app.launch"),
        ("tool.invoke", "host.window.focus"),
        ("tool.invoke", "host.app.close"),
        ("tool.invoke", "host.clipboard.write"),
        ("tool.invoke", "host.clipboard.read"),
    }
)


class AuthorityCatalog:
    """Immutable closed-world lookup for reviewed RFC-0033 operations and mediated paths."""

    def __init__(
        self,
        entries: tuple[AuthorityCatalogEntry, ...] = _BUILTIN_ENTRIES,
        *,
        mediated_transitions: frozenset[tuple[str, str]] = _BUILTIN_MEDIATED_TRANSITIONS,
    ) -> None:
        by_action: dict[str, AuthorityCatalogEntry] = {}
        for entry in entries:
            if not isinstance(entry, AuthorityCatalogEntry):
                raise TypeError("entries must contain AuthorityCatalogEntry values")
            if entry.action in by_action:
                raise ValueError(f"duplicate authority catalog action: {entry.action}")
            by_action[entry.action] = entry

        normalized_transitions: set[tuple[str, str]] = set()
        for transition in mediated_transitions:
            if (
                not isinstance(transition, tuple)
                or len(transition) != 2
                or any(not isinstance(item, str) for item in transition)
            ):
                raise TypeError("mediated_transitions must contain action pairs")
            upstream, downstream = (item.strip().lower() for item in transition)
            if upstream not in by_action or downstream not in by_action:
                raise ValueError("mediated transition references an unknown catalog action")
            if upstream == downstream:
                raise ValueError("mediated transition cannot repeat the same boundary")
            normalized_transitions.add((upstream, downstream))

        for entry in by_action.values():
            if entry.canonical_boundary not in by_action:
                raise ValueError(
                    "canonical boundary is absent from authority catalog: "
                    f"{entry.canonical_boundary}"
                )

        self._entries: Mapping[str, AuthorityCatalogEntry] = MappingProxyType(by_action)
        self._mediated_transitions = frozenset(normalized_transitions)

    @property
    def actions(self) -> tuple[str, ...]:
        return tuple(self._entries)

    @property
    def mediated_transitions(self) -> frozenset[tuple[str, str]]:
        return self._mediated_transitions

    def require(self, action: str) -> AuthorityCatalogEntry:
        if not isinstance(action, str):
            raise TypeError("action must be a string")
        normalized = action.strip().lower()
        try:
            return self._entries[normalized]
        except KeyError as exception:
            raise UnknownAuthorityOperationError(
                "unknown protected authority operation"
            ) from exception

    def validate_intent(self, intent: AuthorityIntent) -> AuthorityCatalogEntry:
        if not isinstance(intent, AuthorityIntent):
            raise TypeError("intent must be AuthorityIntent")
        entry = self.require(intent.action)
        if not entry.accepts_resource(intent.canonical_resource):
            raise InvalidAuthorityObservationError(
                "canonical resource grammar does not match protected action"
            )
        return entry

    def validate_observation(self, observation: AuthorityPathObservation) -> None:
        if not isinstance(observation, AuthorityPathObservation):
            raise TypeError("observation must be AuthorityPathObservation")
        entry = self.validate_intent(observation.intent)
        if observation.boundaries[-1] != entry.canonical_boundary:
            raise InvalidAuthorityObservationError(
                "authority path does not terminate at the canonical boundary"
            )

        for boundary in observation.boundaries:
            self.require(boundary)

        for upstream, downstream in zip(
            observation.boundaries,
            observation.boundaries[1:],
            strict=False,
        ):
            if (upstream, downstream) not in self._mediated_transitions:
                raise InvalidAuthorityObservationError(
                    "authority path contains an unreviewed mediated transition"
                )

        for action in observation.blocked_downstream:
            self.require(action)


BUILTIN_AUTHORITY_CATALOG: Final = AuthorityCatalog()
